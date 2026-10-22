"""Raven Data Lake: store structured files (CSV, TSV, Excel) and JSON, query them read-only, hand them to the AI.

Layout under data/lake/:
  raw/<id><ext>   the original upload, kept byte for byte
  lake.db         one SQLite table per tabular dataset (separate from the platform database, so SQL run here
                  can never reach users, sessions, secrets or the audit log)
Metadata lives in the platform database table lake_datasets.
"""
import hashlib
import io
import json
import os
import re
import sqlite3
import time
from pathlib import Path

import pandas as pd

from src.core import config
from src.core.database import connect, utcnow
from src.services import rag

TABLE_EXT = (".csv", ".tsv", ".xlsx", ".json", ".jsonl", ".ndjson")
ALLOWED_EXT = (*TABLE_EXT, *rag.TEXT_EXT)
MAX_BYTES = int(os.getenv("LAKE_MAX_MB", "100")) * 1024 * 1024
MAX_ROWS = int(os.getenv("LAKE_MAX_ROWS", "1000000"))
QUERY_SECONDS = 15
RESERVED = {"sqlite_master", "sqlite_sequence", "select", "from", "where", "table", "index", "order", "group"}


class LakeError(Exception):
    pass


def root() -> Path:
    p = config.DATA_DIR / "lake"
    (p / "raw").mkdir(parents=True, exist_ok=True)
    return p


def _lake_db() -> Path:
    return root() / "lake.db"


# ------------------------------------------------------------------ naming helpers
def _slug(text: str, fallback: str = "dataset") -> str:
    s = re.sub(r"[^A-Za-z0-9]+", "_", text).strip("_").lower()
    if not s:
        s = fallback
    if s[0].isdigit():
        s = "d_" + s
    return s[:48]


def _clean_columns(cols) -> list[str]:
    out, seen = [], set()
    for i, c in enumerate(cols):
        name = re.sub(r"[^A-Za-z0-9_]+", "_", str(c)).strip("_") or f"col_{i + 1}"
        if name[0].isdigit():
            name = "c_" + name
        base, n = name, 2
        while name.lower() in seen:
            name, n = f"{base}_{n}", n + 1
        seen.add(name.lower())
        out.append(name)
    return out


def _unique_table(con, name: str) -> str:
    base = _slug(name)
    if base in RESERVED:
        base += "_data"
    table, n = base, 2
    while con.execute("SELECT 1 FROM lake_datasets WHERE table_name = ?", (table,)).fetchone():
        table, n = f"{base}_{n}", n + 1
    return table


def _unique_name(con, name: str) -> str:
    name = (name or "dataset").strip()[:80] or "dataset"
    cand, n = name, 2
    while con.execute("SELECT 1 FROM lake_datasets WHERE name = ?", (cand,)).fetchone():
        cand, n = f"{name} ({n})", n + 1
    return cand


# ------------------------------------------------------------------ parsing
def _flatten_cells(df: pd.DataFrame) -> pd.DataFrame:
    for col in df.columns:
        if df[col].dtype == object:
            df[col] = df[col].map(lambda v: json.dumps(v, default=str) if isinstance(v, (dict, list)) else v)
    return df


def _records_to_frame(records: list) -> pd.DataFrame | None:
    if records and all(isinstance(r, dict) for r in records):
        return pd.json_normalize(records, sep=".")
    return None


def _json_frame(value) -> pd.DataFrame | None:
    """A JSON value that is naturally a table: an array of objects, or an object holding one such array."""
    if isinstance(value, list):
        return _records_to_frame(value)
    if isinstance(value, dict):
        lists = [(k, v) for k, v in value.items() if isinstance(v, list) and v and all(isinstance(r, dict) for r in v)]
        if len(lists) == 1:
            return _records_to_frame(lists[0][1])
    return None


def _decode(data: bytes) -> str:
    for enc in ("utf-8-sig", "utf-16", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeError:
            continue
    raise LakeError("Cannot decode the file as text.")


def _parse(ext: str, data: bytes) -> list[tuple[str, pd.DataFrame | None, object | None]]:
    """Return [(label, frame_or_None, document_or_None)]. A frame means a table, otherwise a JSON document."""
    try:
        if ext in (".csv", ".tsv"):
            df = pd.read_csv(io.StringIO(_decode(data)), sep="\t" if ext == ".tsv" else None, engine="python")
            return [("", df, None)]
        if ext == ".xlsx":
            sheets = pd.read_excel(io.BytesIO(data), sheet_name=None, engine="openpyxl")
            return [(name, df, None) for name, df in sheets.items() if len(df.columns)]
        if ext in (".jsonl", ".ndjson"):
            rows = [json.loads(line) for line in _decode(data).splitlines() if line.strip()]
            df = _records_to_frame(rows)
            if df is None:
                raise LakeError("Every line must be a JSON object.")
            return [("", df, None)]
        value = json.loads(_decode(data))
        df = _json_frame(value)
        return [("", df, None if df is not None else value)]
    except LakeError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise LakeError(f"Could not read this {ext} file: {str(exc)[:200]}") from exc


def _outline(value, depth: int = 0) -> str:
    if isinstance(value, dict):
        return "{" + ", ".join(f"{k}: {_outline(v, depth + 1) if depth < 2 else '...'}" for k, v in list(value.items())[:25]) + "}"
    if isinstance(value, list):
        return f"[{len(value)} item(s)" + (f" of {_outline(value[0], depth + 1)}" if value and depth < 2 else "") + "]"
    return type(value).__name__


# ------------------------------------------------------------------ ingest
def ingest(owner: str, filename: str, data: bytes, name: str = "", description: str = "", tags: str = "") -> list[dict]:
    """Store an upload. Returns one metadata dict per dataset created (Excel files create one per sheet)."""
    ext = Path(filename or "").suffix.lower()
    if ext not in ALLOWED_EXT:
        raise LakeError(f"Unsupported file type. Use: {', '.join(ALLOWED_EXT)}.")
    if not data:
        raise LakeError("The file is empty.")
    if len(data) > MAX_BYTES:
        raise LakeError(f"The file is larger than {MAX_BYTES // 1024 // 1024} MB.")
    if ext in rag.TEXT_EXT:
        return [_store_text(owner, filename, ext, data, name, description, tags)]
    parts = _parse(ext, data)
    if not parts:
        raise LakeError("No data found in the file.")
    digest = hashlib.sha256(data).hexdigest()
    made = []
    for label, df, doc in parts:
        base = name.strip() or Path(filename).stem
        full = f"{base} - {label}" if label and len(parts) > 1 else base
        made.append(_store(owner, filename, ext, data, digest, full, description, tags, df, doc))
    return made


def _store_text(owner, filename, ext, data, name, description, tags) -> dict:
    """PDF, Word and text files: extract, split into passages and index them for retrieval."""
    try:
        pages = rag.extract(ext, data)
        chunks = rag.chunk(pages)
    except rag.RagError as exc:
        raise LakeError(str(exc)) from exc
    words = sum(len(t.split()) for _, t in pages)
    info = {"pages": len([p for p, _ in pages if p]) or None, "words": words, "format": ext.lstrip(".")}
    with connect() as con:
        ds_name = _unique_name(con, name.strip() or Path(filename).stem)
        table = _unique_table(con, ds_name)
        cur = con.execute(
            """INSERT INTO lake_datasets (name, table_name, kind, description, tags, source_filename, rows, columns_json,
               size_bytes, sha256, uploaded_by, created_at, info_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (ds_name, table, "text", description.strip()[:500], _tags(tags), Path(filename).name[:200], len(chunks), "[]",
             len(data), hashlib.sha256(data).hexdigest(), owner.lower(), utcnow(), json.dumps(info)))
        did = cur.lastrowid
    try:
        (root() / "raw" / f"{did}{ext}").write_bytes(data)
        res = rag.index(_lake_db(), did, chunks)
    except Exception as exc:  # noqa: BLE001
        delete(did)
        raise LakeError(f"Could not index the document: {str(exc)[:200]}") from exc
    info["semantic"] = res["semantic"]
    info["note"] = res["note"]
    with connect() as con:
        con.execute("UPDATE lake_datasets SET info_json = ? WHERE id = ?", (json.dumps(info), did))
    return get(did)


def _store(owner, filename, ext, data, digest, name, description, tags, df, doc) -> dict:
    cols_meta, rows = [], 0
    if df is not None:
        if len(df) > MAX_ROWS:
            raise LakeError(f"More than {MAX_ROWS:,} rows. Split the file first.")
        df = df.copy()
        df.columns = _clean_columns(df.columns)
        df = _flatten_cells(df)
        rows = len(df)
        cols_meta = [{"name": c, "type": str(df[c].dtype)} for c in df.columns]
    with connect() as con:
        ds_name = _unique_name(con, name)
        table = _unique_table(con, ds_name)
        cur = con.execute(
            """INSERT INTO lake_datasets (name, table_name, kind, description, tags, source_filename, rows, columns_json,
               size_bytes, sha256, uploaded_by, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (ds_name, table, "table" if df is not None else "document", description.strip()[:500], _tags(tags),
             Path(filename).name[:200], rows, json.dumps(cols_meta), len(data), digest, owner.lower(), utcnow()))
        did = cur.lastrowid
    try:
        (root() / "raw" / f"{did}{ext}").write_bytes(data)
        if df is not None:
            with sqlite3.connect(_lake_db()) as lk:
                df.to_sql(table, lk, index=False, if_exists="fail")
    except Exception as exc:  # noqa: BLE001
        delete(did)
        raise LakeError(f"Could not store the data: {str(exc)[:200]}") from exc
    return get(did)


def _tags(tags: str) -> str:
    return ",".join(t.strip()[:30] for t in re.split(r"[,;]", tags or "") if t.strip())[:200]


# ------------------------------------------------------------------ read
def _row(r) -> dict:
    d = dict(r)
    d["columns"] = json.loads(d.pop("columns_json") or "[]")
    d["tag_list"] = [t for t in d["tags"].split(",") if t]
    d["info"] = json.loads(d.pop("info_json", "{}") or "{}")
    return d


def list_datasets() -> list[dict]:
    with connect() as con:
        return [_row(r) for r in con.execute("SELECT * FROM lake_datasets ORDER BY created_at DESC, id DESC")]


def get(dataset_id: int) -> dict | None:
    with connect() as con:
        r = con.execute("SELECT * FROM lake_datasets WHERE id = ?", (dataset_id,)).fetchone()
    return _row(r) if r else None


def raw_path(ds: dict) -> Path | None:
    for p in (root() / "raw").glob(f"{ds['id']}.*"):
        return p
    return None


def read_document(ds: dict, max_chars: int = 12000) -> str:
    p = raw_path(ds)
    if not p:
        return ""
    return _decode(p.read_bytes())[:max_chars]


def stats() -> dict:
    items = list_datasets()
    return {"datasets": len(items), "tables": sum(d["kind"] == "table" for d in items),
            "documents": sum(d["kind"] == "document" for d in items), "texts": sum(d["kind"] == "text" for d in items),
            "rows": sum(d["rows"] for d in items if d["kind"] == "table"),
            "passages": sum(d["rows"] for d in items if d["kind"] == "text"), "bytes": sum(d["size_bytes"] for d in items)}


def delete(dataset_id: int) -> None:
    ds = get(dataset_id)
    if not ds:
        return
    if ds["kind"] == "table" and _lake_db().exists():
        with sqlite3.connect(_lake_db()) as lk:
            lk.execute(f'DROP TABLE IF EXISTS "{ds["table_name"]}"')
    if ds["kind"] == "text":
        rag.delete(_lake_db(), dataset_id)
    p = raw_path(ds)
    if p:
        p.unlink(missing_ok=True)
    with connect() as con:
        con.execute("DELETE FROM lake_datasets WHERE id = ?", (dataset_id,))


# ------------------------------------------------------------------ query (read-only)
_BAD_START = re.compile(r"(?is)^\s*(select|with)\b")


def query(sql: str, limit: int = 500, allowed_tables: set[str] | None = None) -> pd.DataFrame:
    """Run one read-only SELECT against the lake. Raises LakeError for anything else."""
    sql = (sql or "").strip().rstrip(";")
    if not _BAD_START.match(sql) or ";" in sql:
        raise LakeError("Only a single SELECT statement is allowed.")
    if not _lake_db().exists():
        raise LakeError("The lake is empty. Upload a dataset first.")
    allowed = {t.lower() for t in allowed_tables} if allowed_tables is not None else None
    con = sqlite3.connect(f"file:{_lake_db()}?mode=ro", uri=True)
    deadline = time.monotonic() + QUERY_SECONDS

    def authorizer(action, arg1, arg2, db, trigger):
        if action in (sqlite3.SQLITE_SELECT, sqlite3.SQLITE_FUNCTION, sqlite3.SQLITE_RECURSIVE):
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_READ:
            if arg1 and arg1.lower().startswith(("sqlite_", "rag_")):
                return sqlite3.SQLITE_DENY
            if allowed is not None and (arg1 or "").lower() not in allowed:
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK
        return sqlite3.SQLITE_DENY

    con.set_authorizer(authorizer)
    con.set_progress_handler(lambda: 1 if time.monotonic() > deadline else 0, 20000)
    try:
        return pd.read_sql_query(f"SELECT * FROM ({sql}) LIMIT {int(limit)}", con)
    except Exception as exc:  # noqa: BLE001
        msg = str(exc)
        if "not authorized" in msg:
            raise LakeError("That query touches a table you cannot use here.") from exc
        if "interrupted" in msg:
            raise LakeError(f"The query took longer than {QUERY_SECONDS} seconds.") from exc
        raise LakeError(msg[:300]) from exc
    finally:
        con.close()


def preview(ds: dict, n: int = 200) -> pd.DataFrame:
    return query(f'SELECT * FROM "{ds["table_name"]}"', n)


def schema_text(datasets: list[dict] | None = None) -> str:
    out = []
    for d in datasets if datasets is not None else list_datasets():
        if d["kind"] == "table":
            cols = ", ".join(f"{c['name']} ({c['type']})" for c in d["columns"])
            out.append(f"- table {d['table_name']} ({d['name']}, {d['rows']:,} rows): {cols}")
        elif d["kind"] == "text":
            pg = f"{d['info'].get('pages')} pages, " if d["info"].get("pages") else ""
            out.append(f"- text document {d['name']} ({d['info'].get('format', 'text').upper()}, {pg}{d['rows']} passages, "
                       f"search with search_documents): {d['description'] or 'no description'}")
        else:
            out.append(f"- document {d['name']} (JSON, read with read_document): {d['description'] or 'no description'}")
    return "\n".join(out) or "The lake is empty."


def document_outline(ds: dict) -> str:
    try:
        return _outline(json.loads(read_document(ds, MAX_BYTES)))
    except Exception:  # noqa: BLE001
        return "unreadable"


def search_passages(query: str, datasets: list[dict] | None = None, k: int = 6) -> list[dict]:
    """Retrieve the best passages from text documents (PDF, Word, text). Each hit carries its document name."""
    items = [d for d in (datasets if datasets is not None else list_datasets()) if d["kind"] == "text"]
    names = {d["id"]: d["name"] for d in items}
    hits = rag.search(_lake_db(), query, list(names), k)
    for h in hits:
        h["document"] = names.get(h["dataset_id"], "?")
    return hits


def search_mode() -> str:
    return "Hybrid: keyword (BM25) and semantic embeddings" if rag.embeddings_enabled() else \
        "Keyword (BM25) search. Set AZURE_OPENAI_EMBEDDING_DEPLOYMENT in .env to add semantic search."
