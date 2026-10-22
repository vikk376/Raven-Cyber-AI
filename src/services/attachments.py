"""Files attached to the chat assistant for analysis: CSV, Excel, JSON, text, PDF, Word and images.

Files are validated (extension, size, magic bytes), turned into bounded text (or a re-encoded image), scanned for
indicators of compromise and never executed or stored. The text is handed to the model as untrusted data.
"""
import base64
import hashlib
import io
import json

import pandas as pd

from src.services import indicators, rag

MAX_FILES = 5
MAX_BYTES = 10 * 1024 * 1024
TEXT_BUDGET = 24000
IMAGE_MAX_SIDE = 1568
IMAGE_EXT = (".png", ".jpg", ".jpeg", ".webp")
TABLE_EXT = (".csv", ".tsv", ".xlsx")
TEXT_EXT = (".txt", ".md", ".log", ".json", ".css")
ALLOWED_EXT = (*TABLE_EXT, *TEXT_EXT, ".pdf", ".docx", *IMAGE_EXT)
FILE_TYPES = [e.lstrip(".") for e in ALLOWED_EXT]

_MAGIC = {".pdf": (b"%PDF",), ".docx": (b"PK",), ".xlsx": (b"PK",), ".png": (b"\x89PNG",),
          ".jpg": (b"\xff\xd8",), ".jpeg": (b"\xff\xd8",), ".webp": (b"RIFF",)}


class AttachmentError(Exception):
    pass


def _ext(name: str) -> str:
    return "." + name.lower().rsplit(".", 1)[-1] if "." in name else ""


def _clip(text: str, limit: int = TEXT_BUDGET) -> str:
    return text if len(text) <= limit else text[:limit] + f"\n[truncated, {len(text) - limit} more characters]"


def _frame_text(label: str, df: pd.DataFrame) -> str:
    nulls = {c: int(n) for c, n in df.isna().sum().items() if n}
    try:
        head = df.head(40).to_markdown(index=False)
    except ImportError:
        head = df.head(40).to_string(index=False)
    return (f"{label}: {len(df):,} rows, {len(df.columns)} columns\nColumns: "
            + ", ".join(f"{c} ({t})" for c, t in zip(df.columns, df.dtypes.astype(str)))
            + (f"\nEmpty cells: {nulls}" if nulls else "") + f"\nFirst rows:\n{head}")


def _table(ext: str, data: bytes) -> str:
    try:
        if ext == ".xlsx":
            sheets = pd.read_excel(io.BytesIO(data), sheet_name=None, nrows=50000)
            return "\n\n".join(_frame_text(f"Sheet '{n}'", df) for n, df in list(sheets.items())[:6])
        sep = "\t" if ext == ".tsv" else None
        for enc in ("utf-8-sig", "latin-1"):
            try:
                df = pd.read_csv(io.BytesIO(data), sep=sep, engine="python", encoding=enc, nrows=50000)
                break
            except UnicodeError:
                continue
        else:
            raise AttachmentError("Cannot decode the table.")
        text = _frame_text("Table", df)
        if len(data) <= 8000:  # small files are sent whole so nothing is lost
            text += "\n\nRaw content:\n" + data.decode("utf-8", "replace")
        return text
    except AttachmentError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise AttachmentError(f"Could not read this table: {str(exc)[:160]}") from exc


def _image(ext: str, data: bytes) -> tuple[str, str]:
    from PIL import Image
    try:
        with Image.open(io.BytesIO(data)) as im:
            im.load()
            if im.width * im.height > 60_000_000:
                raise AttachmentError("The image is too large.")
            im = im.convert("RGB")  # drops EXIF and other metadata
            im.thumbnail((IMAGE_MAX_SIDE, IMAGE_MAX_SIDE))
            buf = io.BytesIO()
            im.save(buf, "PNG", optimize=True)
    except AttachmentError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise AttachmentError(f"Could not read this image: {str(exc)[:160]}") from exc
    return "image/png", base64.b64encode(buf.getvalue()).decode()


def prepare(name: str, data: bytes) -> dict:
    """Validate and convert one file. Returns {name, kind, size, sha256, text, image, iocs}. Raises AttachmentError."""
    ext = _ext(name)
    if ext not in ALLOWED_EXT:
        raise AttachmentError(f"{name}: type not supported. Use {', '.join(FILE_TYPES)}.")
    if not data:
        raise AttachmentError(f"{name}: the file is empty.")
    if len(data) > MAX_BYTES:
        raise AttachmentError(f"{name}: larger than {MAX_BYTES // 1024 // 1024} MB.")
    if ext in _MAGIC and not data.startswith(_MAGIC[ext]):
        raise AttachmentError(f"{name}: the content does not match a {ext} file.")
    out = {"name": name[:120], "kind": "text", "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
           "text": "", "image": None, "iocs": {}}
    if ext in IMAGE_EXT:
        out["kind"] = "image"
        out["image"] = _image(ext, data)
        return out
    if ext in TABLE_EXT:
        text = _table(ext, data)
    elif ext in (".pdf", ".docx"):
        try:
            pages = rag.extract(ext, data)
        except rag.RagError as exc:
            raise AttachmentError(f"{name}: {exc}") from exc
        if not pages:
            raise AttachmentError(f"{name}: no text found. Scanned PDFs need OCR, or attach a screenshot as an image.")
        text = "\n\n".join((f"[page {n}]\n" if n else "") + t for n, t in pages)
    elif ext == ".json":
        raw = rag._decode(data)
        try:
            raw = json.dumps(json.loads(raw), indent=1)
        except ValueError:
            pass
        text = raw
    else:
        text = rag._decode(data)
    out["iocs"] = indicators.extract_iocs(text)
    out["text"] = _clip(text)
    return out


def prepare_many(files: list[tuple[str, bytes]]) -> tuple[list[dict], list[str]]:
    """Returns (ready, errors). At most MAX_FILES are accepted per message."""
    ready, errors = [], []
    for name, data in files[:MAX_FILES]:
        try:
            ready.append(prepare(name, data))
        except AttachmentError as exc:
            errors.append(str(exc))
    if len(files) > MAX_FILES:
        errors.append(f"Only the first {MAX_FILES} files were used.")
    return ready, errors


def ioc_summary(att: dict) -> str:
    parts = [f"{len(v)} {k}" for k, v in att.get("iocs", {}).items() if v]
    return ", ".join(parts)


def context_block(atts: list[dict], budget: int = 60000) -> str:
    """Text handed to the model. Marked as untrusted so instructions inside files are not followed."""
    blocks, used = [], 0
    for a in atts:
        if a["kind"] != "text":
            blocks.append(f'<file name="{a["name"]}" type="image">(image sent with this message)</file>')
            continue
        iocs = "; ".join(f"{k}: {', '.join(v[:20])}" for k, v in a["iocs"].items() if v)
        body = a["text"][: max(0, budget - used)]
        used += len(body)
        blocks.append(f'<file name="{a["name"]}" sha256="{a["sha256"][:16]}">\n'
                      + (f"Indicators found: {iocs}\n" if iocs else "") + f"{body}\n</file>")
    return "<attached_files untrusted=\"true\">\n" + "\n".join(blocks) + "\n</attached_files>" if blocks else ""


def image_parts(atts: list[dict]) -> list[dict]:
    return [{"type": "image_url", "image_url": {"url": f"data:{a['image'][0]};base64,{a['image'][1]}"}}
            for a in atts if a["kind"] == "image" and a["image"]]
