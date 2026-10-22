"""Raven Cyber AI design system: sky blue and dark blue from the logo, light and dark aware.

The CSS never hard-codes page backgrounds or text colours. Cards are tinted from the current text colour with
color-mix, so the same rules look right in Streamlit's light and dark themes (see .streamlit/config.toml).
"""
import html
from pathlib import Path

import streamlit as st

from src.core import constants

ASSETS = Path(__file__).resolve().parents[2] / "assets"
LOGO = ASSETS / "logo.png"
FAVICON = ASSETS / "favicon.png"

SKY, SKY_LIGHT, BLUE, NAVY = "#38bdf8", "#7dd3fc", "#1d6fe0", "#0b2a55"
PALETTE = ["#1d6fe0", "#38bdf8", "#0b2a55", "#22c55e", "#f59e0b", "#a855f7", "#ef4444"]
SEVERITY = {"Informational": "#94a3b8", "Low": "#22c55e", "Medium": "#f59e0b", "High": "#ef6c00", "Critical": "#ef4444"}

CSS = """
<style>
:root{--sky:#38bdf8;--sky2:#7dd3fc;--blue:#1d6fe0;--navy:#0b2a55;--ok:#22c55e;--warn:#f59e0b;--bad:#ef4444;
--line:rgba(29,111,224,.18);--soft:rgba(255,255,255,.80);
--muted:rgba(11,42,85,.62)}
@keyframes rvIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
@keyframes rvPulse{0%{box-shadow:0 0 0 0 rgba(56,189,248,.55)}70%{box-shadow:0 0 0 8px rgba(56,189,248,0)}100%{box-shadow:0 0 0 0 rgba(56,189,248,0)}}
@keyframes rvFlow{to{background-position:200% 0}}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
[data-testid="stAppViewContainer"]{background-image:radial-gradient(1000px 480px at 92% -8%,rgba(186,230,253,.55),transparent 62%),
radial-gradient(800px 420px at -5% 105%,rgba(125,211,252,.35),transparent 60%)}
[data-testid="stHeader"]{background:transparent}
[data-testid="stSidebar"]{border-right:1px solid var(--line);
background-image:linear-gradient(180deg,#ffffff,#e6f4ff 60%,#d3ecff)}
[data-testid="stSidebarNavLink"]{border-radius:10px;transition:background .15s ease,transform .15s ease}
[data-testid="stSidebarNavLink"]:hover{transform:translateX(2px)}
[data-testid="stSidebarNavLink"][aria-current="page"]{background:linear-gradient(90deg,rgba(56,189,248,.28),rgba(29,111,224,.12));
box-shadow:inset 3px 0 0 var(--sky)}
[data-testid="stSidebarNavSeparator"],[data-testid="stNavSectionHeader"]{opacity:.75;letter-spacing:.08em;text-transform:uppercase;font-size:.7rem}
.block-container{padding-top:1.6rem;max-width:1320px;animation:rvIn .35s ease both}
h1,h2,h3{letter-spacing:-.01em}

/* page header */
.rv-crumb{font-size:.72rem;letter-spacing:.14em;text-transform:uppercase;color:var(--sky);font-weight:700;margin-bottom:.15rem}
.rv-title{font-size:2rem;font-weight:800;margin:0;line-height:1.15;display:flex;align-items:center;gap:.6rem}
.rv-title .ico{display:inline-flex;align-items:center;justify-content:center;width:42px;height:42px;border-radius:12px;font-size:1.3rem;
background:linear-gradient(135deg,var(--blue),var(--sky));box-shadow:0 6px 18px rgba(29,111,224,.35)}
.rv-sub{color:var(--muted);margin:.35rem 0 1.1rem}
.rv-sec{font-size:1.05rem;font-weight:700;margin:1.2rem 0 .5rem;display:flex;align-items:center;gap:.5rem}
.rv-sec:after{content:"";flex:1;height:1px;background:linear-gradient(90deg,var(--line),transparent)}

/* hero (keyed container) */
[class*="st-key-rvhero"]{position:relative;overflow:hidden;border-radius:18px;padding:26px 28px!important;color:#0b2a55;
background:linear-gradient(120deg,#ffffff 0%,#e3f3ff 48%,#a9dcfb 125%);border:1px solid rgba(125,211,252,.7);
box-shadow:0 14px 40px rgba(56,189,248,.22)}
[class*="st-key-rvhero"]:before{content:"";position:absolute;right:-30px;top:-30px;width:330px;height:330px;opacity:.16;pointer-events:none;
background:url(/app/static/logo.png) center/contain no-repeat}
[class*="st-key-rvhero"] *{color:#0b2a55}
[class*="st-key-rvhero"] [data-testid="stBaseButton-primary"],[class*="st-key-rvhero"] [data-testid="stBaseButton-primary"] *{color:#fff}
[class*="st-key-rvhero"] input{color:#0b2447!important;background:#fff!important;border-radius:12px;border:1px solid rgba(56,189,248,.5)}
[class*="st-key-rvhero"] input::placeholder{color:#5b7396!important}
.rv-hero-k{font-size:.74rem;letter-spacing:.18em;text-transform:uppercase;font-weight:700;color:#1d6fe0!important}
.rv-hero-t{font-size:2.05rem;font-weight:800;line-height:1.15;margin:.2rem 0 .3rem}
.rv-hero-s{opacity:.9;margin-bottom:.8rem}

/* cards */
[class*="st-key-rvcard"],[class*="st-key-rvtile"],[class*="st-key-rvadd"]{border:1px solid var(--line)!important;border-radius:16px!important;
background:linear-gradient(160deg,rgba(125,211,252,.16),var(--soft));transition:transform .18s ease,box-shadow .18s ease,border-color .18s ease;animation:rvIn .4s ease both}
[class*="st-key-rvtile"]:hover,[class*="st-key-rvadd"]:hover{transform:translateY(-3px);border-color:var(--sky)!important;box-shadow:0 12px 30px rgba(56,189,248,.22)}
[class*="st-key-rvcard"]{padding:6px 8px}
[class*="st-key-rvtile_sel"]{border-color:var(--sky)!important;box-shadow:0 0 0 2px rgba(56,189,248,.55),0 12px 30px rgba(56,189,248,.25)}
[class*="st-key-rvadd"]{border-style:dashed!important;text-align:center;background:transparent}
.rv-add{text-align:center;padding:14px 0 4px}.rv-add .plus{display:inline-flex;width:46px;height:46px;border-radius:14px;align-items:center;justify-content:center;
font-size:1.7rem;font-weight:700;color:#fff;background:linear-gradient(135deg,var(--blue),var(--sky))}
.rv-add b{display:block;margin-top:.4rem}.rv-add span{display:block;color:var(--muted);font-size:.78rem;min-height:3.6em}
.rv-tile-ic{display:inline-flex;width:40px;height:40px;border-radius:12px;align-items:center;justify-content:center;font-size:1.25rem;
background:linear-gradient(135deg,rgba(29,111,224,.9),rgba(56,189,248,.9));color:#fff;margin-bottom:.35rem}
.rv-tile-t{font-weight:700;font-size:1rem}.rv-tile-d{color:var(--muted);font-size:.8rem;line-height:1.4;height:4.2em;overflow:hidden;
display:-webkit-box;-webkit-line-clamp:3;-webkit-box-orient:vertical}

/* kpi */
.rv-kpi{position:relative;border:1px solid var(--line);border-radius:16px;padding:14px 16px 12px;background:var(--soft);overflow:hidden;
animation:rvIn .4s ease both}
.rv-kpi:before{content:"";position:absolute;left:0;top:0;bottom:0;width:4px;background:linear-gradient(180deg,var(--sky),var(--blue))}
.rv-kpi .l{color:var(--muted);font-size:.76rem;text-transform:uppercase;letter-spacing:.06em}
.rv-kpi .v{font-size:1.9rem;font-weight:800;line-height:1.15}
.rv-kpi .d{font-size:.76rem;color:var(--muted)}
.rv-kpi .i{position:absolute;right:12px;top:10px;font-size:1.3rem;opacity:.55}

/* pills and dots */
.rv-pill{display:inline-block;padding:2px 10px;border-radius:999px;font-size:.72rem;font-weight:700;letter-spacing:.02em}
.rv-ok{background:rgba(34,197,94,.16);color:#16a34a}.rv-bad{background:rgba(239,68,68,.16);color:#dc2626}
.rv-warn{background:rgba(245,158,11,.18);color:#d97706}.rv-info{background:rgba(56,189,248,.18);color:#0284c7}
.rv-muted{background:var(--soft);color:var(--muted)}
.rv-dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px;background:var(--ok);animation:rvPulse 2s infinite}
.rv-chip{display:inline-block;margin:2px 4px 2px 0;padding:1px 9px;border-radius:8px;font-size:.7rem;border:1px solid var(--line);color:var(--muted)}

/* tools and connectors: every card has the same structure and height so grids line up */
.rv-tool{border:1px solid var(--line);border-radius:16px;padding:14px 16px;background:var(--soft);transition:all .18s ease;animation:rvIn .4s ease both}
.rv-tool:hover{border-color:var(--sky);box-shadow:0 10px 26px rgba(56,189,248,.18);transform:translateY(-2px)}
.rv-tool .top{display:flex;align-items:center;gap:.6rem}
.rv-tool .ic{flex:none;display:inline-flex;width:38px;height:38px;border-radius:11px;align-items:center;justify-content:center;font-size:1.25rem;
background:linear-gradient(135deg,rgba(29,111,224,.9),rgba(56,189,248,.9))}
.rv-tool .nm{min-width:0;flex:1}
.rv-tool h4{margin:0;font-size:.95rem;line-height:1.25;height:2.5em;overflow:hidden;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;display:flex;align-items:center}
.rv-tool .v{color:var(--muted);font-size:.72rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.rv-tool p{color:var(--muted);font-size:.8rem;line-height:1.4;margin:.55rem 0;height:4.2em;overflow:hidden;
display:-webkit-box;-webkit-line-clamp:3;-webkit-box-orient:vertical}
.rv-tool .pills{height:1.7rem;overflow:hidden;white-space:nowrap}
.rv-tool .chips{height:1.9rem;overflow:hidden;white-space:nowrap;margin-top:.35rem}
.rv-tool.bare{border:0;background:transparent;padding:2px 2px 0;box-shadow:none;transform:none!important;animation:none}

/* automation flow */
.rv-flow{display:flex;align-items:stretch;gap:0;flex-wrap:wrap;margin:.2rem 0 .4rem}
.rv-step{flex:1;min-width:130px;border:1px solid var(--line);border-radius:14px;padding:10px 12px;background:var(--soft);text-align:center}
.rv-step .e{font-size:1.3rem}.rv-step b{display:block;font-size:.84rem}.rv-step span{font-size:.72rem;color:var(--muted)}
.rv-arrow{align-self:center;padding:0 6px;font-size:1.2rem;color:var(--sky);font-weight:800}
.rv-step.on{border-color:var(--sky);box-shadow:0 0 0 1px var(--sky) inset}

/* buttons, inputs, tabs */
[data-testid="stBaseButton-primary"]{background:linear-gradient(135deg,var(--blue),var(--sky))!important;color:#fff!important;border:none!important;
font-weight:700;box-shadow:0 6px 16px rgba(29,111,224,.30);transition:transform .15s ease,filter .15s ease}
[data-testid="stBaseButton-primary"]:hover{filter:brightness(1.1);transform:translateY(-1px)}
[data-testid="stBaseButton-secondary"]{border-radius:10px;border-color:var(--line)}
[data-testid="stBaseButton-secondary"]:hover{border-color:var(--sky);color:var(--sky)}
.stTabs [data-baseweb="tab-list"]{gap:6px;border-bottom:1px solid var(--line)}
.stTabs button[role="tab"]{border-radius:10px 10px 0 0;padding:10px 18px!important}
.stTabs button[aria-selected="true"]{background:linear-gradient(135deg,var(--blue),var(--sky))!important;color:#fff!important}
.stTabs [data-baseweb="tab-highlight"]{display:none}
div[data-testid="stMetric"]{border:1px solid var(--line);border-radius:14px;padding:10px 14px;background:var(--soft)}
[data-testid="stDataFrame"]{border-radius:12px;overflow:hidden;border:1px solid var(--line)}
.rv-signin{display:block;text-align:center;padding:.85rem 1rem;border-radius:12px;color:#fff!important;text-decoration:none!important;font-weight:700;
background:linear-gradient(135deg,var(--blue),var(--sky));box-shadow:0 10px 24px rgba(29,111,224,.35);transition:transform .15s ease,filter .15s ease}
.rv-signin:hover{filter:brightness(1.1);transform:translateY(-1px)}
.rv-login-brand{font-size:3.2rem;font-weight:800;letter-spacing:.35em;margin:.2rem 0 0}
.rv-login-sub{color:var(--sky);font-size:1.35rem;line-height:1.35;margin:.6rem 0 1.4rem}
.rv-feature{display:flex;gap:.7rem;align-items:center;margin:.55rem 0}
.rv-feature i{display:inline-block;width:18px;height:18px;border-radius:50%;border:2px solid var(--sky);flex:none;box-shadow:0 0 10px rgba(56,189,248,.5)}
[class*="st-key-rvlogin"]{position:relative;overflow:hidden;border-radius:22px;padding:34px 34px 28px!important;color:#0b2a55;
background:linear-gradient(135deg,#ffffff 0%,#e3f3ff 55%,#a9dcfb 140%);border:1px solid rgba(125,211,252,.7);box-shadow:0 22px 60px rgba(56,189,248,.28)}
[class*="st-key-rvlogin"]:before{content:"";position:absolute;right:-60px;bottom:-60px;width:420px;height:420px;opacity:.14;pointer-events:none;
background:url(/app/static/logo.png) center/contain no-repeat}
[class*="st-key-rvlogin"] *{color:#0b2a55}
.rv-pageglow{height:3px;border-radius:3px;background:linear-gradient(90deg,var(--blue),var(--sky),var(--blue));background-size:200% 100%;animation:rvFlow 6s linear infinite;margin:.1rem 0 .8rem}
</style>
"""


def setup(page_title: str | None = None) -> None:
    st.set_page_config(page_title=page_title or constants.APP_NAME,
                       page_icon=str(FAVICON) if FAVICON.exists() else "🛡️", layout="wide")


def inject() -> None:
    st.markdown(CSS, unsafe_allow_html=True)


def sidebar_logo() -> None:
    if LOGO.exists():
        try:
            st.logo(str(LOGO), icon_image=str(LOGO), size="large")
        except TypeError:  # older Streamlit without the size argument
            st.logo(str(LOGO), icon_image=str(LOGO))


def header(title: str, subtitle: str = "", icon: str = "", crumb: str = "") -> None:
    ic = f'<span class="ico">{html.escape(icon)}</span>' if icon else ""
    cr = f'<div class="rv-crumb">{html.escape(crumb)}</div>' if crumb else ""
    st.markdown(f'{cr}<div class="rv-title">{ic}{html.escape(title)}</div>'
                f'<div class="rv-sub">{html.escape(subtitle)}</div><div class="rv-pageglow"></div>', unsafe_allow_html=True)


def section(title: str) -> None:
    st.markdown(f'<div class="rv-sec">{html.escape(title)}</div>', unsafe_allow_html=True)


def kpi(col, label: str, value, detail: str = "", icon: str = "") -> None:
    i = f'<div class="i">{html.escape(icon)}</div>' if icon else ""
    col.markdown(f'<div class="rv-kpi">{i}<div class="l">{html.escape(label)}</div>'
                 f'<div class="v">{html.escape(str(value))}</div><div class="d">{html.escape(detail)}</div></div>',
                 unsafe_allow_html=True)


def tile_html(icon: str, title: str, text: str) -> str:
    return (f'<div class="rv-tile-ic">{html.escape(icon)}</div><div class="rv-tile-t">{html.escape(title)}</div>'
            f'<div class="rv-tile-d">{html.escape(text)}</div>')


def pill(text: str, kind: str = "ok") -> str:
    return f'<span class="rv-pill rv-{kind}">{html.escape(text)}</span>'


def chips(items) -> str:
    return "".join(f'<span class="rv-chip">{html.escape(str(i))}</span>' for i in items)


def tool_card_html(icon: str, name: str, vendor: str, desc: str, status_text: str, status_kind: str, caps,
                   bare: bool = False, extra: tuple[str, str] | None = None) -> str:
    more = " " + pill(*extra) if extra else ""
    return (f'<div class="rv-tool{" bare" if bare else ""}"><div class="top"><span class="ic">{html.escape(icon)}</span>'
            f'<div class="nm"><h4 title="{html.escape(name)}">{html.escape(name)}</h4><div class="v">{html.escape(vendor)}</div></div></div>'
            f'<p>{html.escape(desc)}</p><div class="pills">{pill(status_text, status_kind)}{more}</div>'
            f'<div class="chips">{chips(caps)}</div></div>')


def add_tile_html(title: str, text: str) -> str:
    return f'<div class="rv-add"><div class="plus">+</div><b>{html.escape(title)}</b><span>{html.escape(text)}</span></div>'


def flow_html(steps: list[tuple[str, str, str]], active: int | None = None) -> str:
    parts = []
    for i, (emoji, title, sub) in enumerate(steps):
        parts.append(f'<div class="rv-step{" on" if i == active else ""}"><div class="e">{html.escape(emoji)}</div>'
                     f'<b>{html.escape(title)}</b><span>{html.escape(sub)}</span></div>')
        if i < len(steps) - 1:
            parts.append('<div class="rv-arrow">➜</div>')
    return '<div class="rv-flow">' + "".join(parts) + "</div>"


def card(key: str):
    """A bordered, hover-styled panel."""
    return st.container(border=True, key=f"rvcard_{key}")
