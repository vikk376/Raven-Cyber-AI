"""Sign-in page. Its text and rules are managed from Admin > Sign-in settings."""
import html

import streamlit as st

from src.core import constants
from src.services import auth, settings
from src.ui import theme

FEATURES = ("Detect Faster", "Investigate Smarter", "Respond Automatically", "Powered by Agentic AI")


def render(message: tuple[str, str] | None = None) -> None:
    theme.inject()
    title = settings.get("login.title", "Welcome Back")
    text = settings.get("login.message", "")
    left, right = st.columns([1.15, 1], gap="large")
    with left:
        if theme.LOGO.exists():
            st.image(str(theme.LOGO), width=190)
        st.markdown('<div class="rv-login-brand">RAVEN</div><div style="opacity:.6;letter-spacing:.3em">CYBER AI</div>',
                    unsafe_allow_html=True)
        st.markdown(f'<div class="rv-login-sub">{html.escape(constants.APP_TAGLINE)}</div>', unsafe_allow_html=True)
        st.markdown("".join(f'<div class="rv-feature"><i></i>{html.escape(f)}</div>' for f in FEATURES),
                    unsafe_allow_html=True)
    with right, st.container(key="rvlogin"):
        st.markdown(f"### {html.escape(title)}")
        if text:
            st.write(text)
        if message:
            kind, msg = message
            {"success": st.success, "pending": st.warning, "error": st.error}.get(kind, st.info)(msg)
        try:
            url = auth.get_login_url(auth.new_state())
        except Exception as exc:  # noqa: BLE001
            st.error(f"Cannot start Microsoft sign-in. Check AZURE_TENANT_ID and AZURE_CLIENT_ID. ({exc})")
            return
        # target=_self keeps the sign-in in this tab instead of opening a new one
        st.markdown(f'<a class="rv-signin" href="{html.escape(url)}" target="_self">Sign in with Microsoft</a>', unsafe_allow_html=True)
        allowed = settings.get_list("login.allowed_domains")
        if allowed:
            st.caption("Allowed domains: " + ", ".join(allowed))
        st.caption("New to Raven? Contact your administrator for access. All activity is recorded in an audit log.")
