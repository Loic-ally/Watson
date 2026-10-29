"""MetSec — authorized AI pentest agent. See ROADMAP.md."""
__version__ = "0.0.1"

# Load .env at package import so env vars (META_API_KEY, test-account creds like KM0_USER/
# KM0_PASS, SUPABASE_ANON_KEY) are available no matter which module runs first — auth/recon
# read credentials before anything imports config, which is where load_dotenv used to live.
try:
    from dotenv import load_dotenv as _load_dotenv

    _load_dotenv()
except Exception:  # noqa: BLE001 — dotenv optional; real env vars still work
    pass
