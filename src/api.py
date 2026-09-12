from pathlib import Path
import json

from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles


app = FastAPI(
    title="NetScope API",
    description="Network Security Monitoring API",
    version="1.0.0"
)


# =========================================================
# PATHS
# =========================================================

BASE_DIR = Path(__file__).resolve().parent.parent

LOG_DIR = BASE_DIR / "logs"
DASHBOARD_DIR = BASE_DIR / "dashboard"


# =========================================================
# LOAD JSON
# =========================================================

def load_json(filename):

    path = LOG_DIR / filename

    if not path.exists():
        return []

    try:

        with open(
            path,
            "r",
            encoding="utf-8"
        ) as file:

            return json.load(file)

    except (json.JSONDecodeError, OSError):

        return []


# =========================================================
# API ROOT
# =========================================================

@app.get("/")
def root():

    return {
        "name": "NetScope",
        "version": "1.0",
        "status": "running"
    }


# =========================================================
# PACKETS
# =========================================================

@app.get("/packets")
def packets():

    return load_json("packets.json")


# =========================================================
# FLOWS
# =========================================================

@app.get("/flows")
def flows():

    return load_json("flows.json")


# =========================================================
# ALERTS
# =========================================================

@app.get("/alerts")
def alerts():

    return load_json("security_alerts.json")


# =========================================================
# STATISTICS
# =========================================================

@app.get("/stats")
def stats():

    packets = load_json("packets.json")
    flows = load_json("flows.json")
    alerts = load_json("security_alerts.json")

    return {
        "packets": len(packets),
        "flows": len(flows),
        "alerts": len(alerts)
    }


# =========================================================
# DASHBOARD
# =========================================================

if DASHBOARD_DIR.exists():

    app.mount(
        "/dashboard",
        StaticFiles(
            directory=str(DASHBOARD_DIR),
            html=True
        ),
        name="dashboard"
    )


# =========================================================
# DASHBOARD REDIRECT
# =========================================================

@app.get("/ui")
def dashboard_redirect():

    return RedirectResponse(
        url="/dashboard/"
    )