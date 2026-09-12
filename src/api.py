from pathlib import Path
import json

from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles


app = FastAPI(
    title="NetScope API",
    description="Network Security Monitoring and SOC API",
    version="2.1.0",
)

BASE_DIR = Path(__file__).resolve().parent.parent
LOG_DIR = BASE_DIR / "logs"
DASHBOARD_DIR = BASE_DIR / "dashboard"


def load_json(filename, default=None):
    path = LOG_DIR / filename
    if not path.exists():
        return [] if default is None else default

    try:
        with path.open("r", encoding="utf-8") as file:
            return json.load(file)
    except (json.JSONDecodeError, OSError):
        return [] if default is None else default


@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse(url="/dashboard/")


@app.get("/health")
def health():
    return {"name": "NetScope", "version": "2.1.0", "status": "healthy"}


@app.get("/packets")
def packets():
    return load_json("packets.json")


@app.get("/flows")
def flows():
    return load_json("flows.json")


@app.get("/alerts")
def alerts():
    return load_json("security_alerts.json")


@app.get("/stats")
def stats():
    packets_data = load_json("packets.json")
    flows_data = load_json("flows.json")
    alerts_data = load_json("security_alerts.json")
    return {
        "packets": len(packets_data),
        "flows": len(flows_data),
        "alerts": len(alerts_data),
    }


@app.get("/soc/summary")
def soc_summary():
    return {
        "cases": load_json("soc_cases.json", {}),
        "risk_trend": load_json("risk_trend.json", {}),
    }


if DASHBOARD_DIR.exists():
    app.mount(
        "/dashboard",
        StaticFiles(directory=str(DASHBOARD_DIR), html=True),
        name="dashboard",
    )


@app.get("/ui", include_in_schema=False)
def dashboard_redirect():
    return RedirectResponse(url="/dashboard/")
