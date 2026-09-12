# NetScope Production-Readiness Pack

## 1. Local validation

From `D:\NetScope`:

```powershell
python -m pytest -q
python -m uvicorn src.api:app --reload
```

Open:

```text
http://127.0.0.1:8000/
```

The root now redirects to the SOC dashboard.

## 2. GitHub Actions

Copy `.github/workflows/ci.yml` into the repository.

Every push to `main` and every pull request targeting `main` will run the complete pytest suite on Python 3.13 and 3.14.

## 3. API container

The included `Dockerfile` packages the FastAPI/dashboard layer.

Build:

```powershell
docker build -t netscope-api .
```

Run:

```powershell
docker run --rm -p 8000:8000 -v ${PWD}/logs:/app/logs netscope-api
```

Open:

```text
http://127.0.0.1:8000/
```

### Important capture note

This container is for the API/dashboard layer. Live packet capture should normally run on the machine/network where the traffic is observable. Containerizing packet capture requires host-network and elevated capture permissions and is platform-specific.

## 4. Final verification

```powershell
python -m pytest -q
python -m src.analyzer --count 20
python -m uvicorn src.api:app --reload
```

Then check:

- `/` → dashboard
- `/health` → health status
- `/stats` → packet/flow/alert counts
- `/alerts` → persisted alerts
- `/flows` → persisted flows
- `/soc/summary` → V2.1 SOC persistence
- `/dashboard/` → web dashboard
