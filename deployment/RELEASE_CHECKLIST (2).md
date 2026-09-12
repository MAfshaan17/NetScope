# NetScope Final Release Checklist

- [ ] Replace local `README.md` with the polished release README.
- [ ] Copy `.github/workflows/ci.yml`.
- [ ] Copy `Dockerfile`.
- [ ] Copy `.dockerignore`.
- [ ] Replace `src/api.py` with the hardened API version.
- [ ] Run `python -m pytest -q`.
- [ ] Confirm the full suite is green locally.
- [ ] Run a short authorized packet capture.
- [ ] Start the API and verify `/`, `/health`, `/stats`, `/alerts`, `/flows`.
- [ ] Commit and push to GitHub.
- [ ] Confirm GitHub Actions passes.
