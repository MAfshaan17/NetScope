# NetScope V1.9.3 — Live SOC Pipeline

## What changed

V1.9.3 makes the live packet callback the orchestration point for the complete
NetScope security pipeline:

Packet
-> Legacy SecurityDetector
-> DetectionEngine
-> SOCController
-> Threat Intelligence
-> Risk Engine
-> Correlation
-> Incident Manager
-> Attack Timeline
-> Attacker/Victim Profiles
-> Dashboard
-> Persistent SOC Storage

## Important

Do NOT replace:

- `src/risk_engine.py`
- `src/threat_intel.py`
- `src/dashboard.py`
- `src/attack_timeline.py`
- `src/soc_controller.py`

This package only adds the V1.9.3 live analyzer and its tests.

## Install

Copy:

`src/analyzer.py`

into:

`D:\NetScope\src\analyzer.py`

Copy:

`tests/test_v193_live_soc.py`

into:

`D:\NetScope\tests\test_v193_live_soc.py`

## Validate

```powershell
python -m pytest tests\test_v193_live_soc.py -v
```

Then:

```powershell
python -m pytest -v
```

The existing V1.9.2 baseline is 114 tests.

## Run

```powershell
python -m src.analyzer
```

Examples:

```powershell
python -m src.analyzer --count 50
```

```powershell
python -m src.analyzer --protocol tcp --count 50
```

```powershell
python -m src.analyzer --iface "Ethernet" --count 100
```

Custom IOC lists:

```powershell
python -m src.analyzer --ti-malicious "198.51.100.20,203.0.113.99" --ti-suspicious "203.0.113.50" --count 100
```

## V1.9.3 design rule

A packet-processing exception is isolated inside `packet_callback`, so one
malformed packet cannot terminate the live capture loop.
