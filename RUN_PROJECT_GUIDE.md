# How to Run Adhikar

This guide starts Adhikar locally with the offline mock harness. The mock mode needs no API key and is the recommended way to test the project before the hackathon.

## 1. Open a terminal

On macOS, open **Terminal**. Then move into the project directory:

```bash
cd "/Users/rutikmangale/Documents/DRIVE F/Konsole/Adhikar"
```

Confirm that you are in the correct directory:

```bash
pwd
ls
```

You should see files and directories such as:

```text
README.md
requirements.txt
Makefile
app
data
evals
ui
```

## 2. Confirm Python is installed

Run:

```bash
python3 --version
```

Python 3.11 or newer is recommended. Example:

```text
Python 3.11.9
```

If `python3` is not found, install Python from [python.org](https://www.python.org/downloads/) and reopen the terminal.

## 3. Create a virtual environment

A virtual environment keeps this project's packages separate from other Python projects.

```bash
python3 -m venv .venv
```

Activate it:

```bash
source .venv/bin/activate
```

After activation, the terminal prompt should begin with `(.venv)`.

Whenever you open a new terminal later, return to the project directory and activate the environment again:

```bash
cd "/Users/rutikmangale/Documents/DRIVE F/Konsole/Adhikar"
source .venv/bin/activate
```

## 4. Install the required packages

With the virtual environment active, run:

```bash
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
```

This installs FastAPI, Uvicorn, Pydantic, HTTPX, and python-dotenv.

## 5. Create the local configuration

Copy the example configuration:

```bash
cp .env.example .env
```

The default configuration contains:

```text
HARNESS_BACKEND=mock
DEFAULT_REGION=in
```

Keep `HARNESS_BACKEND=mock` for local development. Mock mode is deterministic, works offline, and does not require a Konsole API key.

For a stronger local token-map key, open `.env` in a text editor and replace:

```text
TOKEN_MAP_KEY=replace-for-production
```

Generate a random value with:

```bash
openssl rand -hex 32
```

Copy the generated value after `TOKEN_MAP_KEY=`.

Never commit `.env`; it is already listed in `.gitignore`.

## 6. Run all checks

Before starting the web application, verify the build:

```bash
make test
```

This command runs:

1. Security and pipeline unit tests.
2. The test that prevents direct model-provider access outside `app/harness.py`.
3. All 15 DPR evaluation cases.

The final evaluation output should contain:

```text
15/15 passed · adversarial 5/5 guarded
```

## 7. Start the application

Run:

```bash
make demo
```

Alternatively, start it directly:

```bash
python3 -m uvicorn app.main:app --reload --port 8018
```

The terminal should show:

```text
Application startup complete.
Uvicorn running on http://127.0.0.1:8018
```

Keep this terminal open while using the application.

## 8. Open Adhikar

Open a web browser and visit:

[http://127.0.0.1:8018](http://127.0.0.1:8018)

Useful development pages:

- Application: [http://127.0.0.1:8018](http://127.0.0.1:8018)
- API documentation: [http://127.0.0.1:8018/docs](http://127.0.0.1:8018/docs)
- Health check: [http://127.0.0.1:8018/api/health](http://127.0.0.1:8018/api/health)

## 9. Try a normal request

In the **Demo corpus** selector, choose:

```text
01 · plain access request
```

Keep these settings:

```text
Processing region: India · in
Protection mode: Defence in depth
Injection inspection: enabled
PII redaction: enabled
```

Click **Run protected triage**.

Expected result:

- Status: `TRIAGED`
- Right: `ACCESS`
- Organisation SLA is displayed
- Identifiers are replaced with tokens
- A draft response is available for human approval
- The footer shows `served from: in`
- The audit badge reports that the chain is intact

Clicking **Approve draft** only changes the workflow status. It does not send anything to a requester.

## 10. Try an adversarial request

Choose:

```text
11 · direct instruction injection
```

Keep **Defence in depth** and **Injection inspection** enabled, then click **Run protected triage**.

Expected result:

- Status: `BLOCKED`
- A red adversarial-content banner appears
- Escalation contains `ADVERSARIAL_CONTENT`
- Escalation contains `THIRD_PARTY_DATA`
- The draft response is withheld
- The trace reports `injection_flagged: true`
- The security event is added to the audit chain

Expand **Decision trace** to inspect the protected payload, model response, region, provider, latency, and cost.

## 11. Test the API manually

Keep the application running and open a second terminal.

Move into the project and activate the environment:

```bash
cd "/Users/rutikmangale/Documents/DRIVE F/Konsole/Adhikar"
source .venv/bin/activate
```

Check application health:

```bash
curl -s http://127.0.0.1:8018/api/health
```

Submit a synthetic request:

```bash
curl -s http://127.0.0.1:8018/api/requests \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Please provide the data linked to account ZX-00000001 and contact nova.quill@example.in.",
    "org_id": "demo-org",
    "policy_overrides": {
      "region": "in",
      "tokenization_mode": "defence_in_depth"
    }
  }'
```

List saved requests:

```bash
curl -s http://127.0.0.1:8018/api/requests
```

Verify the audit chain:

```bash
curl -s http://127.0.0.1:8018/api/audit/verify
```

Expected result:

```json
{
  "intact": true,
  "events": 1,
  "broken_at": null
}
```

The event count may be higher if you have already processed other requests.

## 12. Load or reset demo data

Load all 15 corpus requests:

```bash
curl -s -X POST http://127.0.0.1:8018/api/demo/load-corpus
```

Reset the local demo database:

```bash
curl -i -X POST http://127.0.0.1:8018/api/demo/reset
```

Reset deletes local demo requests, cached verdicts, encrypted token maps, and audit events. It does not delete source files.

## 13. Stop the application

Return to the terminal running Uvicorn and press:

```text
Control + C
```

To leave the virtual environment, run:

```bash
deactivate
```

## 14. Start it again later

You do not need to reinstall packages every time. Use:

```bash
cd "/Users/rutikmangale/Documents/DRIVE F/Konsole/Adhikar"
source .venv/bin/activate
make demo
```

Then open [http://127.0.0.1:8018](http://127.0.0.1:8018).

## Troubleshooting

### `python3: command not found`

Install Python 3.11 or newer from [python.org](https://www.python.org/downloads/).

### `No module named uvicorn` or `No module named fastapi`

Activate the virtual environment and reinstall dependencies:

```bash
source .venv/bin/activate
python3 -m pip install -r requirements.txt
```

### Port 8018 is already in use

Start the application on another port:

```bash
python3 -m uvicorn app.main:app --reload --port 8019
```

Then open [http://127.0.0.1:8019](http://127.0.0.1:8019).

### The application opens but has old demo data

Reset it:

```bash
curl -i -X POST http://127.0.0.1:8018/api/demo/reset
```

Refresh the browser page.

### `make: command not found`

Start Uvicorn directly:

```bash
python3 -m uvicorn app.main:app --reload --port 8018
```

### Konsole backend reports `HARNESS_ERROR`

For local use, confirm that `.env` contains:

```text
HARNESS_BACKEND=mock
```

Restart the application after changing `.env`.

The `konsole` backend is intentionally incomplete until the five event-specific API mappings in `app/harness.py` are confirmed.

## Quick-start summary

For future runs, these are the essential commands:

```bash
cd "/Users/rutikmangale/Documents/DRIVE F/Konsole/Adhikar"
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
cp .env.example .env
make test
make demo
```

Open [http://127.0.0.1:8018](http://127.0.0.1:8018).
