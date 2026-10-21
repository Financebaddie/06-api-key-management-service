# Custom URL Shortener

A local-first URL shortener with a **FastAPI** backend, SQLite database, and a plain HTML/CSS/JavaScript frontend served by the API app. Features include API-key-protected link creation and analytics, public redirects with click logging, API-key requests, and an admin panel for approval, key generation, expiry, revocation, and global stats.

## Project structure

```text
.
├── backend/
│   └── app/
│       ├── main.py       # FastAPI routes, middleware/dependencies, and app setup
│       ├── schema.sql    # SQLite schema
│       └── cli.py        # One-time API key creation utility
├── frontend/             # HTML, CSS, and browser JavaScript
├── data/                 # Local SQLite database (created automatically)
├── requirements.txt
└── .env.example
```

## Run locally

Requires Python 3.10 or newer.

```sh
python3 -m venv .venv
source .venv/bin/activate       # Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
cp .env.example .env            # Windows: copy .env.example .env
```

On Debian or Ubuntu, if creating the virtual environment reports that `venv` or `ensurepip` is missing, install it with `sudo apt update && sudo apt install python3-full`, then rerun `python3 -m venv .venv`.

Edit `.env` and replace `ADMIN_PASSWORD` with a long, unique password. Start the app:

```sh
uvicorn backend.app.main:app --host 127.0.0.1 --port 3000 --reload
```

Open `http://localhost:3000/`. The admin page is at `/admin` and login at `/admin/login`. Users can request a key at `/api-key/request`. To create a key directly from the command line:

```sh
python -m backend.app.cli "Local owner" owner@example.com
```

The generated `sk_live_...` secret is printed once; the database stores only its SHA-256 hash.

## API

Shorten a link (send the key in `x-api-key` or as a Bearer token):

```sh
curl -X POST http://localhost:3000/api/v1/shorten \
  -H 'content-type: application/json' \
  -H 'x-api-key: sk_live_REPLACE_WITH_YOUR_KEY' \
  -d '{"url":"https://example.com/long-page"}'
```

Open the returned `shortUrl` to record a click and redirect. Retrieve analytics for a link owned by the same key:

```sh
curl http://localhost:3000/api/v1/analytics/CODE \
  -H 'Authorization: Bearer sk_live_REPLACE_WITH_YOUR_KEY'
```

Missing or unknown keys receive `401`; revoked or expired keys receive `403`. Analytics include click counts, timestamps, and user-agent metadata. IP addresses are anonymized before storage.

## Deploy on Render

Create a Render **Web Service** from the Git repository. Set:

- Runtime: **Python 3**
- Build command: `pip install -r requirements.txt`
- Start command: `uvicorn backend.app.main:app --host 0.0.0.0 --port $PORT`
- Health check path: `/health`

Configure these environment variables in Render:

```text
DATABASE_PATH=/var/data/shortener.sqlite
ADMIN_USER=your-admin-name
ADMIN_PASSWORD=<a long, unique password>
```

Render supplies `PORT` and `RENDER_EXTERNAL_URL`; the application uses the latter to generate short links and set the admin session cookie securely. Add a persistent disk mounted at `/var/data` so SQLite survives deploys and restarts. Render persistent disks require a paid service and limit the app to one service instance. Never commit `.env` or paste secrets into source control.
