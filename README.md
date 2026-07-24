# Caddy Manager

A tiny, dependency-free web UI to manage the reverse-proxy routes in your
[Caddy](https://caddyserver.com) server — view, add, edit, enable/disable and
delete domains without hand-editing the Caddyfile.

It keeps your routes as structured JSON, renders a Caddyfile from them, and
applies changes **live** through Caddy's admin API (which validates first, so a
bad entry is rejected instead of taking your proxy down).

- 🐍 **Zero dependencies** — pure Python standard library, runs on a ~50 MB image.
- ⚡ **Live apply** — changes hit the running Caddy instantly via `POST /load`; no restart.
- 🔐 **Own login** — first-run onboarding creates a hashed admin account (or use env credentials).
- ❤️ **Health checks** — a reachability dot per upstream.
- 🧩 **Advanced escape hatch** — per-route raw directives for redirects and headers.
- 🌓 Light/dark, responsive, single-file frontend.

## How it works

```
browser ──HTTPS──▶ Caddy ──▶ caddy-manager (this app)
                    ▲               │
                    │  admin API    │ renders + writes
                    └──── :2019 ◀───┘ /path/to/Caddyfile
```

`data/routes.json` is the source of truth. On every change the app re-renders the
Caddyfile, `POST`s it to the Caddy admin API to apply live, and writes it to disk
so it survives restarts. The app never needs your ACME/DNS secrets — Caddy adapts
the config in its own environment.

## Requirements

- An existing **Caddy** instance running in Docker with:
  - the **admin API enabled on the shared docker network** — add `admin :2019` to the
    global options block of your Caddyfile (do **not** publish `2019` to your LAN);
  - a Caddyfile at a known host path that this app can bind-mount.
- Docker + Docker Compose.

## Quick start

1. Enable the admin API in your Caddyfile's global block and make sure Caddy is on
   a docker network this app can join:

   ```caddyfile
   {
       admin :2019
       # ... your email / acme_dns / etc.
   }
   ```

2. Configure and launch:

   ```bash
   cp .env.example .env
   # edit .env: CADDYFILE_HOST_PATH, CADDY_NETWORK
   docker compose up -d --build
   ```

3. Add a route in Caddy pointing your chosen hostname at this container, e.g.:

   ```caddyfile
   @manager host caddy.example.com
   handle @manager {
       reverse_proxy caddy-manager:8080
   }
   ```

4. Open your hostname in a browser and complete the onboarding to create your admin account.

> Tip: seed `data/routes.json` from [`routes.example.json`](routes.example.json),
> or just let the app create a starter file on first run and edit from the UI.

## Prebuilt image

Every push to `main` publishes a multi-arch image (`linux/amd64` + `linux/arm64`)
to GitHub Container Registry, so you can skip the local build:

```bash
docker pull ghcr.io/jozee-engineering/caddy-manager:latest
```

To use it in `docker-compose.yml`, replace `build: .` with:

```yaml
    image: ghcr.io/jozee-engineering/caddy-manager:latest
```

Tags: `latest` (tip of `main`), `sha-<commit>`, and semver tags like `0.1.0` / `0.1` for releases.

## Configuration

| Env var          | Default                 | Description                                            |
| ---------------- | ----------------------- | ------------------------------------------------------ |
| `CADDY_ADMIN`    | `http://caddy:2019`     | Base URL of Caddy's admin API.                         |
| `CADDYFILE_PATH` | `/caddy/Caddyfile`      | Path to the Caddyfile **inside** the container.        |
| `ROUTES_PATH`    | `/data/routes.json`     | Where the route store lives.                           |
| `AUTH_PATH`      | `/data/auth.json`       | Where the hashed admin credential is stored.           |
| `LISTEN_PORT`    | `8080`                  | Port the app listens on.                               |
| `BASE_DOMAIN`    | `example.com`           | Default base domain when bootstrapping a fresh store.  |
| `UI_USER`/`UI_PASS` | *(unset)*            | Set **both** to skip onboarding and use fixed creds.   |

Compose-level: `CADDYFILE_HOST_PATH` (host path of the Caddyfile) and
`CADDY_NETWORK` (external docker network name).

## Authentication

- **First run:** no account exists, so you're taken to an onboarding screen to set a
  username + password. The password is stored hashed (PBKDF2-HMAC-SHA256) in `auth.json`.
- **Env override:** set `UI_USER` and `UI_PASS` to use fixed credentials and skip
  onboarding entirely — handy for automated/headless deploys.
- Sessions are stateless HMAC-signed cookies (`HttpOnly`, `Secure`, `SameSite=Strict`).

## Security notes

Anyone who can log in can rewrite your whole reverse-proxy config, so:

- Keep it behind Caddy (HTTPS) and **do not** expose the admin API (`:2019`) to your LAN.
- Until you complete onboarding, whoever reaches it first can claim the admin account —
  set it up promptly, or use the `UI_USER`/`UI_PASS` override.

## License

[MIT](LICENSE)
