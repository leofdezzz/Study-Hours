# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
npm install
npm start              # node --no-warnings --experimental-sqlite server.js
```

Requires **Node ≥22** because the server uses `node:sqlite` (still marked experimental — the `--experimental-sqlite` flag in `package.json` is intentional).

Environment variables honored by `server.js`:
- `PORT` (default `3000`)
- `DB_PATH` (default `./data.db`)
- `JWT_SECRET` (default is a placeholder — **override in production**)
- `VAPID_EMAIL` (contact address for web-push; default `admin@studyhours.app`)

No test suite, no lint config, no build step. `Procfile` is for Heroku-style dynos.

## Architecture

Two files carry the whole app: **`server.js`** (Express + SQLite + web-push) and **`index.html`** (~2000 lines containing all HTML, CSS, and client JS). `service-worker.js` handles PWA caching and push display; `manifest.json` + `icon.svg` complete the install target.

### Server (`server.js`)

- **Single-file Express app.** All tables are created idempotently on boot via one `db.exec` block. There is one lightweight migration in the wild (adding `settings` to `user_data`) done via a try/catch'd `ALTER TABLE`.
- **Auth.** JWT in `Authorization: Bearer <token>`, tokens expire in 30 days. `auth` middleware attaches `req.user = { id, username }`. Usernames are stored lowercase.
- **Data model per user** lives in `user_data` as three JSON blobs (`subjects`, `logs`, `settings`). The client treats this as one document and PUTs the full thing back on every mutation — server does not merge, it replaces.
- **Groups & leaderboards.** Group join codes are 6-char strings from a confusables-free alphabet (`generateCode`). Leaderboard endpoint re-computes each member's today/week/total on demand from their raw `logs`+`subjects` (`computeStats`). When the last member leaves, the group row is deleted.
- **Reactions** (`🔥 💀 😤 👑` only, enforced by `VALID_EMOJIS`) are keyed by ISO week's Monday (`currentWeekKeys()[0]`). POSTing the same reaction toggles it off.
- **VAPID keys are generated once and persisted in the `config` table** — do not regenerate or all existing push subscriptions break. The public key is served at `GET /api/push/key`.
- **Weekly notifications** run from a naive `setInterval(…, 60_000)` that fires the send job once when UTC is Sunday 20:00. Deduping is via a `config` row keyed `weekly_notif_<weekKey>`, so a restart in that minute won't double-send. Multiple server instances would double-send — this app assumes single-process deploy.

### Client (`index.html`)

- **All state lives in one `data` object** (`{ subjects, logs }`) plus a separate `settings` object. After any mutation, call `persist()` (which PUTs `/api/data`) — there is no per-field endpoint. Settings use `saveSettings(patch)` which PUTs `/api/settings`.
- **`apiFetch` is the only network wrapper.** A 401 clears the token and shows the auth screen, then throws — callers generally `.catch(() => {})`.
- **Render pipeline:** `render()` calls sub-renderers (`renderHeader`, `renderStats`, `renderChart`, `renderSubjects`, …). `renderSubjects` does a diff-style update — re-using existing DOM nodes when the subject set hasn't changed, rebuilding when it has. Don't rewrite this to a full innerHTML swap without preserving the in-place update behavior, because button animations and inputs lose state otherwise.
- **Date keys** are produced by `dk(date)` → `YYYY-MM-DD`. Week computations are Monday-based via `weekOf(offset)`. `weekOffset` is a module-level global for the week navigator.
- **Polling:** `boot()` kicks off a `setInterval(loadGroups, 30000)`. The leaderboard, when open, also polls via `pollLeaderboard`. No WebSocket infra.
- **Push subscription.** `initPush()` fetches the VAPID key, registers the service worker, subscribes, and POSTs to `/api/push/subscribe`. `togglePush()` is the user-facing toggle.

### Custom date picker (gotcha)

The subject sheet's "Fecha del examen" uses a fully custom calendar, not `<input type="date">`. Two things to know:

1. **The popup (`#J_dpPopup`) must remain a direct child of `<body>`**, not inside the modal sheet. The `.sheet` element has a CSS `transform`, which (per spec) becomes the containing block for any `position: fixed` descendant. Putting the popup inside the sheet causes wrong positioning on desktop (the popup drifts off to one side because viewport-relative `getBoundingClientRect()` coords don't match sheet-relative fixed positioning).
2. `dpPosition()` always opens the popup **above** the trigger field. This is deliberate — the sheet is anchored at the bottom on mobile, so opening downward would clip.

### Service worker

Cache name is `study-hours-v<N>` — **bump the version** in `service-worker.js` when shipping changes users need immediately, otherwise clients serve stale `index.html` from cache. `/api/*` requests are passed through (never cached).

### Legacy / ignore

- `db.json` is a leftover from a pre-SQLite JSON store. Nothing reads it.
- `Study Hours.html` (root, with space in name) is an untracked backup/snapshot. The live file is `index.html`.

## Conventions

- UI copy is in Spanish. Keep user-facing strings Spanish when editing.
- Inline styles in `index.html` use the CSS variables at the top of `<style>` (`--bg`, `--s1/s2/s3`, `--text`, `--t2/t3`, `--green`, `--red`). Don't hardcode hex colors for theme-able surfaces.
- DOM IDs are prefixed `J_` for anything JS touches (`J_overlay`, `J_input`, `J_dpPopup`, …). Preserve the prefix when adding new interactive elements.
- After modifying `data.subjects` or `data.logs` in any handler, call `persist()` before `render()`.
