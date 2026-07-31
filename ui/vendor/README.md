# Vendored UI runtimes

These pinned production assets keep the single-page console functional without
network access or a runtime build step:

- React 18.3.1 — MIT License
- React DOM 18.3.1 — MIT License
- `app.min.js` — compiled from the canonical JSX source in `ui/index.html`

React files were downloaded from their version-pinned package distributions.
After editing the JSX source block, run `make build-ui`. Babel Standalone 7.26.4
is kept under `tools/vendor` for that development-only compilation step and is
never served to browsers. The `/assets` route applies immutable caching.
