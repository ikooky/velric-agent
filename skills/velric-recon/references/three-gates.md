# The three gates

Enterprise admin SPAs keep unauthenticated users out with three client-side
gates. `capture_runtime` defeats them with stubs — understand them before
tuning.

## Gate 1 — render gate ("how does the app know I'm logged in?")

The app reads a cookie or localStorage key and derives `isLogin`. To pass it,
inject a truthy value (`cookies` / `localStorage` args). Encodings:

| storage content | inject as |
| --- | --- |
| plain string / `"1"` | any truthy literal |
| `JSON.parse(x)` | `json:{...}` |
| `JSON.parse(atob(x))` | `b64json:{...}` |
| JWT | unsigned / `alg:none` token |

Discover the key name by grepping harvested JS for `isLogin`, `getToken`,
`localStorage.getItem("...")`.

## Gate 2 — interceptor gate ("what triggers the redirect to /login?")

An axios/fetch interceptor inspects a response code field (`response_code`,
`code`, `errno`, `ret`...) and redirects on the "not logged in" value. The
preload hook rewrites those fields to the success value on every JSON response
(`neutralize.fields` + `neutralize.success`). Find the field name by grepping
for `interceptors.response` and the code comparisons next to it.

## Gate 3 — content gate ("where do the menus come from?")

Menus/permissions come from an endpoint (`permissions/all`, `role_permissions`,
`/menu`...). Stub it with a full-feature payload: `build_perm_tree` generates
permissive stubs from the harvested JS (`permissions_all_stub.json`,
`role_permissions_stub.json`) — feed them back via `capture_runtime`'s `stubs`
argument.

## Mock tiers

- `L1` — precise stubs only (menu/permission forgery).
- `L2` — negative-rewrite: patch unauthorized codes to success in any JSON.
- `L3` — fallback: synthesize an empty-success body for unmatched API paths.

Default is `L1+L2`. Add `L3` when blank modules should still mount.

## Honest limits

- Hardened targets (signed cookies, server-rendered menus) stay at the shell:
  static enumeration still works; note it and stop.
- A single runtime sample never implies required/optional — that is what
  `merge_params` confidence is for.
