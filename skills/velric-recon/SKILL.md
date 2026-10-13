---
name: velric-recon
description: Authorized web-app reconnaissance with velric-agent. Use when the task needs API surface discovery (endpoints, routes, params) on an authorized SPA or MPA target — static bundle harvest, headless runtime capture, or permission-tree rebuilding. Tools are stateless: each call takes explicit arguments and writes artifacts under a caller-supplied output_root.
metadata:
  version: "1"
---

# velric-agent recon

Stateless recon toolset for **authorized** targets. One CLI and one MCP server,
same core. Every tool call is independent: arguments in, work done, artifacts
under the caller's `output_root`, nothing remembered.

## Route the target first

Pick the entry tool from what the user supplied:

- **SPA** (empty shell + JS chunks): `harvest_static` first — it downloads the
  full chunk corpus and emits `api_static.txt` / `routes.txt`.
- **MPA** (server-rendered forms, no endpoint bundle): `spider_mpa` — forms
  with parameters are the real endpoints.
- **Live runtime surface** (methods/bodies a static pass cannot see):
  `capture_runtime` after static; needs a Chromium executable.
- **Enterprise admin with code-gated menus**: `build_perm_tree` over the
  harvested `js/` corpus to rebuild permissive menu stubs.
- **Single host sanity check**: `dns_resolve`, then `http_probe`.
- **Parameter field sets**: record samples (the runtime capture detail or any
  source), then `merge_params` — never conclude required/optional from one
  sample.

## Workflow

1. Classify: SPA or MPA? (`http_probe` the entry; look at content type and
   whether the HTML is a shell with `<script src>` chunks.)
2. Static first — it is the safety net when runtime is blocked:
   `harvest_static` (SPA) or `spider_mpa` (MPA).
3. Runtime to recover methods/bodies: `capture_runtime` with the entry URL;
   pass `routes` from the static `routes.txt` for deeper coverage.
   - Larger production SPAs (Grafana, dashboards, admin consoles) boot their
     first API burst **seconds** after the document loads: raise the wait
     (`capture_runtime` `waitMs` / CLI `--wait 6000-8000`, `perRouteMs` /
     `--per-route 4000-6000`) or the capture reports few/zero calls.
   - Custom API prefixes (Algolia `/1/indexes/`, SaaS `/v2/`, `/internal/`
     variants) are not matched by the default pattern: pass an explicit
     `apiPattern` (MCP) / `--api-pattern '<re>'` (CLI) to record them.
4. If module pages stay blank behind permission gates: `build_perm_tree`, feed
   its stubs back into `capture_runtime` via `stubs`, re-run.
5. Merge parameters: collect `param_samples.json` entries, `merge_params`.
6. Report honestly: counts, uncovered modules, and which pass produced what.

## Boundaries

- Recon only: enumerate paths, methods, params, routes. No exploitation.
- Defeat of the three client gates (render/interceptor/content) uses client-side
  stubs and mock responses only; outbound requests are recorded as-is.
- Empty data / blank tables under stubs are expected — do not pivot to real
  credential attempts.
- Every conclusion names its source pass (static / runtime / merged) and its
  coverage limits.

## Read only the relevant reference

- Gate theory, stub tiers, and per-target tuning:
  [references/three-gates.md](references/three-gates.md)
- Artifact inventory and merge semantics:
  [references/artifacts.md](references/artifacts.md)
