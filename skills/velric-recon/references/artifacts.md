# Artifacts inventory

Every producing tool writes only under the caller-supplied absolute
`output_root`. Nothing is written elsewhere; nothing persists between calls.

## harvest_static

| file | content |
| --- | --- |
| `index.html` | entry document |
| `js/` | every downloaded chunk (seed scripts + manifest expansion) |
| `api_static.txt` | API-looking paths, sorted |
| `paths_other.txt` | other path literals (depth ≥2, non-asset) |
| `routes.txt` | frontend route paths (`path:` / `to:` / `redirect:` / `href:`) |
| `chunkmap.txt` | every chunk filename the manifests referenced |

## spider_mpa

| file | content |
| --- | --- |
| `forms.txt` | `METHOD action [param, ...]` — the real endpoints |
| `links.txt` | same-origin pages reached |
| `api_inline.txt` | URL-ish strings from inline scripts/handlers |

## capture_runtime

| file | content |
| --- | --- |
| `runtime_api.json` | shell state, unique `METHOD /path` calls, per-route attribution, detail log, observed headers, WS endpoints/frames |
| `api_merged.txt` | runtime paths ∪ `api_static.txt` (when present) |

## build_perm_tree

| file | content |
| --- | --- |
| `route_map.json` | `KEY:{name,link}` aliases |
| `userRouteAuth.json` | parsed `code → {url, control[]}` |
| `permissions_tree.json` | inferred hierarchy |
| `perm_codes_all.txt` | every code (tree + control) |
| `permissions_all_stub.json` | permissive menu tree stub |
| `role_permissions_stub.json` | flat permission-list stub |

## merge_params

| file | content |
| --- | --- |
| `params_merged.json` | per-endpoint fields with `in` (body/query), sample counts, confidence |
| `params_merged.txt` | one line per endpoint, human-readable |

## Confidence semantics

| confidence | meaning |
| --- | --- |
| `high` | field present in ≥2 samples of an endpoint with ≥2 samples |
| `medium` | field seen once |
| `pending` | recorded statically but never observed live |
