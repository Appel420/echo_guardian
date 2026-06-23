# Production Foundation v0.2

This build starts real production architecture. It is not a demo.

## Live path requirements

- real local sensor adapters when platform integration is added
- real baseline state
- real anomaly events
- real confirmation records
- real audit entries
- real policy enforcement
- real export manifests
- real guarded escalation configuration

## Test harness boundary

Replay streams and simulated inputs may be used only under `/tests` or `/tools`. They must not create production user-facing safety claims.
