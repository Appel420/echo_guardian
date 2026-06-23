# SBOM Generation Plan v0.3

## Objective

Produce a software bill of materials for release review and enterprise readiness.

## MVP Tooling

- Python package inventory from project metadata.
- Optional CycloneDX generation when tooling is installed.
- Output location: `docs/sbom/sbom-v0.3.json`.

## Rule

SBOM generation must not require network access during the core build validation path.
