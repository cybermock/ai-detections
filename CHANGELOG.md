# Changelog

All notable changes to the Splunk ES AI RBA Starter Pack are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-02-13

### Added
- 20+ new detections across Shadow AI, Adversarial AI, and UEBA categories
- Consolidated web access detection (AI-028) replacing AI-001/002/003
- 3 new aggregate risk correlation rules (AI-RISK-003/004/005)
- UEBA behavioral baseline detections (AI-040 to AI-044)
- 4 new CSV lookups for expanded threat coverage
- Python test suite with 5 test modules
- CI/CD pipelines (GitHub Actions)
- 4 Splunk dashboards for health monitoring and analytics
- 23+ analyst runbooks
- Architecture documentation with Mermaid diagrams
- Tuning guide with per-threshold calibration
- Contributing guide for detection engineers
- Build/packaging system for .spl generation
- Health monitoring searches for lookup staleness and data model availability
- Kill chain phase tagging on all detections
- Risk multiplier macro for contextual scoring

### Changed
- Refined MITRE ATT&CK sub-technique mappings
- Enhanced ai_provider_domains.csv with threat intelligence columns
- Updated app.conf for Splunkbase readiness
- Improved risk scoring with contextual multipliers

### Deprecated
- AI-001, AI-002, AI-003 (consolidated into AI-028)

## [0.1.0] - Initial Release

### Added
- 21 individual AI usage detections
- 2 aggregate risk threshold searches
- 5 CSV lookup files
- 4 reusable macros
- README documentation
