# Data Quality Backlog (Basic & Premium)

This backlog defines the work for two separate data quality notebooks:
- Basic Data Quality Notebook (free/core) — first to pick up.
- Premium Data Quality Notebook (paid) — adds healthcare semantics, governance, and automation.

Pick order (priority)
1) 01. Basic Data Quality Notebook (Core)
2) 02. Shared Rule Engine & YAML Rule Packs
3) 03. Results Store, Artifacts and Baselines
4) 04. Premium Data Quality Notebook (Healthcare Semantics)
5) 05. Terminology Value Sets (LOINC/SNOMED/ICD-10/RxNorm)
6) 06. UCUM Unit Standardization & Coherence
7) 07. Clinical Plausibility by Demographics
8) 08. Temporal & Referential Consistency
9) 09. Privacy & PHI Leakage Scanner
10) 10. Consent Alignment Validator
11) 11. Drift & Anomaly Detection
12) 12. Scorecards & Readiness Gates
13) 13. Remediation Workflow & Quarantine
14) 14. Telemetry & Observability
15) 15. Packaging, Licensing, and SKU Gating
16) 16. Audit Pack & Evidence Export
17) 17. CI/CD and Test Harness
18) 18. Samples, Docs, and Onboarding

---

## 01. Basic Data Quality Notebook (Core)
- Short description: A lightweight notebook that runs general profiling and simple rules (nulls, ranges, regex, allowed sets, row counts, freshness) and emits HTML/JSON reports.
- Business value: Immediate quality visibility with minimal setup, enabling quick wins and trust for demos and pilots.
- Tasks:
  - Implement column profiling (completeness, distinctness, min/max, type inference).
  - Add row-level validators (null, range, regex, allowed values).
  - Add dataset checks (row count change, freshness/latency).
  - Emit artifacts (results table, HTML summary, JSON detail).
  - Provide sample rule pack and synthetic data.
- Technical steps:
  - Parameterize notebook (source path/table, domain, run_id, date).
  - Build vectorized checks in Spark/Pandas depending on dataset size.
  - Persist results to Delta/Parquet partitioned by run_date.
  - Generate HTML via template; save JSON for machine use.
  - Add config schema and validation with helpful error messages.

## 02. Shared Rule Engine & YAML Rule Packs
- Short description: A reusable engine and schema for defining, validating, and running rules used by both notebooks.
- Business value: Consistency across clients and faster maintenance by centralizing logic.
- Tasks:
  - Define YAML schemas for rules, thresholds, severities, and domains.
  - Build rule registry and execution planner.
  - Add type-aware evaluators (numeric/text/date/categorical).
  - Implement version pinning and validation errors with line numbers.
- Technical steps:
  - Create parser with JSON Schema validation for YAML.
  - Implement reusable UDFs/UDAFs for common checks.
  - Add rule grouping, ordering, and dependency handling.
  - Expose API: load_rules(), run_rules(), write_results().

## 03. Results Store, Artifacts, and Baselines
- Short description: Persist run metadata, rule outcomes, and baselines for comparison over time.
- Business value: Trend visibility, auditability, and faster diagnosis of regressions.
- Tasks:
  - Create tables for runs, rule_results, column_profiles, and baselines.
  - Implement baseline creation and comparison to last N runs.
  - Add artifact manifest for HTML/JSON linkage.
- Technical steps:
  - Define schemas with partitioning (e.g., run_date).
  - Compute summary stats and store divergence deltas.
  - Attach git SHA/workspace/dataset metadata to runs.

## 04. Premium Data Quality Notebook (Healthcare Semantics)
- Short description: A paid notebook that layers clinical semantics, governance, drift detection, and publish gates on top of the core.
- Business value: Reduces clinical risk, improves compliance readiness, and protects revenue by preventing bad data from publishing.
- Tasks:
  - Integrate FHIR profile checks and cardinalities.
  - Add terminology checks, UCUM unit standardization, and plausibility by age/sex.
  - Validate temporal and referential consistency across Patient/Encounter/Observation/Medication/Appointment.
  - Add drift/anomaly detection, scorecards, and tier gates (Bronze/Silver/Gold).
  - Integrate consent alignment and PHI leakage scanning.
- Technical steps:
  - Load premium rule packs and reference tables.
  - Implement gates (warn/soft-fail/hard-stop) and readiness tier computation.
  - Output triage reports and publish decision artifacts.

## 05. Terminology Value Sets (LOINC/SNOMED/ICD-10/RxNorm)
- Short description: Validate codes against versioned value sets; detect deprecated and unknown codes.
- Business value: Reduces claim denials and analytics errors caused by miscoding.
- Tasks:
  - Define reference table schemas (code, system, display, version, status).
  - Implement allowed_set, must_map, and deprecated checks.
  - Add summary metrics per system and domain.
- Technical steps:
  - Build cached joins with broadcast hints for small sets.
  - Support version pinning and drift alerts for new codes.
  - Expose “coverage” metric (# mapped / # total).

## 06. UCUM Unit Standardization & Coherence
- Short description: Normalize units and ensure unit/value coherence per metric.
- Business value: Enables apples-to-apples comparisons across labs and devices.
- Tasks:
  - Implement UCUM conversions and canonical unit suggestions.
  - Add bounds checks after conversion.
  - Record standardized_value and standardized_unit.
- Technical steps:
  - Maintain UCUM mapping tables and conversion functions.
  - Link LOINC groups to expected units.
  - Flag non-convertible or ambiguous unit entries.

## 07. Clinical Plausibility by Demographics
- Short description: Age/sex-specific plausibility ranges for vitals and labs.
- Business value: Improves safety and clinician trust by catching biologically implausible values.
- Tasks:
  - Curate plausibility tables for common metrics.
  - Implement demographic-aware checks with severity tiers.
  - Aggregate violations by metric and cohort.
- Technical steps:
  - Lookup keyed by metric, age band, sex.
  - Vectorized evaluation across observations.
  - Produce per-metric violation distributions.

## 08. Temporal & Referential Consistency
- Short description: Validate timelines and relationships across clinical entities.
- Business value: Prevents broken care journeys and billing errors.
- Tasks:
  - Ensure encounter start < end; observation within encounter.
  - Validate medication administration within order window.
  - Detect orphans for Patient↔Encounter↔Observations/Medications/Appointments.
- Technical steps:
  - Window and interval checks with tolerances.
  - Foreign key existence validators with sampling output.
  - Emit orphan samples for triage.

## 09. Privacy & PHI Leakage Scanner
- Short description: Detect PII/PHI in curated or gold zones, including free text and quasi-identifiers.
- Business value: Lowers compliance and reputational risk.
- Tasks:
  - Regex/dictionary detectors for emails, phones, addresses, names.
  - Column risk scoring and leakage report.
  - Redaction recommendations.
- Technical steps:
  - Field-level scanners with confidence scoring.
  - k-anonymity/rare cohort flags.
  - Severity tagging for policy gates.

## 10. Consent Alignment Validator
- Short description: Enforce that downstream datasets honor consent flags and usage restrictions.
- Business value: Prevents unauthorized data use and supports lawful processing.
- Tasks:
  - Model consent policies (treatment/research/marketing).
  - Validate joins/exports against consent state.
  - Block publish when violations occur (configurable).
- Technical steps:
  - Build consent lookup and propagation rules.
  - Implement policy engine (allow/deny/explain).
  - Persist violation records with impacted row counts.

## 11. Drift & Anomaly Detection
- Short description: Detect schema, value distribution, concept/code, volume, and freshness anomalies.
- Business value: Early warning system to protect SLAs and data reliability.
- Tasks:
  - Persist baselines; compute PSI/JS divergence.
  - Track Unknown/Other/new code rates.
  - Time-series anomalies with seasonality.
- Technical steps:
  - Baseline tables keyed by dataset and column.
  - Divergence calculators per data type.
  - Anomaly detection with week-of-year features.

## 12. Scorecards & Readiness Gates
- Short description: Domain scorecards with weighted KPIs and publish gates for Bronze/Silver/Gold.
- Business value: Increases trust by preventing low-quality datasets from publishing.
- Tasks:
  - Define KPIs per domain (completeness, conformance, drift).
  - Compute readiness tier and publish decision.
  - Provide HTML/PDF scorecard artifact.
- Technical steps:
  - KPI aggregation queries and thresholds config.
  - Tier computation and policy gate output.
  - Artifact rendering and storage.

## 13. Remediation Workflow & Quarantine
- Short description: Triage reports, batch quarantine, and ticketing integrations.
- Business value: Reduces MTTR with clear, actionable handoffs.
- Tasks:
  - Generate triage HTML with samples/root-cause hints.
  - Implement quarantine policy (warn/soft-fail/hard-stop).
  - Webhooks for Teams/Jira/ServiceNow; auto-close on pass.
- Technical steps:
  - Policy-controlled gating step with state store.
  - Quarantined batch metadata + re-run hooks.
  - Idempotent webhook sender and state sync.

## 14. Telemetry & Observability
- Short description: Central metrics store and dashboards for quality posture and SLOs.
- Business value: Continuous visibility for operations and exec reporting.
- Tasks:
  - Metrics schema for runs, rules, drift, latency.
  - Build dashboard (e.g., Power BI).
  - Configure alerts (email/Teams) on thresholds.
- Technical steps:
  - Append-only metrics table + curated views.
  - Scheduled refresh and incremental models.
  - Alert rule bindings to KPI thresholds.

## 15. Packaging, Licensing, and SKU Gating
- Short description: License validation, feature flags, and usage telemetry (opt-in).
- Business value: Enables monetization with controlled feature access.
- Tasks:
  - License validation with grace period.
  - Flag-guard premium validators.
  - PII-safe usage telemetry.
- Technical steps:
  - Signature verification for keys.
  - Feature flag wrapper in validator registry.
  - Telemetry writer with anonymized fields.

## 16. Audit Pack & Evidence Export
- Short description: Export audit-ready evidence bundles with lineage and signatures.
- Business value: Shortens audits and supports compliance reviews.
- Tasks:
  - Bundle rule versions, configs, and results.
  - PDF summary and manifest with hashes.
  - Immutable storage with retention tags.
- Technical steps:
  - Evidence bundler with manifest.json.
  - PDF rendering of scorecards and findings.
  - Write-once storage policy and verification.

## 17. CI/CD and Test Harness
- Short description: Automated builds, tests, and deployments with synthetic datasets.
- Business value: Faster, safer releases with high confidence.
- Tasks:
  - GitHub Actions for lint/test/build/deploy.
  - Synthetic data generators with seeded violations.
  - Unit and scenario tests for validators.
- Technical steps:
  - Workflow YAMLs and environment matrices.
  - Fixture datasets and golden outputs.
  - Coverage reporting and status checks.

## 18. Samples, Docs, and Onboarding
- Short description: Quickstart guides, sample rule packs, and troubleshooting playbooks.
- Business value: Reduces time-to-value and support burden.
- Tasks:
  - Author quickstart and domain samples.
  - Specialty rule packs (concierge, IVF).
  - Common issues and remediation playbooks.
- Technical steps:
  - Markdown docs with copy-paste snippets.
  - Example configs and expected artifacts.
  - Link docs in notebooks