# Fabric notebook source

# METADATA ********************

# META {
# META   "kernel_info": {
# META     "name": "jupyter",
# META     "jupyter_kernel_name": "python3.11"
# META   },
# META   "dependencies": {}
# META }

# MARKDOWN ********************

# # 01. Basic Data Quality Notebook (Core)
# 
# Pandas-only data quality checks (no Spark). Provides:
# - Column profiling (completeness, distinctness, min/max, type inference).
# - Row-level rules (not_null, range, regex, allowed_values).
# - Dataset-level rules (row_count_min, freshness).
# - Orchestrator `run_basic_dq(df, config, dataset_name, run_id)` returning a single pandas DataFrame with all rule outcomes.
# 
# ---
# 
# ## Quick start
# 
# ```python
# results = run_basic_dq(df, config=config, dataset_name="demo.customers")
# # Failures only:
# failures = results[results["passed"] == False]
# ```
# 
# Results columns:
# - dataset, run_id, run_ts
# - rule_id, rule_type ("profile" | "row_check" | "dataset_check"), target
# - severity ("error" | "warn" | "info"), passed (bool)
# - evaluated_count, failed_count, pass_rate
# - failed_examples (sample values), details (dict with metrics/params)
# 
# ---
# 
# ## Config schema (Python dict)
# 
# Top-level keys:
# - row_validations: list of row rules (applied to individual columns/rows).
# - dataset_checks: list of dataset rules.
# 
# Row rule types:
# - not_null
#   - keys: type="not_null", column, id (opt), severity (default "error")
# - range
#   - keys: type="range", column, min (opt), max (opt), min_inclusive (default True), max_inclusive (default True), id (opt), severity (default "error")
# - regex
#   - keys: type="regex", column, pattern (Python regex), case_insensitive (default False), id (opt), severity (default "warn")
# - allowed_values
#   - keys: type="allowed_values", column, allowed (list), case_sensitive (default True), id (opt), severity (default "error")
# 
# Dataset rule types:
# - row_count_min
#   - keys: type="row_count_min", min (int), id (opt), severity (default "error")
# - freshness
#   - keys: type="freshness", column (timestamp-like), max_lag_minutes (int, default 1440), now (datetime override, optional), id (opt), severity (default "warn")
# 
# Example:
# ```python
# config = {
#   "row_validations": [
#     {"id": "not_null_id", "type": "not_null", "column": "id"},
#     {"id": "range_age", "type": "range", "column": "age", "min": 0, "max": 120, "severity": "warn"},
#     {"id": "regex_email", "type": "regex", "column": "email",
#      "pattern": r"^[^\s@]+@[^\s@]+\.[^\s@]+$", "case_insensitive": True, "severity": "warn"},
#     {"id": "allowed_status", "type": "allowed_values", "column": "status",
#      "allowed": ["active", "inactive"], "case_sensitive": False}
#   ],
#   "dataset_checks": [
#     {"id": "min_rows", "type": "row_count_min", "min": 3},
#     {"id": "freshness_updated_at", "type": "freshness", "column": "updated_at", "max_lag_minutes": 60*24}
#   ]
# }
# ```
# 
# ---
# 
# ## Orchestrator
# 
# - run_basic_dq(df, config=None, dataset_name="dataset", run_id=None) -> pd.DataFrame
#   - Runs profiling, then row rules, then dataset rules.
#   - Adds dataset/run metadata, sorts results for readability.
#   - If a rule type is unknown, records an informational row with a warning in details.
# 
# ---
# 
# ## Column profiling helper
# 
# - infer_col_type(s: pd.Series) -> str
#   - Returns one of: "boolean" | "integer" | "float" | "numeric" | "datetime" | "categorical" | "text" | raw dtype.
#   - Uses pandas dtypes; falls back to best-effort to_datetime/to_numeric.
# 
# - _profile_columns(df: pd.DataFrame) -> pd.DataFrame
#   - For each column, computes:
#     - rows, non_null, nulls, completeness
#     - distinct, distinctness
#     - dtype, inferred_type
#     - numeric: min, max, mean, std (if applicable)
#     - datetime: min, max (ISO)
#   - Emits one "profile" row per column (always passed=True) with metrics in details.
# 
# ---
# 
# ## Standard result row builder
# 
# - _build_row(rule_id, rule_type, target, severity, evaluated_count, failed_count, details, failed_examples=None) -> dict
#   - Normalizes all rule outputs into a consistent record.
#   - pass_rate = (evaluated_count - failed_count) / evaluated_count (defaults to 1.0 if no evaluations).
# 
# ---
# 
# ## Row-level validators
# 
# - check_not_null(df, rule) -> dict
#   - Fails where df[column] is null.
#   - details: {"null_count": N}
#   - evaluated_count = number of rows (nulls included in evaluation).
# 
# - check_range(df, rule) -> dict
#   - Coerces to numeric; non-numeric become NaN and are excluded from evaluation.
#   - Fails if value < min (or <= when exclusive) or > max (or >= when exclusive).
#   - details: {"min", "max", "min_inclusive", "max_inclusive}
# 
# - check_regex(df, rule) -> dict
#   - Casts to string; evaluates only non-null values.
#   - Fails if string does not match compiled regex (case-insensitive optional).
#   - details: {"pattern", "case_insensitive"}
# 
# - check_allowed_values(df, rule) -> dict
#   - If case_sensitive=False, compares lowercase strings against lowered allowed values.
#   - details: {"allowed": [...], "case_sensitive": bool}
# 
# Handlers dictionary (used by the orchestrator):
# - ROW_CHECK_HANDLERS = {"not_null": check_not_null, "range": check_range, "regex": check_regex, "allowed_values": check_allowed_values}
# 
# ---
# 
# ## Dataset-level checks
# 
# - check_row_count_min(df, rule) -> dict
#   - Fails when len(df) < min.
#   - evaluated_count = 1 (single dataset-level assertion).
#   - details: {"rows": n, "min": min_rows}
# 
# - check_freshness(df, rule) -> dict
#   - Parses the given column to UTC datetimes; uses the latest valid timestamp.
#   - Fails if (now - latest) in minutes > max_lag_minutes.
#   - If column has no valid timestamps, marks as failed with reason.
#   - details: {"latest", "now", "lag_minutes", "max_lag_minutes}
#   - Tip: Provide timezone-aware datetimes or strings parseable by pandas.
# 
# Handlers dictionary:
# - DATASET_CHECK_HANDLERS = {"row_count_min": check_row_count_min, "freshness": check_freshness}
# 
# ---
# 
# ## Usage tips
# 
# - View failures:
#   ```python
#   results[results["passed"] == False]
#   ```
# - Expand details for a specific rule:
#   ```python
#   results.loc[results["rule_id"] == "range:age", "details"].iloc[0]
#   ```
# - Convert details dicts into columns:
#   ```python
#   details_expanded = pd.json_normalize(results["details"])
#   results_with_details = pd.concat([results.drop(columns=["details"]), details_expanded], axis=1)
#   ```
# - Regex patterns are Python regexes. Example email pattern used is simplistic; adjust to your needs.
# - Range checks ignore non-numeric values (treated as NaN) in evaluation counts.
# - Severity is metadata for downstream policy; it does not influence pass/fail computation.
# 
# ---


# CELL ********************

import pandas as pd
import numpy as np
import re
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

pd.set_option("display.max_colwidth", 200)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def infer_col_type(s: pd.Series) -> str:
    from pandas.api.types import (
        is_integer_dtype, is_float_dtype, is_numeric_dtype,
        is_bool_dtype, is_datetime64_any_dtype, is_string_dtype,
        is_categorical_dtype
    )
    if is_bool_dtype(s):
        return "boolean"
    if is_integer_dtype(s):
        return "integer"
    if is_float_dtype(s):
        return "float"
    if is_numeric_dtype(s):
        return "numeric"
    if is_datetime64_any_dtype(s):
        return "datetime"
    if is_categorical_dtype(s):
        return "categorical"
    if is_string_dtype(s):
        return "text"
    # Best-effort inference
    s_dt = pd.to_datetime(s, errors="coerce")
    if s_dt.notna().any():
        return "datetime"
    s_num = pd.to_numeric(s, errors="coerce")
    if s_num.notna().any():
        return "numeric"
    return str(s.dtype)


def _profile_columns(df: pd.DataFrame) -> pd.DataFrame:
    rows: List[Dict[str, Any]] = []
    n = len(df)
    for col in df.columns:
        s = df[col]
        inferred = infer_col_type(s)
        non_null = int(s.notna().sum())
        nulls = int(n - non_null)
        completeness = float(non_null / n) if n > 0 else None
        distinct = int(s.nunique(dropna=True))
        distinctness = float(distinct / non_null) if non_null > 0 else None

        metrics: Dict[str, Any] = {
            "rows": n,
            "non_null": non_null,
            "nulls": nulls,
            "completeness": completeness,
            "distinct": distinct,
            "distinctness": distinctness,
            "dtype": str(s.dtype),
            "inferred_type": inferred,
        }

        if inferred in ("integer", "float", "numeric"):
            s_num = pd.to_numeric(s, errors="coerce")
            if s_num.notna().any():
                metrics.update({
                    "min": float(np.nanmin(s_num)),
                    "max": float(np.nanmax(s_num)),
                    "mean": float(np.nanmean(s_num)),
                    "std": float(np.nanstd(s_num, ddof=1)) if s_num.notna().sum() > 1 else None,
                })
            else:
                metrics.update({"min": None, "max": None, "mean": None, "std": None})
        elif inferred == "datetime":
            s_dt = pd.to_datetime(s, errors="coerce", utc=True)
            if s_dt.notna().any():
                metrics.update({
                    "min": s_dt.min().isoformat(),
                    "max": s_dt.max().isoformat(),
                })
            else:
                metrics.update({"min": None, "max": None})

        rows.append({
            "rule_id": f"profile:{col}",
            "rule_type": "profile",
            "target": col,
            "severity": "info",
            "passed": True,
            "evaluated_count": int(non_null),
            "failed_count": 0,
            "pass_rate": 1.0,
            "failed_examples": [],
            "details": metrics,
        })
    return pd.DataFrame(rows)


def _build_row(
    rule_id: str,
    rule_type: str,
    target: str,
    severity: str,
    evaluated_count: int,
    failed_count: int,
    details: Dict[str, Any],
    failed_examples: Optional[List[Any]] = None
) -> Dict[str, Any]:
    if evaluated_count and evaluated_count > 0:
        pass_rate = float((evaluated_count - failed_count) / evaluated_count)
    else:
        pass_rate = 1.0
    return {
        "rule_id": rule_id,
        "rule_type": rule_type,
        "target": target,
        "severity": severity,
        "passed": failed_count == 0,
        "evaluated_count": int(evaluated_count),
        "failed_count": int(failed_count),
        "pass_rate": pass_rate,
        "failed_examples": failed_examples or [],
        "details": details,
    }


# Row-level validators
def check_not_null(df: pd.DataFrame, rule: Dict[str, Any]) -> Dict[str, Any]:
    col = rule["column"]
    severity = rule.get("severity", "error")
    mask_fail = df[col].isna()
    failed_count = int(mask_fail.sum())
    evaluated_count = len(df)
    examples = df.loc[mask_fail, col].head(10).tolist()
    details = {"null_count": failed_count}
    return _build_row(
        rule.get("id", f"not_null:{col}"),
        "row_check",
        col,
        severity,
        evaluated_count,
        failed_count,
        details,
        examples
    )


def check_range(df: pd.DataFrame, rule: Dict[str, Any]) -> Dict[str, Any]:
    col = rule["column"]
    min_v = rule.get("min", None)
    max_v = rule.get("max", None)
    min_incl = rule.get("min_inclusive", True)
    max_incl = rule.get("max_inclusive", True)
    severity = rule.get("severity", "error")

    s_num = pd.to_numeric(df[col], errors="coerce")
    mask_eval = s_num.notna()
    fails = pd.Series(False, index=df.index)
    if min_v is not None:
        fails = fails | (s_num < min_v if min_incl else s_num <= min_v)
    if max_v is not None:
        fails = fails | (s_num > max_v if max_incl else s_num >= max_v)

    mask_fail = mask_eval & fails
    failed_count = int(mask_fail.sum())
    evaluated_count = int(mask_eval.sum())
    examples = df.loc[mask_fail, col].head(10).tolist()
    details = {
        "min": min_v, "max": max_v,
        "min_inclusive": min_incl, "max_inclusive": max_incl,
    }
    return _build_row(
        rule.get("id", f"range:{col}"),
        "row_check",
        col,
        severity,
        evaluated_count,
        failed_count,
        details,
        examples
    )


def check_regex(df: pd.DataFrame, rule: Dict[str, Any]) -> Dict[str, Any]:
    col = rule["column"]
    pattern = rule["pattern"]
    case_insensitive = bool(rule.get("case_insensitive", False))
    severity = rule.get("severity", "warn")

    flags = re.IGNORECASE if case_insensitive else 0
    rx = re.compile(pattern, flags)
    s = df[col].astype("string")
    mask_eval = s.notna()
    mask_fail = mask_eval & ~s.str.match(rx)

    failed_count = int(mask_fail.sum())
    evaluated_count = int(mask_eval.sum())
    examples = df.loc[mask_fail, col].head(10).tolist()
    details = {"pattern": pattern, "case_insensitive": case_insensitive}
    return _build_row(
        rule.get("id", f"regex:{col}"),
        "row_check",
        col,
        severity,
        evaluated_count,
        failed_count,
        details,
        examples
    )


def check_allowed_values(df: pd.DataFrame, rule: Dict[str, Any]) -> Dict[str, Any]:
    col = rule["column"]
    allowed = rule.get("allowed", [])
    case_sensitive = bool(rule.get("case_sensitive", True))
    severity = rule.get("severity", "error")

    s = df[col]
    mask_eval = s.notna()
    if case_sensitive:
        allowed_set = set(allowed)
        mask_fail = mask_eval & ~s.isin(allowed_set)
    else:
        allowed_lower = {str(x).lower() for x in allowed}
        s_cmp = s.astype("string").str.lower()
        mask_fail = mask_eval & ~s_cmp.isin(allowed_lower)

    failed_count = int(mask_fail.sum())
    evaluated_count = int(mask_eval.sum())
    examples = df.loc[mask_fail, col].head(10).tolist()
    details = {"allowed": list(allowed), "case_sensitive": case_sensitive}
    return _build_row(
        rule.get("id", f"allowed_values:{col}"),
        "row_check",
        col,
        severity,
        evaluated_count,
        failed_count,
        details,
        examples
    )


# Dataset-level checks
def check_row_count_min(df: pd.DataFrame, rule: Dict[str, Any]) -> Dict[str, Any]:
    min_rows = int(rule.get("min", 0))
    severity = rule.get("severity", "error")
    n = len(df)
    failed = int(n < min_rows)
    details = {"rows": n, "min": min_rows}
    return _build_row(
        rule.get("id", "row_count_min"),
        "dataset_check",
        "dataset",
        severity,
        evaluated_count=1,
        failed_count=failed,
        details=details
    )


def check_freshness(df: pd.DataFrame, rule: Dict[str, Any]) -> Dict[str, Any]:
    col = rule["column"]
    max_lag_minutes = int(rule.get("max_lag_minutes", 1440))
    severity = rule.get("severity", "warn")
    now: datetime = rule.get("now") or _utc_now()

    s_dt = pd.to_datetime(df[col], errors="coerce", utc=True)
    if not s_dt.notna().any():
        details = {"reason": "no_valid_timestamps", "max_lag_minutes": max_lag_minutes}
        return _build_row(
            rule.get("id", f"freshness:{col}"),
            "dataset_check",
            col,
            severity,
            evaluated_count=0,
            failed_count=1,
            details=details
        )

    latest = s_dt.max()
    lag = (now - latest).total_seconds() / 60.0
    failed = int(lag > max_lag_minutes)
    details = {
        "latest": latest.isoformat(),
        "now": now.isoformat(),
        "lag_minutes": lag,
        "max_lag_minutes": max_lag_minutes,
    }
    return _build_row(
        rule.get("id", f"freshness:{col}"),
        "dataset_check",
        col,
        severity,
        evaluated_count=1,
        failed_count=failed,
        details=details
    )


ROW_CHECK_HANDLERS = {
    "not_null": check_not_null,
    "range": check_range,
    "regex": check_regex,
    "allowed_values": check_allowed_values,
}

DATASET_CHECK_HANDLERS = {
    "row_count_min": check_row_count_min,
    "freshness": check_freshness,
}


def run_basic_dq(
    df: pd.DataFrame,
    config: Optional[Dict[str, Any]] = None,
    dataset_name: str = "dataset",
    run_id: Optional[str] = None,
) -> pd.DataFrame:
    """
    Execute basic data quality: column profiling, row validators, and dataset checks.
    Returns a single pandas DataFrame summarizing all rules.
    """
    config = config or {}
    run_ts = _utc_now()
    run_id = run_id or run_ts.isoformat()

    results: List[Dict[str, Any]] = []

    # 1) Column profiling
    prof_df = _profile_columns(df)
    results.extend(prof_df.to_dict(orient="records"))

    # 2) Row-level validators
    for rule in config.get("row_validations", []):
        rtype = rule.get("type")
        handler = ROW_CHECK_HANDLERS.get(rtype)
        if handler is None:
            results.append(_build_row(
                rule.get("id", f"unknown_row_rule:{rtype}"),
                "row_check",
                rule.get("column", ""),
                rule.get("severity", "info"),
                evaluated_count=0,
                failed_count=0,
                details={"warning": f"unknown row rule type '{rtype}'"}
            ))
            continue
        results.append(handler(df, rule))

    # 3) Dataset-level checks
    for rule in config.get("dataset_checks", []):
        rtype = rule.get("type")
        handler = DATASET_CHECK_HANDLERS.get(rtype)
        if handler is None:
            results.append(_build_row(
                rule.get("id", f"unknown_dataset_rule:{rtype}"),
                "dataset_check",
                "dataset",
                rule.get("severity", "info"),
                evaluated_count=0,
                failed_count=0,
                details={"warning": f"unknown dataset rule type '{rtype}'"}
            ))
            continue
        results.append(handler(df, rule))

    # 4) Assemble final results DataFrame (+ metadata)
    out = pd.DataFrame(results)
    out.insert(0, "dataset", dataset_name)
    out.insert(1, "run_id", run_id)
    out.insert(2, "run_ts", run_ts)
    type_order = {"dataset_check": 0, "row_check": 1, "profile": 2}
    out["_order"] = out["rule_type"].map(type_order).fillna(99)
    out.sort_values(["_order", "severity", "rule_id"], inplace=True)
    out.drop(columns=["_order"], inplace=True)
    return out

# METADATA ********************

# META {
# META   "language": "python",
# META   "language_group": "jupyter_python"
# META }
