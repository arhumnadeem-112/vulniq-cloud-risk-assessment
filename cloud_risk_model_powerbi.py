# CLOUD RISK ASSESSMENT MODEL — POWER BI EDITION (Table-Passing Version) - 12:48am
# =============================================================================
#
# HOW THIS WORKS:
# ─────────────────────────────────────────────────────────────────────────────
# This script does NOT connect to Azure MySQL.
# Power BI passes its already-loaded tables directly into this script
# as pandas DataFrames — no duplicate connections, no credentials here.
#
# The tables Power BI passes in (named exactly as your Power BI table names):
#   vulns_raw   ← your "Vulnerabilities" table
#   repo        ← your "RepoHealth" table
#   incidents   ← your "ServiceIncidents" table
#
# This script is NOT pasted into "Get data → Python script".
# It is pasted into a BLANK QUERY using Advanced Editor.
# See the setup guide for the exact M formula wrapper.

import warnings
warnings.filterwarnings("ignore")

import numpy as np
import pandas as pd
import datetime

from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import (
    train_test_split, cross_val_score, StratifiedKFold
)
from sklearn.pipeline import Pipeline
import xgboost as xgb

# =============================================================================
# SECTION 0 — CONFIGURATION
# Power BI injects the parameter values as Python variables automatically.
# To test this script standalone (outside Power BI), uncomment the block below:
# =============================================================================

RISK_WEIGHTS = {
    "vulnerability_severity": float(W_VulnSeverity),
    "vulnerability_volume":   float(W_VulnVolume),
    "active_exploitation":    float(W_ActiveExploit),
    "incident_history":       float(W_IncidentHistory),
    "repository_health":      float(W_RepoHealth),
    "cwe_attack_types":       float(W_CWE),
}

# Auto-normalise weights to 1.0 if they don't sum exactly
_total_w = sum(RISK_WEIGHTS.values())
if abs(_total_w - 1.0) > 0.001:
    RISK_WEIGHTS = {k: v / _total_w for k, v in RISK_WEIGHTS.items()}

RISK_THRESHOLDS = {
    "cvss_min":     float(T_CVSSMin),
    "kev_min":      int(T_KEVMin),
    "epss_min":     float(T_EPSSMin),
    "incident_min": int(T_IncidentMin),
}

RISK_BANDS = {
    "high_threshold":   0.70,
    "medium_threshold": 0.40,
}

# =============================================================================
# SECTION 1 — DATA COMES FROM POWER BI TABLES (not Azure MySQL)
# =============================================================================
# Power BI passes these three DataFrames in via the M formula wrapper:
#   vulns_raw   — your Vulnerabilities table
#   repo        — your RepoHealth table
#   incidents   — your ServiceIncidents table
#
# Column names match exactly what is in your loaded CSVs.
# Type coercion below is Power BI-only — keeps string-loaded columns usable
# without changing any downstream aggregation logic from the notebook.
# =============================================================================

# --- Column rename (matches notebook Section 2a) ----------------------------
vulns_raw.columns = [c if c != "id" else "service_id" for c in vulns_raw.columns]
repo.columns      = [c if c != "id" else "service_id" for c in repo.columns]
incidents.columns = [c if c != "id" else "service_id" for c in incidents.columns]

# --- Clean up column types (Power BI may load numerics as strings) -----------
vulns_raw["cvss_v3_score"] = pd.to_numeric(vulns_raw["cvss_v3_score"], errors="coerce")
vulns_raw["epss_score"]    = pd.to_numeric(vulns_raw["epss_score"],    errors="coerce")
vulns_raw["is_kev"]        = pd.to_numeric(vulns_raw["is_kev"],        errors="coerce").fillna(0).astype(int)

repo["commit_count_90d"]         = pd.to_numeric(repo["commit_count_90d"],         errors="coerce").fillna(0)
repo["contributor_count_90d"]    = pd.to_numeric(repo["contributor_count_90d"],    errors="coerce").fillna(0)
repo["open_issues"]              = pd.to_numeric(repo["open_issues"],              errors="coerce").fillna(0)
repo["security_issues_open"]     = pd.to_numeric(repo["security_issues_open"],     errors="coerce").fillna(0)
repo["mean_days_close_security"] = pd.to_numeric(repo["mean_days_close_security"], errors="coerce").fillna(0)
repo["days_since_last_release"]  = pd.to_numeric(repo["days_since_last_release"],  errors="coerce").fillna(0)
# has_security_policy arrives as "True"/"False" strings from Power BI — map explicitly
_hsp = repo["has_security_policy"].astype(str).str.strip().str.lower()
repo["has_security_policy"] = _hsp.map(
    {"true": 1, "false": 0, "1": 1, "0": 0, "1.0": 1, "0.0": 0}
).fillna(pd.to_numeric(repo["has_security_policy"], errors="coerce")).fillna(0).astype(float)

incidents["duration_minutes"] = pd.to_numeric(incidents["duration_minutes"], errors="coerce").fillna(0)

# =============================================================================
# SECTION 2 — FEATURE ENGINEERING (identical logic to notebook)
# =============================================================================

services = (
    vulns_raw[["service_name", "ecosystem"]]
    .drop_duplicates(subset="service_name")
    .reset_index(drop=True)
)
services["vendor"]  = services["service_name"]
services["is_oss"]  = 0
services["is_saas"] = 0

# Aggregating Incidents
sev_map = {"critical": 4, "high": 3, "medium": 2, "low": 1}
incidents["sev_score"] = incidents["severity"].map(sev_map).fillna(0)
incidents["resolved"]  = (incidents["status"] == "resolved").astype(int)

incidents_agg = incidents.groupby("service_name").agg(
    incident_count  = ("incident_id",      "count"),
    avg_severity    = ("sev_score",        "mean"),
    recurrence_rate = ("resolved",         lambda x: (1 - x).mean()),
    total_downtime  = ("duration_minutes", "sum"),
).reset_index()

# Aggregating Vulnerabilities
vuln_agg = vulns_raw.groupby("service_name").agg(
    total_vulns   = ("cve_id",        "count"),
    open_vulns    = ("severity",      lambda x: x.isin(["critical", "high"]).sum()),
    mean_cvss     = ("cvss_v3_score", "mean"),
    max_cvss      = ("cvss_v3_score", "max"),
    exploit_count = ("is_kev",        "sum"),
    mean_epss     = ("epss_score",    "mean"),
).reset_index()

# Top 20 CWE one-hot encoding
top_20_cwe  = vulns_raw["cwe_id"].value_counts().head(20).index.tolist()
vulns_cwe   = vulns_raw[vulns_raw["cwe_id"].isin(top_20_cwe)].copy()
cwe_dummies = pd.get_dummies(vulns_cwe[["service_name", "cwe_id"]], columns=["cwe_id"], dtype=int)
cwe_agg     = cwe_dummies.groupby("service_name").sum().reset_index()

# Aggregating Repo Health
repo_agg = repo.groupby("service_name").agg(
    commit_count_90d         = ("commit_count_90d",         "mean"),
    contributor_count_90d    = ("contributor_count_90d",    "mean"),
    open_issues              = ("open_issues",              "mean"),
    security_issues_open     = ("security_issues_open",     "mean"),
    mean_days_close_security = ("mean_days_close_security", "mean"),
    days_since_last_release  = ("days_since_last_release",  "mean"),
    has_security_policy      = ("has_security_policy",      "max"),
).reset_index()

# Merging all tables on service_name
df = services.copy()
df = df.merge(repo_agg,      on="service_name", how="left")
df = df.merge(incidents_agg, on="service_name", how="left")
df = df.merge(vuln_agg,      on="service_name", how="left")
df = df.merge(cwe_agg,       on="service_name", how="left")

# Safe fillna — numeric columns only
numeric_cols = df.select_dtypes(include="number").columns
df[numeric_cols] = df[numeric_cols].fillna(0)

# Ensuring CWE columns are int
cwe_cols_in_df = [c for c in df.columns if c.startswith("cwe_id_")]
df[cwe_cols_in_df] = df[cwe_cols_in_df].astype(int)

# Derived compound features
df["vuln_density"]  = df["open_vulns"]              / (df["total_vulns"] + 1)
df["risk_velocity"] = df["incident_count"]          * df["recurrence_rate"]
df["patch_debt"]    = df["days_since_last_release"] * df["security_issues_open"]
df["exploit_ratio"] = df["exploit_count"]           / (df["total_vulns"] + 1)
df["epss_risk"]     = df["mean_epss"]               * df["total_vulns"]

# Encoding categorical columns
df["ecosystem"] = df["ecosystem"].fillna("unknown")
df["vendor"]    = df["vendor"].fillna("unknown")
le = LabelEncoder()
df["ecosystem_enc"] = le.fit_transform(df["ecosystem"])
df["vendor_enc"]    = le.fit_transform(df["vendor"])
df["is_oss_enc"]    = pd.to_numeric(df["is_oss"],  errors="coerce").fillna(0).astype(int)
df["is_saas_enc"]   = pd.to_numeric(df["is_saas"], errors="coerce").fillna(0).astype(int)

# Configurable threshold-based risk label
df["high_risk"] = (
    (df["mean_cvss"]      >= RISK_THRESHOLDS["cvss_min"])    |
    (df["exploit_count"]  >= RISK_THRESHOLDS["kev_min"])     |
    (df["mean_epss"]      >= RISK_THRESHOLDS["epss_min"])    |
    (df["incident_count"] >= RISK_THRESHOLDS["incident_min"])
).astype(int)

# =============================================================================
# SECTION 3 — FEATURE SELECTION & TRAIN/TEST SPLIT
# =============================================================================
CWE_COLS = [c for c in df.columns if c.startswith("cwe_id_")]

# Removed features to prevent leakage
# high_risk label is defined by: mean_cvss, exploit_count, mean_epss, incident_count
# epss_risk = mean_epss * total_vulns  (leaks mean_epss)
# exploit_ratio = exploit_count / total_vulns  (leaks exploit_count)
# risk_velocity = incident_count * recurrence_rate  (leaks incident_count)
LEAKING_FEATURES = {
    "mean_cvss", "max_cvss",
    "exploit_count",
    "mean_epss",
    "incident_count",
    "epss_risk",
    "exploit_ratio",
    "risk_velocity",
}

FEATURE_COLS = [
    "total_vulns", "open_vulns", "vuln_density",
    "commit_count_90d", "contributor_count_90d", "open_issues",
    "security_issues_open", "mean_days_close_security",
    "days_since_last_release", "has_security_policy", "patch_debt",
    "avg_severity", "recurrence_rate", "total_downtime",
    "vendor_enc", "ecosystem_enc", "is_oss_enc", "is_saas_enc",
] + CWE_COLS

FEATURE_COLS = [f for f in FEATURE_COLS if f in df.columns]

FEATURE_WEIGHT_MAP = {
    # Vulnerability severity — mean_cvss, max_cvss, mean_epss removed (label leakage)
    # Vulnerability volume
    "open_vulns":                 RISK_WEIGHTS["vulnerability_volume"],
    "total_vulns":                RISK_WEIGHTS["vulnerability_volume"],
    "vuln_density":               RISK_WEIGHTS["vulnerability_volume"],

    # Active exploitation — exploit_count, exploit_ratio, epss_risk removed (label leakage)
    # Incident history — incident_count and risk_velocity removed (label leakage)
    "avg_severity":               RISK_WEIGHTS["incident_history"],
    "recurrence_rate":            RISK_WEIGHTS["incident_history"],
    "total_downtime":             RISK_WEIGHTS["incident_history"],

    # Repository health
    "commit_count_90d":           RISK_WEIGHTS["repository_health"],
    "contributor_count_90d":      RISK_WEIGHTS["repository_health"],
    "open_issues":                RISK_WEIGHTS["repository_health"],
    "security_issues_open":       RISK_WEIGHTS["repository_health"],
    "mean_days_close_security":   RISK_WEIGHTS["repository_health"],
    "days_since_last_release":    RISK_WEIGHTS["repository_health"],
    "has_security_policy":        RISK_WEIGHTS["repository_health"],
    "patch_debt":                 RISK_WEIGHTS["repository_health"],

    # Service metadata — neutral weight (average of all categories)
    "vendor_enc":                 sum(RISK_WEIGHTS.values()) / len(RISK_WEIGHTS),
    "ecosystem_enc":              sum(RISK_WEIGHTS.values()) / len(RISK_WEIGHTS),
    "is_oss_enc":                 sum(RISK_WEIGHTS.values()) / len(RISK_WEIGHTS),
    "is_saas_enc":                sum(RISK_WEIGHTS.values()) / len(RISK_WEIGHTS),
}

# Build weight vector — CWE columns use cwe_attack_types weight
feature_weights = np.array([
    FEATURE_WEIGHT_MAP.get(f, RISK_WEIGHTS["cwe_attack_types"])
    for f in FEATURE_COLS
])

# Applying weights to feature matrix
X_raw      = df[FEATURE_COLS]
X_weighted = X_raw * feature_weights
y          = df["high_risk"]

# Train/test split on WEIGHTED features
if len(df) >= 20:
    X_train, X_test, y_train, y_test = train_test_split(
        X_weighted, y, test_size=0.3, random_state=42, stratify=y
    )
else:
    X_train, X_test, y_train, y_test = X_weighted, X_weighted, y, y

# =============================================================================
# SECTION 4 — MODEL DEFINITIONS (identical to notebook)
# =============================================================================
lr = Pipeline([
    ("scaler", StandardScaler()),
    ("clf", LogisticRegression(
        max_iter=1000, class_weight="balanced", C=0.01, random_state=42
    ))
])

rf = RandomForestClassifier(
    n_estimators=100, max_depth=3, max_features="sqrt",
    min_samples_leaf=3, class_weight="balanced", random_state=42, n_jobs=-1
)

xgb_model = xgb.XGBClassifier(
    n_estimators=100, max_depth=2, learning_rate=0.05,
    subsample=0.6, colsample_bytree=0.5,
    reg_alpha=1.0, reg_lambda=2.0, min_child_weight=3,
    scale_pos_weight=(
        (y_train == 0).sum() / (y_train == 1).sum()
        if y_train.sum() > 0 else 1
    ),
    eval_metric="logloss", use_label_encoder=False,
    random_state=42, verbosity=0,
)

nn = Pipeline([
    ("scaler", StandardScaler()),
    ("clf", MLPClassifier(
        hidden_layer_sizes=(32, 16), activation="relu", solver="adam",
        alpha=0.1, max_iter=500, early_stopping=True,
        validation_fraction=0.2, random_state=42
    ))
])

contamination = min(max(float(y.mean()), 0.05), 0.5)
iso_forest = IsolationForest(
    n_estimators=100, contamination=contamination,
    max_samples="auto", random_state=42
)

# =============================================================================
# SECTION 5 — TRAIN ALL MODELS
# =============================================================================
lr.fit(X_train, y_train)
rf.fit(X_train, y_train)
xgb_model.fit(X_train, y_train)
nn.fit(X_train, y_train)
iso_forest.fit(X_train)

# =============================================================================
# SECTION 6 — SCORE ALL SERVICES (identical to notebook Section 7)
# =============================================================================
df["xgb_risk_score"] = xgb_model.predict_proba(X_weighted)[:, 1]
df["lr_risk_score"]  = lr.predict_proba(X_weighted)[:, 1]

iso_full_raw   = iso_forest.decision_function(X_weighted)
iso_full_score = -iso_full_raw
iso_full_score = (iso_full_score - iso_full_score.min()) / (iso_full_score.max() - iso_full_score.min() + 1e-9)
df["anomaly_score"] = iso_full_score
df["anomaly_flag"]  = (iso_full_score >= 0.5).astype(int)

df["risk_level"] = pd.cut(
    df["lr_risk_score"],
    bins=[0, RISK_BANDS["medium_threshold"], RISK_BANDS["high_threshold"], 1.0],
    labels=["Low", "Medium", "High"]
)

# =============================================================================
# SECTION 7 — BUILD dataset (Power BI reads this variable)
# Matches notebook Section 8 export columns + weight config
# =============================================================================
dataset = df[[
    "service_name", "vendor", "ecosystem",
    "open_vulns", "mean_cvss", "mean_epss", "incident_count",
    "exploit_count", "total_vulns", "vuln_density",
    "security_issues_open", "days_since_last_release",
    "lr_risk_score", "anomaly_score", "anomaly_flag", "risk_level",
]].copy()

dataset["last_scored"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

for category, weight in RISK_WEIGHTS.items():
    dataset[f"weight_{category}"] = weight

dataset = dataset.sort_values("lr_risk_score", ascending=False).reset_index(drop=True)

# Power BI reads whatever is in the "dataset" variable as the output table.
