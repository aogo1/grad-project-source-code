import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from xgboost import XGBClassifier

np.random.seed(42)
N   = 2000
OUT = '/home/aogo/soc/mlapi/'

# MITRE tactic -> baseline malice probability
TACTIC_RISK = {
    'Execution':           0.85,
    'Persistence':         0.80,
    'PrivilegeEscalation': 0.82,
    'DefenseEvasion':      0.78,
    'CredentialAccess':    0.90,
    'Discovery':           0.45,
    'LateralMovement':     0.88,
    'Collection':          0.70,
    'Exfiltration':        0.92,
    'CommandAndControl':   0.88,
    'Impact':              0.95,
    'none':                0.10,
}

TACTICS = list(TACTIC_RISK.keys())

SUSPICIOUS_PORTS = {4444, 1337, 31337, 8080, 9001, 6666}

# ── Generate synthetic samples ──────────────────────────────────────────────
rows = []
for _ in range(N):
    tactic = np.random.choice(
        TACTICS,
        p=[0.12, 0.08, 0.08, 0.10, 0.10, 0.10,
           0.06, 0.06, 0.06, 0.08, 0.06, 0.10]
    )
    base_risk    = TACTIC_RISK[tactic]
    is_malicious = int(np.random.random() < base_risk)

    if is_malicious:
        rule_level        = np.random.randint(8, 16)          # overlap at 8-9
        cmdline_length    = int(np.random.normal(250, 80))
        cmdline_entropy   = np.random.uniform(2.8, 5.5)       # overlap in lower range
        is_encoded_ps     = int(np.random.random() < 0.55)    # not always present
        is_hidden_win     = int(np.random.random() < 0.45)
        dest_port         = int(np.random.choice(
            list(SUSPICIOUS_PORTS) + [443, 80, 0, 8080, 3389],
            p=[.07, .07, .07, .07, .07, .07, .20, .15, .08, .08, .07]
        ))
        targets_sensitive = int(np.random.random() < 0.35)
        image_in_temp     = int(np.random.random() < 0.28)
    else:
        rule_level        = np.random.randint(1, 11)          # overlap at 8-10
        cmdline_length    = int(np.random.normal(80, 50))
        cmdline_entropy   = np.random.uniform(1.0, 3.8)       # overlap in upper range
        is_encoded_ps     = int(np.random.random() < 0.05)    # rare but possible
        is_hidden_win     = int(np.random.random() < 0.03)
        dest_port         = int(np.random.choice(
            [80, 443, 53, 8080, 3389, 0, 4444],
            p=[.25, .25, .20, .10, .08, .07, .05]             # 4444 occasionally benign
        ))
        targets_sensitive = int(np.random.random() < 0.02)
        image_in_temp     = int(np.random.random() < 0.05)

    # Gaussian noise on continuous features to break perfect separation
    rule_level      = int(np.clip(rule_level + np.random.randint(-1, 2), 1, 15))
    cmdline_length  = max(0, cmdline_length + np.random.randint(-20, 21))
    cmdline_entropy = float(np.clip(cmdline_entropy + np.random.normal(0, 0.2), 0, 6))

    rows.append({
        'rule_level':           rule_level,
        'cmdline_length':       cmdline_length,
        'cmdline_entropy':      cmdline_entropy,
        'is_encoded_ps':        is_encoded_ps,
        'is_hidden_window':     is_hidden_win,
        'dest_port_suspicious': int(dest_port in SUSPICIOUS_PORTS),
        'targets_sensitive':    targets_sensitive,
        'image_in_temp':        image_in_temp,
        'hour_of_day':          np.random.randint(0, 24),
        **{f'tactic_{t}': int(t == tactic) for t in TACTICS},
        'label': is_malicious,
    })

# ── Build DataFrame ──────────────────────────────────────────────────────────
df           = pd.DataFrame(rows)
X            = df.drop('label', axis=1)
y            = df['label']
feature_names = list(X.columns)

print(f"Dataset: {len(df)} samples  |  Malicious: {y.sum()}  |  Benign: {(y==0).sum()}")

# ── Train / test split ───────────────────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)

scaler      = StandardScaler()
X_train_s   = scaler.fit_transform(X_train)
X_test_s    = scaler.transform(X_test)

# ── Train XGBoost ────────────────────────────────────────────────────────────
model = XGBClassifier(
    n_estimators=200,
    max_depth=5,
    learning_rate=0.1,
    eval_metric='logloss',
    random_state=42,
)
model.fit(X_train_s, y_train)

# ── Evaluation ───────────────────────────────────────────────────────────────
y_pred  = model.predict(X_test_s)
y_proba = model.predict_proba(X_test_s)[:, 1]

print("\n=== Classification Report ===")
print(classification_report(y_test, y_pred))

print("=== Confusion Matrix ===")
cm = confusion_matrix(y_test, y_pred)
print(f"  TN={cm[0,0]}  FP={cm[0,1]}")
print(f"  FN={cm[1,0]}  TP={cm[1,1]}")

print(f"\n=== ROC AUC: {roc_auc_score(y_test, y_proba):.4f} ===")

# ── Cross-validation (thesis metric) ────────────────────────────────────────
cv_scores = cross_val_score(
    XGBClassifier(n_estimators=200, max_depth=5, learning_rate=0.1,
                  eval_metric='logloss', random_state=42),
    scaler.transform(X), y, cv=5, scoring='roc_auc'
)
print(f"=== 5-Fold CV AUC: {cv_scores.mean():.4f} ± {cv_scores.std():.4f} ===")

# ── Feature importance ───────────────────────────────────────────────────────
print("\n=== Top 10 Features by Importance ===")
importances = pd.Series(model.feature_importances_, index=feature_names)
print(importances.sort_values(ascending=False).head(10).to_string())

# ── Save models ──────────────────────────────────────────────────────────────
joblib.dump(model,         OUT + 'sentinel_xgb.pkl')
joblib.dump(scaler,        OUT + 'sentinel_scaler.pkl')
joblib.dump(feature_names, OUT + 'sentinel_features.pkl')

print(f"\n✓ Models saved to {OUT}")
