# SentinelAI — Machine Learning Model Documentation

## 1. Initial Approach and Architectural Challenge

The initial ML design trained an XGBoost multiclass classifier on the CICIDS2017 dataset, a widely-used network intrusion detection benchmark containing 80 features extracted by CICFlowMeter from raw packet captures. Features included Flow Duration, Total Forward Packets, Backward Packet Length Mean, Flow Inter-Arrival Time, and TCP flag counts.

However, during integration testing, a fundamental architectural mismatch was identified. The live SentinelAI pipeline does not process raw network flows. Instead, Wazuh SIEM generates alerts from Sysmon endpoint telemetry on Windows hosts. These alerts contain behavioral metadata — rule severity levels, MITRE ATT&CK technique identifiers, process names, command-line arguments, file hashes, and target image paths — none of which correspond to the 80 network flow features the CICIDS2017 model was trained on.

Passing Wazuh alert fields into CICIDS2017 feature slots (e.g., mapping rule_level to Total Fwd Packets and zeroing the remaining 79 features) produced statistically meaningless predictions because the model was operating entirely outside its training distribution. This approach was rejected as scientifically indefensible.

The same limitation applies to alternative network flow datasets including UNSW-NB15, which uses 49 features derived from packet captures (source/destination bytes, TTL values, TCP window sizes, jitter, inter-packet timing) — equally incompatible with endpoint behavioral data.

## 2. Revised Architecture — Hybrid Layered Detection

SentinelAI was restructured around a layered detection philosophy where each component performs the function it is best suited for:

| Layer | Component | Function |
|-------|-----------|----------|
| Rule Engine | Wazuh Custom Rules (100010–100014) | Deterministic detection of known TTPs via signature matching |
| Threat Intelligence | VirusTotal + AbuseIPDB | Reputation scoring of IPs and file hashes |
| Machine Learning | Custom XGBoost Binary Classifier | Behavioral anomaly scoring on endpoint metadata features |
| Orchestration | n8n SOAR + Risk Score Formula | Weighted fusion of all three signals into a composite 0–100 risk score |

This architecture mirrors industry-standard Extended Detection and Response (XDR) platforms, where ML serves as one analytical signal within a broader detection pipeline rather than the sole classifier.

## 3. Knowledge-Guided Synthetic Training Data

Due to the absence of a pre-existing labeled Sysmon endpoint dataset matching the project's detection scope, a synthetic training dataset was generated using domain knowledge derived from the MITRE ATT&CK framework and Wazuh rule severity taxonomy.

### Methodology

A Python script generated 2,000 synthetic alert samples (approximately 1,457 malicious and 543 benign) with the following design principles:

- **MITRE tactic-based labeling**: Each sample was assigned a MITRE ATT&CK tactic with a corresponding baseline malice probability derived from threat intelligence literature. For example, Credential Access tactics received a 90% malice probability, while Discovery tactics received 45%, reflecting the reality that discovery activity is frequently benign.

- **Feature distribution modeling**: Malicious samples were generated with characteristics consistent with known attack patterns — elevated rule severity (8–15), long and high-entropy command lines, encoded PowerShell flags, suspicious destination ports (4444, 1337, 31337), and access to sensitive processes (lsass.exe). Benign samples were generated with normal operational characteristics — low severity (1–10), short command lines, standard ports (80, 443, 53), and no sensitive process access.

- **Controlled noise injection**: Gaussian noise was added to continuous features (rule_level ±1, command-line length ±20, entropy ±0.2) and deliberate overlap was introduced between class distributions (rule_level 8–10 overlap zone, occasional suspicious port in benign traffic, rare encoded PowerShell in legitimate scripts). This prevents trivial decision boundaries and produces realistic classification performance.

### Justification

Knowledge-guided synthetic data generation is an established technique in security ML research, employed when labeled operational data is scarce or when privacy constraints prevent dataset sharing. The approach is analogous to SMOTE (Synthetic Minority Oversampling Technique) in that it generates artificial samples grounded in domain knowledge rather than relying solely on interpolation of existing observations.

The synthetic distributions were validated against observed Wazuh alert patterns from live red team exercises conducted on VM3 (Windows endpoint), confirming that the generated feature ranges align with real operational telemetry.

## 4. Feature Engineering

The model uses 21 features extracted from live Wazuh SIEM alert JSON payloads. All features are derived from fields that actually exist in Sysmon/Wazuh endpoint telemetry:

### Continuous Features

| Feature | Source Field | Description |
|---------|-------------|-------------|
| rule_level | rule.level | Wazuh alert severity (1–15) |
| cmdline_length | data.win.eventdata.commandLine | Character count of the executed command line |
| cmdline_entropy | data.win.eventdata.commandLine | Shannon entropy of the command-line string — higher entropy correlates with obfuscation and encoding |
| hour_of_day | timestamp | Hour extracted from alert timestamp (0–23) — attacks outside business hours may indicate automated tooling |

### Binary Features

| Feature | Source Field | Description |
|---------|-------------|-------------|
| is_encoded_ps | data.win.eventdata.commandLine | Regex match for PowerShell encoding flags (-enc, -encodedcommand, FromBase64String, IEX) |
| is_hidden_window | data.win.eventdata.commandLine | Presence of "-windowstyle hidden" indicating concealed execution |
| dest_port_suspicious | data.win.eventdata.destinationPort | Port belongs to known suspicious set: {4444, 1337, 31337, 8080, 9001, 6666} |
| targets_sensitive | data.win.eventdata.targetImage | Target process is lsass.exe, SAM, or NTDS — credential access indicators |
| image_in_temp | data.win.eventdata.image | Executing binary is located in Temp, AppData, or Downloads — common malware staging directories |

### Categorical Features (One-Hot Encoded)

| Feature | Source Field | Values |
|---------|-------------|--------|
| tactic_Execution | rule.mitre.tactic | 1 if tactic is Execution, 0 otherwise |
| tactic_Persistence | rule.mitre.tactic | 1 if tactic is Persistence, 0 otherwise |
| tactic_PrivilegeEscalation | rule.mitre.tactic | 1 if tactic is Privilege Escalation, 0 otherwise |
| tactic_DefenseEvasion | rule.mitre.tactic | 1 if tactic is Defense Evasion, 0 otherwise |
| tactic_CredentialAccess | rule.mitre.tactic | 1 if tactic is Credential Access, 0 otherwise |
| tactic_Discovery | rule.mitre.tactic | 1 if tactic is Discovery, 0 otherwise |
| tactic_LateralMovement | rule.mitre.tactic | 1 if tactic is Lateral Movement, 0 otherwise |
| tactic_Collection | rule.mitre.tactic | 1 if tactic is Collection, 0 otherwise |
| tactic_Exfiltration | rule.mitre.tactic | 1 if tactic is Exfiltration, 0 otherwise |
| tactic_CommandAndControl | rule.mitre.tactic | 1 if tactic is Command and Control, 0 otherwise |
| tactic_Impact | rule.mitre.tactic | 1 if tactic is Impact, 0 otherwise |
| tactic_none | rule.mitre.tactic | 1 if no MITRE tactic is present, 0 otherwise |

## 5. Model Architecture and Training

| Parameter | Value |
|-----------|-------|
| Algorithm | XGBoost (Extreme Gradient Boosting) Binary Classifier |
| Library | xgboost 2.x with scikit-learn interface |
| Training samples | 2,000 (1,457 malicious / 543 benign) |
| Train/test split | 80/20 stratified |
| Feature scaling | StandardScaler (zero mean, unit variance) |
| Number of estimators | 200 |
| Max depth | 5 |
| Learning rate | 0.1 |
| Evaluation metric | Log loss |

## 6. Evaluation Results

### Classification Report (Hold-Out Test Set, n=400)

| Class | Precision | Recall | F1-Score | Support |
|-------|-----------|--------|----------|---------|
| Benign (0) | 0.96 | 0.98 | 0.97 | 109 |
| Malicious (1) | 0.99 | 0.99 | 0.99 | 291 |
| **Accuracy** | | | **0.98** | **400** |
| Macro Avg | 0.98 | 0.98 | 0.98 | 400 |
| Weighted Avg | 0.99 | 0.98 | 0.99 | 400 |

### Confusion Matrix

|  | Predicted Benign | Predicted Malicious |
|--|------------------|---------------------|
| **Actual Benign** | TN = 107 | FP = 2 |
| **Actual Malicious** | FN = 4 | TP = 287 |

### Additional Metrics

| Metric | Value |
|--------|-------|
| ROC AUC (test set) | 0.9993 |
| 5-Fold Cross-Validation AUC | 0.9994 ± 0.0003 |

### Feature Importance (Top 10)

| Rank | Feature | Importance |
|------|---------|------------|
| 1 | cmdline_length | 0.3953 |
| 2 | rule_level | 0.1407 |
| 3 | cmdline_entropy | 0.1058 |
| 4 | is_hidden_window | 0.0656 |
| 5 | is_encoded_ps | 0.0590 |
| 6 | tactic_Impact | 0.0435 |
| 7 | tactic_Persistence | 0.0337 |
| 8 | tactic_none | 0.0323 |
| 9 | targets_sensitive | 0.0309 |
| 10 | image_in_temp | 0.0222 |

The top three features — command-line length, rule severity level, and command-line entropy — align with established behavioral indicators in endpoint threat detection literature. Long, high-entropy command lines are a hallmark of obfuscated malicious payloads, while rule severity directly reflects the threat classification assigned by the Wazuh analysis engine.

## 7. Integration in the SentinelAI Pipeline

### Flask API Deployment

The trained model is served via a Flask REST API on VM2 (SOAR server) at port 5000 with two endpoints:

- **GET /health** — Returns model status and feature count for monitoring
- **POST /predict** — Accepts a raw Wazuh alert JSON, extracts the 21 features internally, scales them using the trained StandardScaler, and returns a prediction

### API Response Format

```json
{
  "is_malicious": 1,
  "confidence": 0.9995,
  "risk_label": "critical",
  "features_used": {
    "rule_level": 12,
    "cmdline_length": 49,
    "cmdline_entropy": 4.29,
    "is_encoded_ps": 1,
    "is_hidden_window": 1,
    "dest_port_suspicious": 1,
    "targets_sensitive": 0,
    "image_in_temp": 0,
    "hour_of_day": 3,
    "tactic_Execution": 1
  }
}
```

### Risk Score Composition

The ML confidence score is one of four weighted inputs to the composite risk score calculated by the n8n SOAR workflow:

| Source | Weight | Range | Description |
|--------|--------|-------|-------------|
| Wazuh Rule Severity | 40% | 0–100 | rule_level normalized to 0–100 scale |
| ML Model Confidence | 30% | 0–100 | Model probability × 100 |
| AbuseIPDB Score | 20% | 0–100 | IP abuse confidence score |
| VirusTotal Detections | 10% | 0–100 | Malicious detections / total engines × 100 |

**Final Score = (Wazuh × 0.40) + (ML × 0.30) + (AbuseIPDB × 0.20) + (VirusTotal × 0.10)**

### Risk Thresholds

| Score Range | Severity | Automated Action |
|-------------|----------|------------------|
| 70–100 | CRITICAL | Active response — kill process on endpoint |
| 50–69 | HIGH | Create TheHive case for analyst review |
| 30–49 | MEDIUM | Create TheHive case for analyst review |
| 0–29 | LOW | Log only — no case created |

## 8. Limitations and Future Work

### Known Limitations

1. **Synthetic training data**: The model was trained on synthetically generated data rather than real-world operational telemetry. While the distributions were designed to reflect known attack patterns and validated against live red team exercises, real-world accuracy is expected to differ from test set performance. The high evaluation metrics (98% accuracy, 0.999 AUC) reflect the structured nature of the synthetic data and should not be interpreted as guaranteed operational performance.

2. **Class imbalance**: The training set contains approximately 73% malicious and 27% benign samples, reflecting the MITRE tactic probability distribution used for generation. Production environments would exhibit a significantly higher proportion of benign activity.

3. **Feature scope**: The current 21 features represent a subset of possible behavioral indicators. Additional features such as parent-child process relationship anomalies, file signature verification status, network connection frequency baselines, and user behavior profiling could improve detection coverage.

### Future Improvements

1. **Analyst feedback loop**: SentinelAI is designed with a feedback mechanism where analyst true positive / false positive verdicts from TheHive case reviews are stored and used to retrain the model on real operational data. Over successive retraining cycles, the model progressively shifts from synthetic training distribution to the actual operational distribution of the deployed environment.

2. **Incremental learning**: Implementing online learning capabilities would allow the model to adapt to emerging threat patterns without full retraining cycles.

3. **Ensemble expansion**: The current single XGBoost classifier could be supplemented with an autoencoder-based anomaly detector trained on baseline normal behavior, providing complementary detection coverage for previously unseen attack patterns.
