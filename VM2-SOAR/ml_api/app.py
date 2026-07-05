from flask import Flask, request, jsonify
import joblib
import numpy as np
import re
import math

app  = Flask(__name__)
PATH = '/home/aogo/soc/mlapi/'

model         = joblib.load(PATH + 'sentinel_xgb.pkl')
scaler        = joblib.load(PATH + 'sentinel_scaler.pkl')
feature_names = joblib.load(PATH + 'sentinel_features.pkl')

SUSPICIOUS_PORTS = {4444, 1337, 31337, 8080, 9001, 6666}

TACTICS = [
    'Execution', 'Persistence', 'PrivilegeEscalation', 'DefenseEvasion',
    'CredentialAccess', 'Discovery', 'LateralMovement', 'Collection',
    'Exfiltration', 'CommandAndControl', 'Impact', 'none'
]


def shannon_entropy(s):
    if not s:
        return 0.0
    return -sum((s.count(c) / len(s)) * math.log2(s.count(c) / len(s)) for c in set(s))


def extract_features(alert):
    rule      = alert.get('rule', {})
    eventdata = alert.get('data', {}).get('win', {}).get('eventdata', {})

    cmdline = eventdata.get('commandLine', '') or ''
    target  = eventdata.get('targetImage',  '') or ''
    image   = eventdata.get('image',        '') or ''

    try:
        dest_port = int(eventdata.get('destinationPort', 0) or 0)
    except (ValueError, TypeError):
        dest_port = 0

    try:
        hour = int((alert.get('timestamp', '') or '')[11:13])
    except (ValueError, IndexError):
        hour = 12

    tactics = rule.get('mitre', {}).get('tactic', [])
    # Normalise tactic string — strip spaces so 'Privilege Escalation' -> 'PrivilegeEscalation'
    tactic  = tactics[0].replace(' ', '') if tactics else 'none'
    if tactic not in TACTICS:
        tactic = 'none'

    return {
        'rule_level':           int(rule.get('level', 0)),
        'cmdline_length':       len(cmdline),
        'cmdline_entropy':      shannon_entropy(cmdline),
        'is_encoded_ps':        int(bool(re.search(
                                    r'-enc\b|-encodedcommand|frombase64string|iex\s*\(',
                                    cmdline.lower()))),
        'is_hidden_window':     int('hidden' in cmdline.lower()),
        'dest_port_suspicious': int(dest_port in SUSPICIOUS_PORTS),
        'targets_sensitive':    int(any(x in target.lower()
                                        for x in ['lsass', 'sam', 'ntds', 'system32\\config'])),
        'image_in_temp':        int(any(x in image.lower()
                                        for x in ['\\temp\\', '\\appdata\\', '\\downloads\\'])),
        'hour_of_day':          hour,
        **{f'tactic_{t}': int(t == tactic) for t in TACTICS},
    }


@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status':   'ok',
        'model':    'sentinel_xgb_v2',
        'features': len(feature_names),
    })


@app.route('/predict', methods=['POST'])
def predict():
    try:
        alert = request.get_json(force=True)
        if not alert:
            return jsonify({'error': 'Empty or invalid JSON body'}), 400

        features = extract_features(alert)

        # Build feature vector in exact training order; unseen tactic columns default to 0
        X = np.array([[features.get(f, 0) for f in feature_names]])

        X_scaled = scaler.transform(X)
        proba    = float(model.predict_proba(X_scaled)[0, 1])
        pred     = int(proba >= 0.5)

        if proba >= 0.85:
            risk_label = 'critical'
        elif proba >= 0.60:
            risk_label = 'high'
        elif proba >= 0.35:
            risk_label = 'medium'
        else:
            risk_label = 'low'

        return jsonify({
            'is_malicious':      pred,
            'confidence':        round(proba, 4),
            'risk_label':        risk_label,
            'features_used':     features,
        })

    except Exception as e:
        # Never crash the workflow — return a neutral score on error
        return jsonify({
            'is_malicious': 0,
            'confidence':   0.5,
            'risk_label':   'unknown',
            'error':        str(e),
        }), 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
