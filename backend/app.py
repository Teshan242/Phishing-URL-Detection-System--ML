# app.py
from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import pandas as pd

# -----------------------------
# 1. Load model
# -----------------------------
model = joblib.load("phishing_model.pkl")  # Make sure path is correct

# -----------------------------
# 2. Load top safe sites
# -----------------------------
# CSV format: index,url
try:
    safe_df = pd.read_csv("../dataset/tranco_top.csv", header=None, names=['index','url'])
    safe_sites = set(safe_df['url'].str.strip().str.lower())
except Exception as e:
    print("Warning: Could not load Tranco top sites:", e)
    safe_sites = set()

# -----------------------------
# 3. Feature extraction
# -----------------------------
from urllib.parse import urlsplit
import tldextract
import numpy as np

def extract_features(url):
    if not isinstance(url, str) or not url.strip():
        return {key: 0 for key in [
            'url_len','dom_len','subdom_cnt','tld_len','is_ip','letter_cnt','digit_cnt',
            'special_cnt','eq_cnt','qm_cnt','amp_cnt','dot_cnt','dash_cnt','under_cnt',
            'letter_ratio','digit_ratio','spec_ratio','is_https','slash_cnt','entropy',
            'path_len','query_len'
        ]}
    
    feat = {}
    feat['url_len'] = len(url)
    ext = tldextract.extract(url)
    feat['dom_len'] = len(ext.domain)
    feat['subdom_cnt'] = len(ext.subdomain)
    feat['tld_len'] = len(ext.suffix)
    feat['is_ip'] = 1 if url.replace('.', '').isdigit() else 0
    feat['letter_cnt'] = sum(c.isalpha() for c in url)
    feat['digit_cnt'] = sum(c.isdigit() for c in url)
    feat['special_cnt'] = sum(not c.isalnum() for c in url)
    feat['eq_cnt'] = url.count('=')
    feat['qm_cnt'] = url.count('?')
    feat['amp_cnt'] = url.count('&')
    feat['dot_cnt'] = url.count('.')
    feat['dash_cnt'] = url.count('-')
    feat['under_cnt'] = url.count('_')
    feat['letter_ratio'] = feat['letter_cnt'] / (feat['url_len'] + 1e-5)
    feat['digit_ratio'] = feat['digit_cnt'] / (feat['url_len'] + 1e-5)
    feat['spec_ratio'] = feat['special_cnt'] / (feat['url_len'] + 1e-5)
    feat['is_https'] = 1 if url.lower().startswith('https') else 0
    feat['slash_cnt'] = url.count('/')

    # Entropy
    counts = [url.count(c)/feat['url_len'] for c in set(url)]
    feat['entropy'] = -sum(p*np.log2(p+1e-5) for p in counts)

    # Safe path & query length
    parsed = urlsplit(url)
    feat['path_len'] = len(parsed.path or '')
    feat['query_len'] = len(parsed.query or '')

    return feat

# -----------------------------
# 4. Flask app
# -----------------------------
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

@app.route("/predict", methods=["POST"])
def predict():
    data = request.json
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error":"No URL provided"}), 400

    # Remove trailing slash for matching
    url_check = url.lower().rstrip('/')

    # Check top safe sites
    for safe in safe_sites:
        if url_check.endswith(safe):
            return jsonify({"prediction": 0, "probability": 0.01, "note": "Top safe site"})

    # Prepend https if missing
    if not url.lower().startswith("http"):
        url = "https://" + url

    # Extract features & predict
    feat = extract_features(url)
    X = pd.DataFrame([feat])
    prob = model.predict_proba(X)[0][1]  # Probability of phishing
    pred = int(prob >= 0.5)

    # Optional: Calibrate probability to avoid 100% always
    temperature = 2.0
    if prob > 0.95:
        prob = 0.95 + (prob - 0.95) * 0.2
    elif prob > 0.8:
        prob = 0.8 + (prob - 0.8) * 0.5

    return jsonify({"prediction": pred, "probability": float(round(prob, 3))})

# -----------------------------
# 5. Run server
# -----------------------------
if __name__ == "__main__":
    app.run(debug=True)
