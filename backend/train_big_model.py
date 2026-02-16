# train_big_model.py
import pandas as pd
import numpy as np
import tldextract
from urllib.parse import urlsplit
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib

# -----------------------------
# 1. Load datasets
# -----------------------------
df_openphish = pd.read_csv("../dataset/openphish.txt", header=None, names=['url'], low_memory=False)
df_phishtank = pd.read_csv("../dataset/online-valid.csv", low_memory=False)
df_kag1 = pd.read_csv("../dataset/phishing_site_urls.csv", low_memory=False)
df_kag2 = pd.read_csv("../dataset/phishing.csv", low_memory=False)

# Load Tranco safe sites
df_tranco = pd.read_csv("../dataset/tranco_top.csv", header=None, names=['rank', 'url'])
df_safe = df_tranco[['url']].copy()
df_safe['label'] = 0  # safe

# Standardize phishing datasets
for df in [df_phishtank, df_kag1, df_kag2]:
    if 'url' not in df.columns:
        df.rename(columns={df.columns[0]: 'url'}, inplace=True)
    df['label'] = 1  # phishing

df_openphish['label'] = 1  # phishing

# Combine all datasets
df_all = pd.concat([df_openphish, df_phishtank, df_kag1, df_kag2, df_safe], ignore_index=True)
df_all = df_all[df_all['url'].notna()]

# 2. Feature extraction
def extract_features(url):
    if not isinstance(url, str) or not url.strip():
        # return zeros for empty/malformed URLs
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

    # Path & query lengths
    parsed = urlsplit(url)
    feat['path_len'] = len(parsed.path or '')
    feat['query_len'] = len(parsed.query or '')

    return feat

# -----------------------------
# 3. Extract features
# -----------------------------
print("Extracting features for all URLs...")
X = pd.DataFrame([extract_features(url) for url in df_all['url']])
y = df_all['label'].values

# -----------------------------
# 4. Train/test split
# -----------------------------
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

# -----------------------------
# 5. Train model
# -----------------------------
model = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
print("Training model...")
model.fit(X_train, y_train)

# -----------------------------
# 6. Evaluate
# -----------------------------
y_pred = model.predict(X_test)
acc = accuracy_score(y_test, y_pred)
print(f"Model accuracy: {acc:.4f}")

# -----------------------------
# 7. Save model
# -----------------------------
joblib.dump(model, "../backend/phishing_model.pkl")
print("✅ Model trained and saved as phishing_model.pkl")
