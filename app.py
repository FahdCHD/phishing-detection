import streamlit as st
import joblib
import pandas as pd
from urllib.parse import urlparse
import re

# ---- Load model artifacts ----
@st.cache_resource
def load_artifacts():
    try:
        model = joblib.load("phishing_detection_model.pkl")
        scaler = joblib.load("scaler.pkl")
        feature_columns = joblib.load("feature_columns.pkl")
        return model, scaler, feature_columns
    except FileNotFoundError as e:
        st.error(f"❌ Model files not found: {str(e)}\n\nEnsure these files are in the same directory:\n- phishing_detection_model.pkl\n- scaler.pkl\n- feature_columns.pkl")
        return None, None, None

# Feature extraction from URL
def extract_features(url, feature_cols):
    """Extract features from URL, matching the exact feature names from training"""
    
    features = {col: 1 for col in feature_cols}  # Default all to 1 (legitimate)
    
    try:
        # Parse URL carefully
        parsed = urlparse(url)
        domain = parsed.netloc  # e.g., "60.23.238.24:42870" or "google.com"
        path = parsed.path
        scheme = parsed.scheme
        full_url = url
        
        # Extract hostname and port
        if ':' in domain:
            hostname = domain.split(':')[0]
            try:
                port = int(domain.split(':')[1])
            except:
                port = None
        else:
            hostname = domain
            port = None
        
        # 1. having_IP_Address - detect if domain is an IP address
        if 'having_IP_Address' in features:
            ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
            if re.match(ip_pattern, hostname):
                features['having_IP_Address'] = -1  # IP detected = phishing
            else:
                features['having_IP_Address'] = 1
        
        # 2. URL_Length
        if 'URL_Length' in features:
            url_len = len(full_url)
            if url_len < 54:
                features['URL_Length'] = 1
            elif url_len <= 75:
                features['URL_Length'] = 0
            else:
                features['URL_Length'] = -1
        
        # 3. Shortining_Service
        if 'Shortining_Service' in features:
            shorteners = ['bit.ly', 'tinyurl', 'shorty', 'goo.gl', 'ow.ly']
            features['Shortining_Service'] = -1 if any(s in domain for s in shorteners) else 1
        
        # 4. having_At_Symbol
        if 'having_At_Symbol' in features:
            features['having_At_Symbol'] = -1 if '@' in full_url else 1
        
        # 5. double_slash_redirecting
        if 'double_slash_redirecting' in features:
            features['double_slash_redirecting'] = -1 if '//' in full_url[7:] else 1
        
        # 6. Prefix_Suffix
        if 'Prefix_Suffix' in features:
            features['Prefix_Suffix'] = -1 if '-' in hostname else 1
        
        # 7. having_Sub_Domain
        if 'having_Sub_Domain' in features:
            dot_count = hostname.count('.')
            if dot_count >= 3:
                features['having_Sub_Domain'] = -1
            elif dot_count == 2:
                features['having_Sub_Domain'] = 0
            else:
                features['having_Sub_Domain'] = 1
        
        # 8. SSLfinal_State - check for HTTPS
        if 'SSLfinal_State' in features:
            features['SSLfinal_State'] = 1 if scheme == 'https' else -1
        
        # 9. Domain_registeration_length
        if 'Domain_registeration_length' in features:
            features['Domain_registeration_length'] = 1
        
        # 10. Favicon
        if 'Favicon' in features:
            features['Favicon'] = 1
        
        # 11. port - check for non-standard ports
        if 'port' in features:
            if port is None:
                # Default ports
                features['port'] = 1
            elif port in [80, 443]:  # Standard HTTP/HTTPS
                features['port'] = 1
            else:
                # Non-standard port = suspicious
                features['port'] = -1
        
        # 12. HTTPS_token - check if 'https' appears in domain (spoofing)
        if 'HTTPS_token' in features:
            features['HTTPS_token'] = -1 if 'https' in hostname.lower() else 1
        
        # 13. Request_URL
        if 'Request_URL' in features:
            features['Request_URL'] = 1
        
        # 14. URL_of_Anchor
        if 'URL_of_Anchor' in features:
            features['URL_of_Anchor'] = 1
        
        # 15. Links_in_tags
        if 'Links_in_tags' in features:
            features['Links_in_tags'] = 1
        
        # 16. SFH
        if 'SFH' in features:
            features['SFH'] = 1
        
        # 17. Submitting_to_email (note lowercase)
        if 'Submitting_to_email' in features:
            features['Submitting_to_email'] = 1
        
        # 18. Abnormal_URL
        if 'Abnormal_URL' in features:
            suspicious = ['login', 'verify', 'update', 'confirm', 'account', 'secure', 'signin']
            is_suspicious = any(s in full_url.lower() for s in suspicious)
            features['Abnormal_URL'] = -1 if is_suspicious else 1
        
        # 19. Redirect
        if 'Redirect' in features:
            features['Redirect'] = -1 if '//' in full_url[8:] else 1
        
        # 20. on_mouseover
        if 'on_mouseover' in features:
            features['on_mouseover'] = 1
        
        # 21. RightClick
        if 'RightClick' in features:
            features['RightClick'] = 1
        
        # 22. DNSRecord
        if 'DNSRecord' in features:
            features['DNSRecord'] = 1
        
        # 23. web_traffic
        if 'web_traffic' in features:
            popular = ['google', 'facebook', 'amazon', 'microsoft', 'apple', 'github', 'stackoverflow']
            features['web_traffic'] = 1 if any(p in hostname.lower() for p in popular) else 0
        
        # 24. Page_Rank
        if 'Page_Rank' in features:
            popular = ['google', 'facebook', 'amazon', 'microsoft', 'apple', 'github']
            features['Page_Rank'] = 1 if any(p in hostname.lower() for p in popular) else -1
        
        # 25. Links_pointing_to_page
        if 'Links_pointing_to_page' in features:
            features['Links_pointing_to_page'] = 1
        
        # 26. age_of_domain
        if 'age_of_domain' in features:
            features['age_of_domain'] = 1
        
        # 27. Hosting_IP
        if 'Hosting_IP' in features:
            # If hostname itself is an IP, that's suspicious
            ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
            features['Hosting_IP'] = -1 if re.match(ip_pattern, hostname) else 1
        
        # 28. HTTPS_in_domain
        if 'HTTPS_in_domain' in features:
            features['HTTPS_in_domain'] = -1 if 'https' in hostname.lower() else 1
        
        # 29. Google_Index
        if 'Google_Index' in features:
            features['Google_Index'] = 1
        
        # 30. Iframe
        if 'Iframe' in features:
            features['Iframe'] = 1
        
        # 31. popUpWidnow (note the original typo)
        if 'popUpWidnow' in features:
            features['popUpWidnow'] = 1
        
        return features, None
        
    except Exception as e:
        return None, str(e)

# ---- Streamlit UI ----
st.set_page_config(page_title="Phishing Detection", page_icon="🔍", layout="wide")

st.title("🔍 Phishing Website Detector")
st.markdown("---")
st.write("Enter a URL to check if it's a **phishing site** or **legitimate**.")

# Load artifacts
model, scaler, feature_columns = load_artifacts()

if model is None or scaler is None or feature_columns is None:
    st.stop()

# URL input
st.subheader("Enter URL")
url_input = st.text_input("URL:", placeholder="https://example.com", label_visibility="collapsed")

col1, col2 = st.columns([3, 1])
with col2:
    predict_clicked = st.button("Check URL", type="primary", use_container_width=True)

if predict_clicked and url_input:
    # Validate and normalize URL
    if not url_input.startswith(('http://', 'https://')):
        url_input = 'https://' + url_input
    
    st.markdown("---")
    
    # Extract features
    features, error = extract_features(url_input, feature_columns)
    
    if error:
        st.error(f"❌ Error processing URL: {error}")
    else:
        # Build DataFrame with exact column order from training
        X = pd.DataFrame([features])[feature_columns]
        X_scaled = scaler.transform(X)
        
        # Make prediction
        prediction = model.predict(X_scaled)[0]
        proba = model.predict_proba(X_scaled)[0]
        
        # Display result
        col_result1, col_result2 = st.columns([2, 1])
        
        with col_result1:
            if prediction == 1:
                st.success(f"✅ **LEGITIMATE WEBSITE**")
            else:
                st.error(f"⚠️ **PHISHING DETECTED**")
        
        with col_result2:
            if prediction == 1:
                st.metric("Confidence", f"{proba[1]:.1%}")
            else:
                st.metric("Confidence", f"{proba[0]:.1%}")
        
        # Feature breakdown
        st.markdown("---")
        st.subheader("🔧 Feature Analysis")
        
        # Highlight key suspicious features
        critical_features = {
            'having_IP_Address': 'Direct IP address',
            'port': 'Non-standard port',
            'SSLfinal_State': 'No HTTPS/SSL',
            'Hosting_IP': 'Hosting on IP',
            'web_traffic': 'Low traffic/unknown domain',
            'Page_Rank': 'Low PageRank',
            'Abnormal_URL': 'Suspicious keywords'
        }
        
        st.write("**Key Risk Indicators:**")
        risk_cols = st.columns(4)
        risk_idx = 0
        
        for feat, description in critical_features.items():
            if feat in features:
                value = features[feat]
                is_risky = value == -1
                
                with risk_cols[risk_idx % 4]:
                    if is_risky:
                        st.warning(f"⚠️ {feat}\n({description})\nValue: {value}")
                    else:
                        st.info(f"✓ {feat}\n({description})\nValue: {value}")
                    risk_idx += 1
        
        # All features table
        with st.expander("📊 All Extracted Features"):
            feature_df = pd.DataFrame(list(features.items()), columns=['Feature', 'Value'])
            feature_df = feature_df.sort_values('Feature')
            st.dataframe(feature_df, use_container_width=True, hide_index=True)
        
        st.markdown("---")
        st.info("⚠️ **Disclaimer:** This model uses simulated traffic/reputation scores. Real phishing detection requires live APIs and additional verification methods.")

elif predict_clicked and not url_input:
    st.warning("👉 Please enter a URL")
else:
    st.info("👉 Enter a URL and click **Check URL** to get started")

st.markdown("---")
st.caption("🤖 Random Forest Classifier | Test Accuracy: 98.69% | ROC-AUC: 0.9992")
