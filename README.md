
##  Methodology

1. **Data Loading** — 11,055 samples with 30 URL-based features
2. **Data Cleaning** — Removed 357 rows (~3.2%) with conflicting labels
3. **Train/Val/Test Split** — 70/15/15 stratified split
4. **Preprocessing** — String→numeric conversion, StandardScaler normalization
5. **Model Training** — Compared Logistic Regression, Random Forest, XGBoost
6. **Evaluation** — Random Forest selected (98.57% accuracy)

##  Limitations

- Uses mocked traffic/reputation data (not live APIs)
- URL-only analysis (cannot detect content-based phishing)
- Requires periodic retraining as threats evolve

##  Dataset

**Source:** UCI Phishing Websites Dataset
- Total Samples: 11,055
- Features: 30 URL indicators
- Classes: Phishing (-1) vs Legitimate (1)


---

**Last Updated:** September 2026
