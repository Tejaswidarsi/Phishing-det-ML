import os
import re
import string
import joblib
import logging
import requests
import numpy as np
import pandas as pd
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report
from sklearn.preprocessing import StandardScaler
from requests.exceptions import MissingSchema


# ==============================================
# ✅ Configure Logging
# ==============================================
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# ==============================================
# ✅ Load & Process Phishing Email Dataset
# ==============================================
logging.info("Loading phishing email dataset...")

try:
    dataset_path = "C:\\Users\\HP\\Desktop\\Phishing\\files\\Phishing.csv"
    df = pd.read_csv(dataset_path)
    logging.info("Email dataset loaded successfully!")

    required_columns = ['Email Text', 'Email Type']
    if not all(col in df.columns for col in required_columns):
        raise ValueError("Required columns not found in dataset. Check CSV file formatting.")

    df = df[required_columns].copy()
    df.columns = df.columns.str.strip()

    # ✅ Handle missing values
    df['Email Text'] = df['Email Text'].fillna('')
    df['Email Type'] = df['Email Type'].map({'Safe Email': 0, 'Phishing Email': 1})
    df.dropna(inplace=True)

except Exception as e:
    logging.error(f"Error loading email dataset: {e}")
    exit()

# ✅ Clean email text
def clean_text(text):
    """Clean email text by removing unwanted characters."""
    if not isinstance(text, str):
        return ""
    text = text.lower()
    text = re.sub(r'\d+', '', text)  # Remove numbers
    text = re.sub(r'https?://\S+|www\.\S+', '', text)  # Remove URLs
    text = re.sub(r'<.*?>+', '', text)  # Remove HTML tags
    text = text.translate(str.maketrans('', '', string.punctuation))  # Remove punctuation
    return text

df['cleaned_text'] = df['Email Text'].apply(clean_text)

# ✅ Train-Test Split & TF-IDF Vectorization
X_email = df['cleaned_text']
y_email = df['Email Type']

X_train_email, X_test_email, y_train_email, y_test_email = train_test_split(
    X_email, y_email, test_size=0.2, stratify=y_email, random_state=42
)

vectorizer = TfidfVectorizer(stop_words='english', max_features=5000, ngram_range=(1, 2))
X_train_email_tfidf = vectorizer.fit_transform(X_train_email)
X_test_email_tfidf = vectorizer.transform(X_test_email)

# ✅ Train Email Classification Model
email_model = LogisticRegression(max_iter=200, n_jobs=-1)
email_model.fit(X_train_email_tfidf, y_train_email)

# ✅ Evaluate Email Model
y_pred_email = email_model.predict(X_test_email_tfidf)
logging.info("\n📊 Email Model Performance:")
logging.info(f"✅ Accuracy: {accuracy_score(y_test_email, y_pred_email)}")
logging.info(f"✅ Classification Report:\n{classification_report(y_test_email, y_pred_email)}")

# ✅ Save Email Model & Vectorizer
os.makedirs("models", exist_ok=True)
joblib.dump(email_model, "models/email_model.pkl")
joblib.dump(vectorizer, "models/email_vectorizer.pkl")

# ✅ Email Prediction Function
def predict_email(email):
    """Predict if an email is phishing or safe."""
    email_cleaned = clean_text(email)
    email_tfidf = vectorizer.transform([email_cleaned])
    prediction = email_model.predict(email_tfidf)[0]
    return "Phishing Content 🚨" if prediction == 1 else "Safe Content ✅"

# ==============================================
# ✅ Load Pretrained Models
# ==============================================
df = pd.read_csv("C:\\Users\\HP\\Desktop\\Phishing\\files\\url.csv")
df.drop_duplicates(inplace=True)

# Convert URL, Domain, and TLD to numerical codes
df["URL"] = df["URL"].astype("category").cat.codes
df["Domain"] = df["Domain"].astype("category").cat.codes
df["TLD"] = df["TLD"].astype("category").cat.codes

# Save cleaned dataset (this is correct)
df.to_csv("cleaned_url_dataset.csv", index=False)
print("✅ Data cleaned and saved successfully!")

X = df.drop(columns=["label"])  # Features
y = df["label"]  # Labels (Phishing/Legitimate)

# Scale the features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Split into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

# Train a Logistic Regression model
url_model = LogisticRegression(max_iter=1000)
url_model.fit(X_train, y_train)

# Save the model and scaler
joblib.dump(url_model, "models/url_model.pkl")
joblib.dump(scaler, "models/url_scaler.pkl")  # save scaler

# Evaluate the model
y_pred = url_model.predict(X_test)
print(f"Model Accuracy: {accuracy_score(y_test, y_pred)}")

# Load the cleaned training data to access the category codes
cleaned_df = pd.read_csv("cleaned_url_dataset.csv")
label_counts = cleaned_df["label"].value_counts()

print("Label Counts in cleaned_url_dataset.csv:")
print(label_counts)

# Explicitly convert the columns to category.
url_categories = cleaned_df["URL"].astype("category")
domain_categories = cleaned_df["Domain"].astype("category")
tld_categories = cleaned_df["TLD"].astype("category")

def extract_features(url):
    """Extracts features from the given URL."""
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    tld = parsed_url.netloc.split('.')[-1]
    path = parsed_url.path
    query = parsed_url.query

    # Convert URL, Domain, and TLD to numerical codes using the loaded categories
    url_code = url_categories.cat.categories.get_loc(url) if url in url_categories.cat.categories else -1
    domain_code = domain_categories.cat.categories.get_loc(domain) if domain in domain_categories.cat.categories else -1
    tld_code = tld_categories.cat.categories.get_loc(tld) if tld in tld_categories.cat.categories else -1

    features = {
        "URL": url_code,
        "URLLength": len(url),
        "Domain": domain_code,
        "DomainLength": len(parsed_url.netloc),
        "IsDomainIP": 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}", parsed_url.netloc) else 0,
        "TLD": tld_code,
        "PathLength": len(path),
        "QueryLength": len(query),
        "SubdomainCount": domain.count('.'),
        "HasHttps": 1 if url.startswith("https") else 0,
        "HasAtSymbol": 1 if "@" in url else 0,
        "HasDashSymbol": 1 if "-" in url else 0,
        "HasTildeSymbol": 1 if "~" in url else 0,
        "URLSimilarityIndex": 0,  # Placeholder (needs dataset comparison)
        "CharContinuationRate": 0,  # Placeholder (calculate based on dataset)
        "TLDLegitimateProb": 0,  # Placeholder (needs reference data)
    }

    return np.array(list(features.values())).reshape(1, -1)


# ==============================================
# ✅ Analyze Website Content & Send to Email Model
# ==============================================
def analyze_website(url):
    """Fetches and analyzes website content for phishing indicators."""
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")

        # ✅ Extract website text
        page_text = soup.get_text().lower()

        # ✅ Check for suspicious keywords
        suspicious_keywords = ["login", "verify", "bank", "account", "password", "update", "click here"]
        keyword_count = sum(page_text.count(keyword) for keyword in suspicious_keywords)

        # ✅ Email Model Prediction
        email_prediction = predict_email(page_text) if email_model else "Email model unavailable."

        # ✅ Heuristic-based scoring
        if keyword_count > 3:
            return f"🔴 HIGH RISK: Suspicious content detected! ({email_prediction})"
        elif keyword_count > 1:
            return f"🟡MODERATE RISK: Some suspicious keywords found. ({email_prediction})"
        else:
            return f"🟢LOW RISK: No major phishing indicators. ({email_prediction})"

    except MissingSchema:
        return "⚠️ Invalid URL format! Please enter a valid URL."
    except requests.RequestException:
        return "❌ Unable to fetch website content."
    


def predict_url(url):
    features = extract_features(url)
    prediction = url_model.predict(features)[0] if url_model else None

    result = "Phishing" if prediction == 1 else "Safe"
    website_analysis = analyze_website(url)

    # Check if website_analysis is an error message
    if website_analysis.startswith("⚠️"):
        result = "Error" # If it's an error, change the result to "Error"

    return {
        "result": result,
        "website_analysis": website_analysis,
    }



# ✅ Test Example
test = predict_url("https://web.whatsapp.com/")
print(test)