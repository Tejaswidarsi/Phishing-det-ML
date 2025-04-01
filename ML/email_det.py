import pandas as pd
import numpy as np
import re
from flask_cors import CORS
import string
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import joblib



# ✅ Step 1: Load & Clean Data
print("🔄 Loading dataset...")

DATA_PATH = "C:/Users/HP/Desktop/Phishing/files/Phishing.csv"  # Use forward slashes

try:
    df = pd.read_csv(DATA_PATH)
    print("✅ Dataset loaded successfully!\n")

    # Debug: Print column names
    print("📌 Available columns:", df.columns.tolist())

    # Ensure required columns exist
    required_columns = ['Email Text', 'Email Type']
    if not all(col in df.columns for col in required_columns):
        raise ValueError("❌ ERROR: Required columns not found in dataset. Check CSV formatting.")

    df = df[required_columns]  # Keep necessary columns
except Exception as e:
    print("❌ Error loading dataset:", str(e))
    exit()

# ✅ Step 2: Handle Missing Values
df.dropna(inplace=True)
df.reset_index(drop=True, inplace=True)

# ✅ Step 3: Normalize Labels
df['Email Type'] = df['Email Type'].map({'Safe Email': 0, 'Phishing Email': 1})

# ✅ Step 4: Remove Unexpected Values
df = df[df['Email Type'].isin([0, 1])]  # Keep only valid labels

# ✅ Check Data After Cleaning
print("\n🔍 Unique values in 'Email Type' column:", df['Email Type'].unique())
print(f"✅ Total Samples: {len(df)}")

if df.empty:
    raise ValueError("❌ ERROR: No data available after cleaning. Check your CSV file.")

# ✅ Step 5: Preprocess Email Text
def clean_text(text):
    text = text.lower()
    text = re.sub(r'\[.*?\]', '', text)  # Remove brackets
    text = re.sub(r'https?://\S+|www\.\S+', '', text)  # Remove URLs
    text = re.sub(r'<.*?>+', '', text)  # Remove HTML tags
    text = text.translate(str.maketrans('', '', string.punctuation))  # Remove punctuation
    return text.strip()  # Remove extra spaces

df['cleaned_text'] = df['Email Text'].apply(clean_text)

# ✅ Step 6: Train-Test Split
X = df['cleaned_text']
y = df['Email Type']
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# ✅ Step 7: TF-IDF Vectorization
vectorizer = TfidfVectorizer(stop_words='english', max_features=5000)
X_train_tfidf = vectorizer.fit_transform(X_train)
X_test_tfidf = vectorizer.transform(X_test)

# ✅ Step 8: Train Model (Logistic Regression)
model = LogisticRegression()
model.fit(X_train_tfidf, y_train)

# ✅ Step 9: Function for Predictions
def predict_email(email):
    def clean_text(text):
        if not isinstance(text, str):
            return ""
        text = text.lower()
        text = re.sub(r'\d+', '', text)
        text = re.sub(r'https?://\S+|www\.\S+', '', text)
        text = re.sub(r'<.*?>+', '', text)
        text = text.translate(str.maketrans('', '', string.punctuation))
        return text

    try:
        email_model = joblib.load("models/email_model.pkl")
        vectorizer = joblib.load("models/email_vectorizer.pkl")

        email_cleaned = clean_text(email)
        email_tfidf = vectorizer.transform([email_cleaned])
        prediction = email_model.predict(email_tfidf)[0]
        return "Phishing Content 🚨" if prediction == 1 else "Safe Content ✅"

    except FileNotFoundError:
        return "Error: Email model files not found."
    except joblib.PickleError:
        return "Error: Corrupted email model files."
    except ValueError as e:
        return f"Error: Vectorization or prediction error - {e}"
    except Exception as e:
        return f"Error: An unexpected error occurred - {e}"

    
