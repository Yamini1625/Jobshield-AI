"""
train_model.py
----------------
Trains a TF-IDF + Logistic Regression classifier that estimates the
probability that a job/internship posting is fraudulent, based on the
text of the posting.

This is a DEMO dataset (ml/dataset.csv) of ~50 hand-crafted examples.
It is enough to make the classifier meaningfully sensitive to common
scam language patterns, but for production-grade accuracy you should
retrain on a larger labeled dataset (for example the public "Real or
Fake Job Posting" dataset on Kaggle) - just replace ml/dataset.csv
with a bigger file that has the same two columns: text,label
(label = 1 for fraudulent, 0 for genuine) and re-run this script.

Run with:
    python ml/train_model.py
"""

import csv
import os
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(BASE_DIR, "dataset.csv")
MODEL_PATH = os.path.join(BASE_DIR, "scam_model.pkl")


def load_dataset(path):
    texts, labels = [], []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            texts.append(row["text"])
            labels.append(int(row["label"]))
    return texts, labels


def train():
    texts, labels = load_dataset(DATASET_PATH)
    print(f"Loaded {len(texts)} training examples "
          f"({sum(labels)} fraudulent / {len(labels) - sum(labels)} genuine)")

    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(
            lowercase=True,
            ngram_range=(1, 2),
            stop_words="english",
            min_df=1,
        )),
        ("clf", LogisticRegression(max_iter=1000, class_weight="balanced")),
    ])

    pipeline.fit(texts, labels)

    joblib.dump(pipeline, MODEL_PATH)
    print(f"Model trained and saved to {MODEL_PATH}")

    # quick sanity check
    sample_scam = "Pay Rs 999 registration fee for instant job, no interview needed, guaranteed placement!"
    sample_legit = "Software Engineer Intern position, apply through our careers page, technical interview required."
    for label, text in [("SCAM sample", sample_scam), ("LEGIT sample", sample_legit)]:
        proba = pipeline.predict_proba([text])[0][1]
        print(f"{label}: fraud probability = {proba:.2f}")


if __name__ == "__main__":
    train()
