import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score
)


print("Loading dataset...")

df = pd.read_csv(
    "dataset/phishing_site_urls.csv",
    encoding="latin1"
)

df = df.dropna(
    subset=["URL", "Label"]
)

df["URL"] = (
    df["URL"]
    .astype(str)
    .str.strip()
    .str.lower()
)

df["Label"] = (
    df["Label"]
    .astype(str)
    .str.strip()
    .str.lower()
)

df = df[
    df["Label"].isin(
        ["good", "bad"]
    )
]

df = df.drop_duplicates(
    subset=["URL"]
)

df["label"] = (
    df["Label"] == "bad"
).astype(int)


print("\nDataset:")

print(
    df["label"].value_counts()
)


# Development ke liye manageable sample
if len(df) > 200000:

    legit = df[
        df["label"] == 0
    ].sample(
        n=min(
            100000,
            (df["label"] == 0).sum()
        ),
        random_state=42
    )

    phishing = df[
        df["label"] == 1
    ].sample(
        n=min(
            100000,
            (df["label"] == 1).sum()
        ),
        random_state=42
    )

    df = pd.concat(
        [legit, phishing]
    ).sample(
        frac=1,
        random_state=42
    )


X_train, X_test, y_train, y_test = (
    train_test_split(
        df["URL"],
        df["label"],

        test_size=0.20,

        random_state=42,

        stratify=df["label"]
    )
)


print("\nTraining rows:", len(X_train))
print("Testing rows:", len(X_test))


model = Pipeline([

    (
        "tfidf",

        TfidfVectorizer(

            analyzer="char",

            ngram_range=(3, 5),

            min_df=2,

            max_features=150000,

            sublinear_tf=True
        )
    ),

    (
        "classifier",

        LogisticRegression(

            max_iter=1000,

            class_weight="balanced",

            C=2.0
        )
    )

])


print("\nTraining URL model...")

model.fit(
    X_train,
    y_train
)


predictions = model.predict(
    X_test
)

probabilities = (
    model.predict_proba(
        X_test
    )[:, 1]
)


print("\nConfusion Matrix:")

print(
    confusion_matrix(
        y_test,
        predictions
    )
)


print("\nClassification Report:")

print(
    classification_report(
        y_test,
        predictions,
        target_names=[
            "legitimate",
            "phishing"
        ]
    )
)


print(
    "\nROC-AUC:",
    round(
        roc_auc_score(
            y_test,
            probabilities
        ),
        4
    )
)


joblib.dump(
    model,
    "url_model.pkl"
)

print(
    "\nSaved: url_model.pkl"
)