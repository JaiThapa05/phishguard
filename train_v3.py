import pandas as pd
import joblib
import tldextract

from sklearn.model_selection import GroupShuffleSplit
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score
)


DATASET = "dataset/training_v3.csv"


def registered_domain(url):
    try:
        ext = tldextract.extract(str(url))

        if ext.suffix:
            return f"{ext.domain}.{ext.suffix}".lower()

        return ext.domain.lower()

    except Exception:
        return str(url).lower()


print("Loading V3 dataset...")

df = pd.read_csv(DATASET)

df = df.dropna(
    subset=["URL", "label"]
)

df["URL"] = (
    df["URL"]
    .astype(str)
    .str.strip()
    .str.lower()
)

df["label"] = (
    df["label"]
    .astype(int)
)

df = df.drop_duplicates(
    subset=["URL"]
)


print("\nClasses:")
print(df["label"].value_counts())


print("\nExtracting registered domains...")

df["domain"] = (
    df["URL"]
    .apply(registered_domain)
)


# Domain-aware split
splitter = GroupShuffleSplit(
    n_splits=1,
    test_size=0.20,
    random_state=42
)


train_index, test_index = next(
    splitter.split(
        df["URL"],
        df["label"],
        groups=df["domain"]
    )
)


train_df = df.iloc[train_index]
test_df = df.iloc[test_index]


print(
    "\nTraining:",
    len(train_df)
)

print(
    "Testing:",
    len(test_df)
)


model = Pipeline([

    (
        "tfidf",

        TfidfVectorizer(
            analyzer="char",
            ngram_range=(3, 5),
            min_df=3,
            max_features=120000,
            sublinear_tf=True
        )
    ),

    (
        "classifier",

        LogisticRegression(
            max_iter=1200,
            class_weight="balanced",
            C=1.2
        )
    )
])


print("\nTraining V3 model...")

model.fit(
    train_df["URL"],
    train_df["label"]
)


pred = model.predict(
    test_df["URL"]
)

prob = (
    model.predict_proba(
        test_df["URL"]
    )[:, 1]
)


print("\nConfusion Matrix:")

print(
    confusion_matrix(
        test_df["label"],
        pred
    )
)


print("\nClassification Report:")

print(
    classification_report(
        test_df["label"],
        pred,
        target_names=[
            "legitimate",
            "phishing"
        ]
    )
)


print(
    "ROC-AUC:",
    round(
        roc_auc_score(
            test_df["label"],
            prob
        ),
        4
    )
)


joblib.dump(
    model,
    "url_model_v3.pkl"
)

print(
    "\nSaved: url_model_v3.pkl"
)