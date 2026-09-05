import pandas as pd
import joblib
import tldextract

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score
)
from sklearn.calibration import CalibratedClassifierCV

from features import extract_features, FEATURE_NAMES


DATASET = "dataset/phishing_site_urls.csv"


def get_registered_domain(url):
    try:
        result = tldextract.extract(str(url))

        if result.suffix:
            return f"{result.domain}.{result.suffix}".lower()

        return result.domain.lower()

    except Exception:
        return str(url).lower()


print("Loading dataset...")

df = pd.read_csv(
    DATASET,
    encoding="latin1"
)

df = df.dropna(subset=["URL", "Label"])

df["URL"] = df["URL"].astype(str).str.strip()

df["Label"] = (
    df["Label"]
    .astype(str)
    .str.strip()
    .str.lower()
)

df = df[
    df["Label"].isin(["good", "bad"])
]

df = df.drop_duplicates(
    subset=["URL"]
)

df["label"] = (
    df["Label"] == "bad"
).astype(int)


print("\nLabels:")
print(df["Label"].value_counts())

print("\nExamples:")
print(
    df[["URL", "Label"]]
    .sample(10, random_state=42)
)


# Use 150k while developing
if len(df) > 150000:
    df = df.sample(
        150000,
        random_state=42
    )


print("\nExtracting domains...")

df["group_domain"] = (
    df["URL"]
    .apply(get_registered_domain)
)


print("Extracting features...")

X = pd.DataFrame([
    extract_features(url)
    for url in df["URL"]
])[FEATURE_NAMES]

y = df["label"]
groups = df["group_domain"]


# Domain-aware split

splitter = GroupShuffleSplit(
    n_splits=1,
    test_size=0.20,
    random_state=42
)

train_idx, test_idx = next(
    splitter.split(
        X,
        y,
        groups=groups
    )
)

X_train = X.iloc[train_idx]
X_test = X.iloc[test_idx]

y_train = y.iloc[train_idx]
y_test = y.iloc[test_idx]


print("\nTraining rows:", len(X_train))
print("Testing rows:", len(X_test))


base_model = RandomForestClassifier(
    n_estimators=300,

    max_depth=18,

    min_samples_leaf=3,

    class_weight="balanced",

    n_jobs=-1,

    random_state=42
)


print("\nTraining calibrated model...")

model = CalibratedClassifierCV(
    base_model,
    method="sigmoid",
    cv=3
)

model.fit(
    X_train,
    y_train
)


pred = model.predict(X_test)

probabilities = (
    model.predict_proba(X_test)[:, 1]
)


print("\nConfusion Matrix:")

print(
    confusion_matrix(
        y_test,
        pred
    )
)


print("\nClassification Report:")

print(
    classification_report(
        y_test,
        pred,
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
    "model.pkl"
)

print(
    "\nNew model saved as model.pkl"
)