import pandas as pd
from urllib.parse import urlparse


PHISHING_FILE = "dataset/phishing_site_urls.csv"
TRANCO_FILE = "dataset/tranco.csv"
OUTPUT_FILE = "dataset/training_v3.csv"


def normalize_url(url):

    url = str(url).strip().lower()

    if not url:
        return None

    if not url.startswith(
        ("http://", "https://")
    ):
        url = "http://" + url

    try:
        parsed = urlparse(url)

        if not parsed.hostname:
            return None

        return url

    except Exception:
        return None


print("Loading phishing dataset...")

old = pd.read_csv(
    PHISHING_FILE,
    encoding="latin1"
)

old["Label"] = (
    old["Label"]
    .astype(str)
    .str.lower()
    .str.strip()
)

# IMPORTANT:
# Old dataset se sirf phishing rows lenge.
# Uske "good" URLs par ab depend nahi karenge.

phishing = old[
    old["Label"] == "bad"
][["URL"]].copy()

phishing["URL"] = (
    phishing["URL"]
    .apply(normalize_url)
)

phishing = phishing.dropna()

phishing["label"] = 1


print(
    "Phishing URLs:",
    len(phishing)
)


print("Loading Tranco legitimate domains...")

tranco = pd.read_csv(
    TRANCO_FILE,
    header=None,
    names=[
        "rank",
        "domain"
    ]
)

tranco = tranco.dropna(
    subset=["domain"]
)

# Development ke liye top 100k
tranco = tranco.head(100000)


legitimate = pd.DataFrame()

legitimate["URL"] = (
    "https://" +
    tranco["domain"]
    .astype(str)
    .str.strip()
    .str.lower()
)

legitimate["label"] = 0


print(
    "Legitimate URLs:",
    len(legitimate)
)


combined = pd.concat(
    [
        legitimate,
        phishing
    ],
    ignore_index=True
)


combined = combined.drop_duplicates(
    subset=["URL"]
)


combined = combined.sample(
    frac=1,
    random_state=42
).reset_index(drop=True)


combined.to_csv(
    OUTPUT_FILE,
    index=False
)


print("\nFinal dataset:")
print(
    combined["label"]
    .value_counts()
)

print(
    "\nSaved:",
    OUTPUT_FILE
)