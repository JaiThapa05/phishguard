import pandas as pd
from urllib.parse import urlparse

df = pd.read_csv(
    "dataset/phishing_site_urls.csv",
    encoding="latin1"
)

df["URL"] = df["URL"].astype(str).str.strip()
df["Label"] = df["Label"].astype(str).str.strip().str.lower()


def hostname(url):
    try:
        u = url

        if not u.startswith(("http://", "https://")):
            u = "http://" + u

        return (urlparse(u).hostname or "").lower()

    except Exception:
        return ""


df["host"] = df["URL"].apply(hostname)

domains = [
    "google.com",
    "github.com",
    "microsoft.com",
    "amazon.com",
    "wikipedia.org",
    "python.org"
]


for domain in domains:

    rows = df[
        (df["host"] == domain) |
        (df["host"].str.endswith("." + domain))
    ]

    print("\n" + "=" * 60)
    print(domain)
    print("=" * 60)

    print("Rows:", len(rows))

    if len(rows):
        print("\nLabels:")
        print(rows["Label"].value_counts())

        print("\nExamples:")
        print(
            rows[
                ["URL", "Label"]
            ].head(10).to_string(index=False)
        )