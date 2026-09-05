import pandas as pd

df = pd.read_csv(
    "dataset/phishing_site_urls.csv",
    encoding="latin1"
)

print("\nLABEL COUNTS:")
print(df["Label"].value_counts())

targets = [
    "google",
    "github",
    "microsoft",
    "amazon",
    "wikipedia"
]

for target in targets:

    matches = df[
        df["URL"]
        .astype(str)
        .str.contains(
            target,
            case=False,
            na=False
        )
    ]

    print(
        f"\n===== {target.upper()} ====="
    )

    print(
        matches[
            ["URL", "Label"]
        ].head(15)
    )

    print("\nLabels:")

    print(
        matches["Label"]
        .value_counts()
    )