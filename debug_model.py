import joblib
import pandas as pd

from features import extract_features, FEATURE_NAMES

model = joblib.load("model.pkl")

urls = [
    "https://google.com",
    "https://github.com",
    "https://microsoft.com",
    "https://amazon.com",
    "https://wikipedia.org",

    "http://192.168.1.20/verify/account/login",
    "http://paypal-secure-login.example.com/verify",
    "http://random-domain-928374.example.net/password"
]

print("\nFEATURE NAMES:")
print(FEATURE_NAMES)

print("\n" + "=" * 70)

for url in urls:

    features = extract_features(url)

    X = pd.DataFrame(
        [features]
    )[FEATURE_NAMES]

    probability = model.predict_proba(X)[0]

    print("\nURL:", url)

    print(
        "LEGIT:",
        round(probability[0] * 100, 2),
        "%"
    )

    print(
        "PHISH:",
        round(probability[1] * 100, 2),
        "%"
    )

    print("FEATURES:")

    for key, value in features.items():
        print(
            f"  {key}: {value}"
        )