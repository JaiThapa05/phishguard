import joblib

model = joblib.load(
    "url_model.pkl"
)

urls = [
    "https://google.com",
    "https://github.com",
    "https://microsoft.com",
    "https://amazon.com",
    "https://wikipedia.org",
    "https://python.org",

    "http://paypal-secure-login.example.com/verify",
    "http://192.168.1.20/verify/account/login",
    "http://random-domain-928374.example.net/password"
]


print("\nURL MODEL V2")
print("=" * 65)


for url in urls:

    probability = (
        model.predict_proba(
            [url.lower()]
        )[0][1]
    )

    print(
        f"{url:55} "
        f"{probability * 100:.2f}%"
    )