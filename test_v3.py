import joblib

model = joblib.load(
    "url_model_v3.pkl"
)


legitimate = [
    "https://google.com",
    "https://github.com",
    "https://microsoft.com",
    "https://amazon.com",
    "https://wikipedia.org",
    "https://python.org",
    "https://mozilla.org",
    "https://stackoverflow.com",
    "https://cloudflare.com",
    "https://openai.com",
    "https://github.com/login",
    "https://accounts.google.com/",
    "https://www.amazon.com/gp/help/customer/display.html",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://docs.python.org/3/"
]


suspicious = [
    "http://paypal-secure-login.example.com/verify",
    "http://microsoft-login.example.net/account/verify",
    "http://apple-id-confirm.example.org/login",
    "http://192.168.1.20/verify/account/password",
    "http://random-domain-928374.example.net/password"
]


print("\n========== LEGITIMATE ==========\n")

for url in legitimate:

    p = model.predict_proba(
        [url.lower()]
    )[0][1]

    print(
        f"{p*100:6.2f}%  {url}"
    )


print("\n========== SUSPICIOUS ==========\n")

for url in suspicious:

    p = model.predict_proba(
        [url.lower()]
    )[0][1]

    print(
        f"{p*100:6.2f}%  {url}"
    )