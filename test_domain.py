from domain_reputation import check_domain_age

for domain in [
    "google.com",
    "github.com",
    "microsoft.com"
]:

    result = check_domain_age(domain)

    print()
    print("Domain:", domain)
    print("Registered:", result["created"])
    print("Age:", result["age_text"])
    print("Days:", result["age_days"])