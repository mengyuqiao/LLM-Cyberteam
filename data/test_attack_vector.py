from transformers import pipeline

# Load the cybersecurity NER model
ner = pipeline(
    "ner",
    model="bnsapa/cybersecurity-ner",
    aggregation_strategy="simple"
)

def classify_attack_vector(report: str) -> str:
    # Extract and lowercase the entity words
    tokens = {ent["word"].lower() for ent in ner(report)}

    # Expanded keyword sets
    network_kw  = {"network", "remote", "router", "rce", "http", "https", "s3", "storage", "object"}
    adjacent_kw = {"bluetooth", "802.11", "wifi", "subnet", "lan"}
    local_kw    = {"local", "execute", "user", "login", "privilege"}
    physical_kw = {"physical", "touch", "usb", "peripheral", "manipulate"}

    # 1) Match on NER-extracted tokens
    if tokens & network_kw:
        return "Network (N)"
    if tokens & adjacent_kw:
        return "Adjacent Network (A)"
    if tokens & local_kw:
        return "Local (L)"
    if tokens & physical_kw:
        return "Physical (P)"

    # 2) Fallback raw-text scan
    text = report.lower()
    for label, kws in [
        ("Network (N)",          network_kw),
        ("Adjacent Network (A)", adjacent_kw),
        ("Local (L)",            local_kw),
        ("Physical (P)",         physical_kw),
    ]:
        if any(kw in text for kw in kws):
            return label

    return "Unknown"


if __name__ == "__main__":
    example_report = """
    CVE-2024-24747: MinIO is a High Performance Object Storage. When someone creates an access key,
    it inherits the permissions of the parent key. Not only for `s3:*` actions, but also `admin:*` actions.
    Which means unless somewhere above in the access-key hierarchy, the `admin` rights are denied,
    access keys will be able to simply override their own `s3` permissions to something more permissive. The vulnerability is fixed in RELEASE.2024-01-31T20-20-33Z.
    """
    print(classify_attack_vector(example_report))