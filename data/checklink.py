import os, json


def main():
    base = "./security-agent/cyber_data/data/cve_link/2025"
    for month in sorted(os.listdir(base)):
        path = os.path.join(base, month, "link.json")
        if not os.path.isfile(path):
            print(f"{month:>9}: MISSING link.json")
            continue
        data = json.load(open(path))
        length = len(data) if isinstance(data, list) else 0
        print(f"{month:>9}: {length} URLs")


if __name__ == "__main__":
    main()
