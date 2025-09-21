import json

input_file = "./security-agent/cyber_data/crawl/epss_history.json"
output_file = "extracted_cve_ids.txt"

with open(input_file, "r", encoding="utf-8") as f:
    data = json.load(f)

# 提取所有 CVE ID（假设结构为 { "CVE-XXXX-YYYY": {...}, ... }）
cve_ids = list(data.keys())

print(f"总共提取了 {len(cve_ids)} 个 CVE ID")

# 可选：写入文本文件
with open(output_file, "w", encoding="utf-8") as f:
    for cve_id in cve_ids:
        f.write(cve_id + "\n")

print(f"CVE ID 列表已保存到: {output_file}")
