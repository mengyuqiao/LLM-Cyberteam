from utils import get_related_cve, load_data, save_json
from tqdm import tqdm
import pandas as pd

def generate4_detail(detail_dict):
    d1= []
    for key,value in tqdm(detail_dict.items()):
        # related CVE-ID
        q1 = ref_instruction + "Based on the provided information, identify the related CVE-ID for the described vulnerability. Ensure that the output includes only the CVE-ID in the exact format CVE-year-code (e.g., CVE-2001-1593). Do not include any additional text."
        links = value["Reference"]
        for link in links:
            try:
                if not link['ref_cve_link'] or not link['ref_desc'] or link['ref_cve_link'] == "N/A":
                    continue
                i1 = f"<Description>: {value['Description']} <reference description>:{link['ref_desc']} <Affected Products>:{value['Affected Products']} <CVSS Scores>: {value['CVSS Scores']}"
                a1 = get_related_cve(link["ref_cve_link"])
                a1 = ", ".join(a1)
                if a1 and a1!="N/A":
                    d1.append({"instruction": q1,"input":i1, "output": a1})
            except Exception as e:
                print(f'error in {key}, {link}, {e}')
    return pd.DataFrame(d1)

cve_details = load_data("data/cve_detail")
cve_references = load_data("data/cve_ref")
print("Number of cve_details: ", len(cve_details))
print("Number of cve_references: ", len(cve_references))

ref_instruction = "The following is a CVE case: <description> a description of the vulnerability, outlining its impact and type of issue. <reference description> a brief summary of the linked content, helping to quickly understand its relevance and purpose regarding the vulnerability. <affected products> the affected products and their versions. <CVSS Scores> the CVSS (Common Vulnerability Scoring System) score used to quantify the severity of the vulnerability. "
detail_instruction = "The following is a CVE case: <description> a description of the vulnerability, outlining its impact and type of issue. <affected products> the affected products and their versions. <CVSS Scores> the CVSS (Common Vulnerability Scoring System) score used to quantify the severity of the vulnerability. "

for cve_detail in cve_details:
    task4_related = generate4_detail(cve_details[cve_detail])
    save_json(task4_related, "task4/related", cve_detail)
# nohup python gen_task4.py > task4.log 2>&1 &