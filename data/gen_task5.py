from utils import get_cvsçs_vector
from sklearn.model_selection import train_test_split
# load data by year
import os
import json
import pandas as pd
from tqdm import tqdm
from utils import load_data, save_json

def generate5_detail(detail_dict):
    d1= []
    # do human language mapping
    pre_mapping = {
        "AC": "Access Complexity",
        "Au": "Authentication",
        "AT": "Attack Requirements", # https://www.cvedetails.com/cve/CVE-2017-12741
        "VC": "Confidentiality(VC)",
        "VI": "Integrity(VI)",
        "C": "Confidentiality Impact",
        "I": "Integrity Impact",
        "A": "Availability Impact",
        "PR": "Privileges Required",
        "UI": "User Interaction",
        "S": "Scope",
    }
    after_mapping = {
        "H": "High",
        "L": "Low",
        "M": "Medium",
        "N": "None",
        "U": "Unchanged",
        "R": "Required",
        "C": "Complete",
        "P": "Partial",
        "S": "Single",
        "A": "Active",
    }
    av_mapping = {
        "L": "Local",
        "A": "Adjacent Network",
        "N": "Network",
        "P": "Physical", # CVE-2014-2019
        # "R": "Remote", 
    }
    for key,value in tqdm(detail_dict.items()):
        # CVSS vector
        # q3 = "The following is a CVE case: <description> a description of the vulnerability, outlining its impact, attack requirements, and type of issue. <affected products> the affected products and their versions. Based on these information, determine the CVSS vector for the vulnerability by evaluating the following attributes: \n - Access Vector (Local, Adjacent Network, Network, Physical)\n- Access Complexity (Low, Medium, High)\n- Privileges Required (None, Low, High)\n - User Interaction (None, Required)\n - Scope (Unchanged, Changed)\n - Confidentiality Impact (None, Partial, Complete)\n - Integrity Impact (None, Partial, Complete)\n - Availability Impact (None, Partial, Complete)\n Provide the output strictly in the following format: `Attribute: Value, Attribute: Value, ...` \n Example: `Access Vector: Local, Access Complexity: Low, Privileges Required: Low, User Interaction: None, Scope: Unchanged, Confidentiality Impact: None, Integrity Impact: None, Availability Impact: High`. Do not include any additional explanations or comments."
        q3 = "The following is a CVE case: <description> a description of the vulnerability, outlining its impact, attack requirements, and type of issue. <affected products> the affected products and their versions. Based on this information, determine the CVSS vector for this vulnerability by evaluating the following aspects: Assess Vector (Local, Adjacent Network, Network, Physical), Access Complexity, Authentication, Confidentiality (VC), Integrity (VI), Privileges Required, User Interaction, Scope, and their corresponding values (e.g., High, Medium, Low, None, Unchanged, Required, Complete, Partial, Single). Provide the response strictly in the format: 'aspect: value, aspect: value, ...' (e.g., Access Vector: Network, Access Complexity: Medium, Authentication: None, Confidentiality Impact: Partial, Integrity Impact: Partial, Availability Impact: Partial), without including any additional information."
        i3 = f"<Description>: {value['Description']} <Affected Products>:{value['Affected Products']}"    
        a3_url = "https://www.cvedetails.com/cve/"+value["CVE Code"]+"/"
        # print(a3_url)
        a3_ori = get_cvss_vector(a3_url)
        if not a3_ori:
            print("None",key)
            continue
        if "AV" not in a3_ori:
            print("---",key,a3_ori)
            continue
        a3_ori = a3_ori.split("/")
        flag = True
        for var in a3_ori:
            # print(var)
            pair = var.split(":")
            if len(pair) == 2:
                if flag:
                    if pair[0] == "CVSS":
                        continue
                    try:
                        a3_ori[a3_ori.index(var)] = "Access Vector: " + av_mapping[pair[1]]
                    except Exception as e:
                        print(f'AV error in {key}, {pair}, {e}')
                    flag = False
                    continue
                try:
                    a3_ori[a3_ori.index(var)] = pre_mapping[pair[0]] + ": " + after_mapping[pair[1]]
                except Exception as e:
                    print(f'error in {key}, {pair}, {e}')
        a3 = ", ".join([i for i in a3_ori])
        # print(a3)
        if a3 and a3!="N/A":
            d1.append({"instruction": q3,"input":i3, "output": a3})
    return pd.DataFrame(d1)

cve_details = load_data("data/cve_detail")
cve_references = load_data("data/cve_ref")
print("Number of cve_details: ", len(cve_details))
print("Number of cve_references: ", len(cve_references))

ref_instruction = "The following is a CVE case: <description> a description of the vulnerability, outlining its impact and type of issue. <reference description> a brief summary of the linked content, helping to quickly understand its relevance and purpose regarding the vulnerability. <affected products> the affected products and their versions. <CVSS Scores> the CVSS (Common Vulnerability Scoring System) score used to quantify the severity of the vulnerability. "
detail_instruction = "The following is a CVE case: <description> a description of the vulnerability, outlining its impact and type of issue. <affected products> the affected products and their versions. <CVSS Scores> the CVSS (Common Vulnerability Scoring System) score used to quantify the severity of the vulnerability. "

saved_tasks = ["2014","2015","2016","2017","2018","2019","2020","2021","2022","2023"]
for cve_detail in cve_details:
    if cve_detail in saved_tasks:
        continue
    print("Processing: ", cve_detail)
    task5_vector = generate5_detail(cve_details[cve_detail])
    save_json(task5_vector, "task5/CVSS", cve_detail)
    
# nohup python gen_task5.py > task5.log 2>&1 &