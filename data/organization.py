from utils import get_related_cve, load_data, save_json, get_cvss_vector
from tqdm import tqdm
import pandas as pd
import json
import random
import os
random.seed(42)

init_path = "data/organization/"
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

def json_list_to_file(json_list, file_name):
    cnt_related = 0
    gathered_data = []
    for year in cve_details:
        if year not in ['2020', '2021', '2022', '2023', '2024']:
            print('skip year', year)
            continue
        random.shuffle(json_list)
        # json_list = json_list[:200]
        for key in json_list:
            if key not in cve_details[year]:
                print('skip key', key)
                continue
            value = cve_details[year][key]
            # task2
            product_q = "What are the affected products for this vulnerability?"
            product = value.get("Affected Products", "")
            # task 3
            cve_id_q = "What is the CVE-ID for this vulnerability?"
            # cve_id = value.get("CVE Code", "")
            cve_id = key.split(".")[0]
            # task 5
            # cvss_url = "https://www.cvedetails.com/cve/"+value["CVE Code"]+"/"
            cvss_url = "https://www.cvedetails.com/cve/"+cve_id+"/"
            cvss = get_cvss_vector(cvss_url)
            if cvss:
                if "AV" not in cvss:
                    print("---no AV ",key,cvss)
                    continue
                cvss = cvss.split("/")
                flag = True
                for var in cvss:
                    # print(var)
                    pair = var.split(":")
                    if len(pair) == 2:
                        if flag:
                            if pair[0] == "CVSS":
                                continue
                            try:
                                cvss[cvss.index(var)] = "Access Vector: " + av_mapping[pair[1]]
                            except Exception as e:
                                print(f'---AV error in {key}, {e}')
                            flag = False
                            continue
                        try:
                            cvss[cvss.index(var)] = pre_mapping [pair[0]] + ": " + after_mapping[pair[1]]
                        except Exception as e:
                            print(f'---error in {key}, {e}')
                cvss_q = "Determine the CVSS vector for this vulnerability by evaluating the following aspects: Assess Vector (Local, Adjacent Network, Network, Physical), Access Complexity, Authentication, Confidentiality (VC), Integrity (VI), Privileges Required, User Interaction, Scope, and their corresponding values (e.g., High, Medium, Low, None, Unchanged, Required, Complete, Partial, Single). Provide the response strictly in the format: 'aspect: value, aspect: value, ...' (e.g., Access Vector: Network, Access Complexity: Medium, Authentication: None, Confidentiality Impact: Partial, Integrity Impact: Partial, Availability Impact: Partial), without including any additional information."
                cvss = ", ".join([i for i in cvss])
            # only using the first cve_ref
            cve_ref = cve_references[year].get(key)  
            if not cve_ref:
                print("===No reference", key)
                continue  
            for reference in cve_ref:
                if not reference['ref_summary']:
                    continue
                actors_q = "Who are the threat actors likely to be involved in exploiting this vulnerability?"
                actors = reference["ref_summary"].get("Threat Actors", "")
                ttps_q = "What specific TTPs (Tactics, Techniques, and Procedures) might adversaries exploit in relation to this vulnerability?"
                ttps = reference["ref_summary"].get("TTPs", "")
                paths_q = "What are the exploit paths for this vulnerability?"
                paths = reference["ref_summary"].get("Exploit Paths", "")
                # task2
                tool_q = "What are the corresponding infrastructure and tools for this vulnerability?"
                tool = reference["ref_summary"].get("Infrastructure and Tools", "")
                impact_q = "What are the potential impacts of this vulnerability?"
                impact = reference["ref_summary"].get("Impacts", "")
                # task 6
                migitation_q = "What are the mitigation strategies for this vulnerability?"
                migitation = reference["ref_summary"].get("Mitigation", "")
                patch_q = "What patches are available to address this vulnerability?"
                patch = reference["ref_summary"].get("Patch", "")
                try:
                    # task 4
                    related_q = "Identify the related CVE-ID for the described vulnerability. Ensure that the output includes only the CVE-ID in the exact format CVE-year-code (e.g., CVE-2001-1593). Do not include any additional text."
                    # print(reference["ref_link"])
                    related = get_related_cve(reference["ref_link"])
                    # print("related", related)
                    related = ", ".join(related)
                    cnt_related += 1
                    break
                except Exception as e:
                    print(f'error in {key}, {e}')
                    print(e)
                if not related:
                    continue
            
            if True:
                history = []
                # follow the sequence of tasks
                if actors:
                    history.append([actors_q, actors])
                if ttps:
                    history.append([ttps_q, ttps])
                if paths:
                    history.append([paths_q, paths])
                if tool:
                    history.append([tool_q, tool])
                if impact:
                    history.append([impact_q, impact])
                if product and product != "N/A":
                    history.append([product_q, product])
                if cve_id:
                    history.append([cve_id_q, cve_id])
                if related: # missing
                    history.append([related_q, related])
                if cvss:
                    history.append([cvss_q, cvss])
                if migitation:
                    history.append([migitation_q, migitation])
                    
            description = value.get("Description", "")
            ref_desc = reference.get("ref_desc", "")
            
            # construct qa
            data = {
                "instruction": "The following is a CVE case: <description (description of the vulnerability, outlining its impact and type of issue) :>"+description+ "<reference description (a brief summary of the linked content, helping to quickly understand its relevance and purpose regarding the vulnerability) :> "+ref_desc,
                "input": patch_q,                      
                "output": patch,
                "history": history,
                        }
            gathered_data.append(data)
            if len(gathered_data) == 400:
                break
        if len(gathered_data) == 400:
            random.shuffle(gathered_data)
            break
    print("data length", len(gathered_data))
    if not os.path.exists(init_path):
        os.makedirs(init_path)
    train_file_name = os.path.join(init_path, "train_" + file_name)
    test_file_name = os.path.join(init_path, "test_" + file_name)
    with open(train_file_name, 'w') as f:
        json.dump(gathered_data[:200], f, indent=4)
    with open(test_file_name, 'w') as f:
        json.dump(gathered_data[200:400], f, indent=4)
  
# loading data
print("loading data")
cve_details = load_data("data/cve_detail")
cve_references = load_data("data/cve_ref")
print("Number of cve_details: ", len(cve_details))
print("Number of cve_references: ", len(cve_references))

xss_files = [] # Cross site scripting (XSS)
denail_files = [] # Denial of Service (DoS)
execute_files = [] # Execute code

for cve_detail in tqdm(cve_details):
    if cve_detail not in ['2020', '2021', '2022', '2023', '2024']:
        print('skip year', cve_detail)
        continue
    cnt_related = 0
    keys = list(cve_details[cve_detail].keys())
    random.shuffle(keys)
    for key in tqdm(keys):
        value = cve_details[cve_detail][key]
        category = value['Vulnerability Categories']
        if 'Cross site scripting (XSS)' in category:
            xss_files.append(key)
        if 'Denial of service' in category:
            denail_files.append(key)
        if 'Execute code' in category:
            execute_files.append(key)
         
print("Number of xss files: ", len(xss_files))
print("Number of denial files: ", len(denail_files))
print("Number of execute files: ", len(execute_files))
   
print("save xss files")
json_list_to_file(xss_files, 'xss.json')
print("save denial files")
json_list_to_file(denail_files, 'denial.json')
print("save execute files")
json_list_to_file(execute_files, 'execute.json')

# product_files = {}
# product = 'microsoft' 
# # 'oracle', 'apache', 'microsoft', 'linux', 'red hat', 'ubuntu' debian
# p1,p2,p3 = 'windows 10', 'windows 11', 'edge'  
# # windows 10 1192 windows 11 489
# product_files['1'] = []
# product_files['2'] = []
# product_files['3'] = []

# c1,c2,c3 = 'dell', 'opensuse', 'gitlab' 
# # dell 538 opensuse 484 gitlab 1163
# c1_files = []
# c2_files = []
# c3_files = []

# for cve_ref in cve_references:
#     keys = list(cve_references[cve_ref].keys())
#     random.shuffle(keys)
#     for key in tqdm(keys):
#         value = cve_references[cve_ref][key]
#         value_str = json.dumps(value)
#         if product in value_str.lower():
#             if p1 in value_str.lower(): #"openstack",'openshift', 'enterprise linux'
#                 product_files['1'].append(key)
#             if p2 in value_str.lower():
#                 product_files['2'].append(key)
#             if p3 in value_str.lower():
#                 product_files['3'].append(key)
#         if c1 in value_str.lower():
#             c1_files.append(key)
#         if c2 in value_str.lower():
#             c2_files.append(key)
#         if c3 in value_str.lower():
#             c3_files.append(key)

# print(p1, "files: ", len(product_files['1']))
# print(p2, "files: ", len(product_files['2']))
# print(p3, "files: ", len(product_files['3']))
# print(c1, "files: ", len(c1_files))
# print(c2, "files: ", len(c2_files))
# print(c3, "files: ", len(c3_files))

# # save data
# # print(p1)
# # json_list_to_file(product_files['1'], p1+'.json')
# print(p2)
# json_list_to_file(product_files['2'], p2+'.json')
# print(p3)
# json_list_to_file(product_files['3'], p3+'.json')
# print(c1)
# json_list_to_file(c1_files, c1+'.json')
# print(c2)
# json_list_to_file(c2_files, c2+'.json')
# print(c3)
# json_list_to_file(c3_files, c3+'.json')
