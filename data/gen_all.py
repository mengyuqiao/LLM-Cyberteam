from utils import get_related_cve, load_data, get_cvss_vector
import os
from sklearn.model_selection import train_test_split
from tqdm import tqdm
import pandas as pd
from utils import get_related_cve
import random

def save_json(df, file_name):
    init_path = "data/secure_whole/"
    if not os.path.exists(init_path):
        os.makedirs(init_path)
    save_by_chunk(df, file_name)

def save_by_chunk(df, file_name):
    init_path = "data/secure_whole/"
    max_file_size = 100 * 1024 * 1024
    df_json = df.to_json(orient='records')
    total_size = len(df_json.encode('utf-8'))
    
    if not os.path.exists(init_path):
        os.makedirs(init_path)

    if total_size <= max_file_size:
        file_path = os.path.join(init_path, f"{file_name}.json")
        print(f"Saving {file_path}")
        df_json = df.to_json(orient='records')
        with open(file_path, 'w') as f:
            f.write(df_json)
    else:
        chunk_size = len(df) // (total_size // max_file_size + 1)
        for i, chunk in enumerate(range(0, len(df), chunk_size)):
            chunk_file_name = f"{file_name}-{i + 1}.json"
            file_path = os.path.join(init_path, chunk_file_name)
            chunk_df = df.iloc[chunk:chunk + chunk_size]
            print(f"Chunk Saving {file_path}")
            chunk_df.to_json(file_path, orient='records')
            
cve_details = load_data("data/cve_detail")
cve_references = load_data("data/cve_ref")
print("Number of cve_details: ", len(cve_details))
print("Number of cve_references: ", len(cve_references))

random.seed(42)
gathered_data = []
for cve_detail in cve_details:
    if cve_detail == "2024":
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
        cnt_related = 0
        round_cnt = 0
        keys = list(cve_details[cve_detail].keys())
        random.shuffle(keys)
        for key in tqdm(keys):
            value = cve_details[cve_detail][key]
            # task2
            product_q = "Based on these information, what are the affected products for this vulnerability?"
            product = value.get("Affected Products", "")
            # task 3
            cve_id_q = "Based on these information, what is the CVE-ID for this vulnerability?"
            cve_id = value.get("CVE Code", "")
            # task 5
            cvss_url = "https://www.cvedetails.com/cve/"+value["CVE Code"]+"/"
            cvss = get_cvss_vector(cvss_url)
            if not cvss:
                print("None",key)
                continue
            if "AV" not in cvss:
                print("---",key,cvss)
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
                            cvss[cvss.index(var)] = "Access     Vector: " + av_mapping[pair[1]]
                        except Exception as e:
                            print(f'AV error in {key}, {pair}, {e}')
                        flag = False
                        continue
                    try:
                        cvss[cvss.index(var)] = pre_mapping [pair[0]] + ": " + after_mapping[pair[1]]
                    except Exception as e:
                        print(f'error in {key}, {pair}, {e}')
            cvss_q = "Based on this information, determine the CVSS vector for this vulnerability by evaluating the following aspects: Assess Vector (Local, Adjacent Network, Network, Physical), Access Complexity, Authentication, Confidentiality (VC), Integrity (VI), Privileges Required, User Interaction, Scope, and their corresponding values (e.g., High, Medium, Low, None, Unchanged, Required, Complete, Partial, Single). Provide the response strictly in the format: 'aspect: value, aspect: value, ...' (e.g., Access Vector: Network, Access Complexity: Medium, Authentication: None, Confidentiality Impact: Partial, Integrity Impact: Partial, Availability Impact: Partial), without including any additional information."
            cvss = ", ".join([i for i in cvss])
            # only using the first cve_ref
            cve_ref = cve_references[cve_detail].get(key)    
            for reference in cve_ref:
                # print("inp",reference)
                if not reference['ref_summary']:
                    continue
                actors_q = "Based on these information, who are the threat actors likely to be involved in exploiting this vulnerability?"
                actors = reference["ref_summary"].get("Threat Actors", "")
                ttps_q = "Based on this information, what specific TTPs (Tactics, Techniques, and Procedures) might adversaries exploit in relation to this vulnerability?"
                ttps = reference["ref_summary"].get("TTPs", "")
                paths_q = "Based on these information, what are the exploit paths for this vulnerability?"
                paths = reference["ref_summary"].get("Exploit Paths", "")
                # task2
                tool_q = "Based on these information, what are the corresponding infrastructure and tools for this vulnerability?"
                tool = reference["ref_summary"].get("Infrastructure and Tools", "")
                impact_q = "Based on these information, what are the potential impacts of this vulnerability?"
                impact = reference["ref_summary"].get("Impacts", "")
                # task 6
                migitation_q = "Based on these information, what are the mitigation strategies for this vulnerability?"
                migitation = reference["ref_summary"].get("Mitigation", "")
                patch_q = "Based on these information, , what patches are available to address this vulnerability?"
                patch = reference["ref_summary"].get("Patch", "")
                try:
                    # task 4
                    related_q = "Based on the provided information, identify the related CVE-ID for the described vulnerability. Ensure that the output includes only the CVE-ID in the exact format CVE-year-code (e.g., CVE-2001-1593). Do not include any additional text."
                    # print(reference["ref_link"])
                    related = get_related_cve(reference["ref_link"])
                    # print("related", related)
                    related = ", ".join(related)
                    cnt_related += 1
                    break
                except Exception as e:
                    print(f'error in {key}, {reference}')
                    print(e)
                if not related:
                    continue
                
            if True:
                history = []
                # follow the sequence of tasks
                if actors:
                    # print("add actor")
                    history.append([actors_q, actors])
                if ttps:
                    # print("add ttps")
                    history.append([ttps_q, ttps])
                if paths:
                    # print("add paths")
                    history.append([paths_q, paths])
                if tool:
                    # print("add tool")
                    history.append([tool_q, tool])
                if impact:
                    # print("add impact")
                    history.append([impact_q, impact])
                if product and product != "N/A":
                    # print("add product")
                    history.append([product_q, product])
                if cve_id:
                    # print("add cve_id")
                    history.append([cve_id_q, cve_id])
                if related:
                    print("add related")
                    history.append([related_q, related])
                if cvss:
                    # print("add cvss")
                    history.append([cvss_q, cvss])
                if migitation:
                    # print("add migitation") 
                    history.append([migitation_q, migitation])
                # if patch:
                #     print("add patch")
                #     history.append([patch_q, patch])
            
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
            if len(gathered_data) % 200 == 0:
                round_cnt += 1
                save_json(pd.DataFrame(gathered_data), "2024"+"-"+str(round_cnt))
                gathered_data = []
        print("cnt_related", cnt_related)
if gathered_data:
    round_cnt += 1 
    save_json(pd.DataFrame(gathered_data), "2024"+"-"+str(round_cnt))