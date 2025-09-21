### Generate CVE reports for pre-training

import os, json
from utils import g4f_generate

template = """
### **Cyber Threat Report for CVE: [CVE Identifier]**

#### **1. Executive Summary**
- **CVE Identifier:** [CVE-YYYY-NNNN]
- **Severity Rating:** [Low/Medium/High/Critical]
- **Affected Systems:** [List of affected software, hardware, or services]
- **Date of Discovery:** [Date]
- **Threat Actor(s):** [If known, e.g., APT groups or generic attacker profiles]
- **Summary of Impact:** [e.g., Data breach, privilege escalation, remote code execution]
- **Mitigation Summary:** [High-level mitigation guidance]

---

#### **2. Vulnerability Overview**
- **Description:**  
  Provide a detailed explanation of the vulnerability, including its nature, functionality, and how it was discovered.
  
- **Technical Details:**  
  Include specifics such as:
  - Vulnerable component or codebase
  - Exploitation vector (e.g., network, local, physical access)
  - Required privileges or user interaction
  - Dependencies or conditions for exploitation

- **CVE Details:**  
  - **CWE (Common Weakness Enumeration):** [Identifier and description]
  - **CVSS (Common Vulnerability Scoring System):**  
    - **Base Score:** [Score]  
    - **Exploitability Score:** [Score]  
    - **Impact Score:** [Score]  

---

#### **3. Impact Analysis**
- **Potential Impact:**  
  - Confidentiality: [High/Medium/Low]  
  - Integrity: [High/Medium/Low]  
  - Availability: [High/Medium/Low]  
  
- **Real-World Examples (if applicable):**  
  Document any incidents or case studies involving exploitation of this CVE.

- **Threat Landscape:**  
  - Known active exploits or campaigns
  - Likely targets (e.g., industries, regions)

---

#### **4. Mitigation and Remediation**
- **Patches and Updates:**  
  Detail available patches or updates from vendors.

- **Temporary Workarounds:**  
  Provide recommendations for temporary mitigation if patches are unavailable.

- **Best Practices:**  
  - Implement network segmentation
  - Restrict user privileges
  - Monitor system logs for unusual activity

- **Vendor Advisory Links:**  
  - [Vendor Name and URL]

---

#### **5. Exploitation Techniques**
- **Proof of Concept (PoC):**  
  Indicate whether PoC exploit code is publicly available.  
  - **Source:** [GitHub, Pastebin, or other]

- **Attack Vector and Flow:**  
  Diagram or describe the steps attackers use to exploit the vulnerability.

---

#### **6. Detection and Monitoring**
- **Indicators of Compromise (IOCs):**  
  - File hashes
  - Network signatures
  - Malicious IPs or domains

- **Monitoring Recommendations:**  
  - Deploy intrusion detection systems (IDS/IPS)
  - Audit affected systems and applications for anomalies

---

#### **7. Risk Assessment**
- **Likelihood of Exploitation:** [Low/Medium/High]
- **Business Impact:** [Detailed assessment, e.g., financial loss, regulatory consequences]
- **Overall Risk:** [Summary of the likelihood and impact]

---

#### **8. Recommendations and Next Steps**
- Prioritize patching of critical systems.
- Conduct security awareness training for stakeholders.
- Review and update incident response plans.
- Collaborate with external threat intelligence services.

"""

    
for year in [2024]:
    for month in [
        "January", 
    ]:
        for dirpath, dnames, fnames in os.walk(f"./data/cve_ref/{year}/{month}"):
            year, month = dirpath.strip('/').split('/')[-2:]
            if len(dnames) == 0:  # dirt, [], [CVE-XXXX-XXXX.json,]
                for f in fnames:
                    detail_path = f"data/cve_detail/{year}/{month}/{f}"
                    ref_path = os.path.join(dirpath, f)
                    report_path = f"data/cve_report/{year}/{month}/{f.replace('.json', '.txt')}"
                    
                    if not os.path.exists(detail_path):  # crawling not ready 
                        continue
                    if os.path.exists(report_path):      # already generated
                        continue
                      
                    with open(detail_path, 'r') as detail_f:
                        detail_data = json.load(detail_f)
                    with open(ref_path, 'r') as ref_f:
                        ref_data = json.load(ref_f)
                        
                    detail_data["Reference"] = ref_data
                    
                    prompt = f"""
                    
                    ### Role:  
                    You are a cybersecurity professional tasked with creating CVE reports using:  
                    1. A provided **report template** detailing the required sections and fields.  
                    2. A **JSON format CVE details** file containing the necessary information.  

                    ---

                    ### Inputs:  

                    #### (1) Report Template:  
                    {template}  

                    #### (2) JSON Format CVE Details:  
                    {detail_data}  

                    ---

                    ### Task Requirements:  
                    - Extract relevant details from the JSON data to populate the report template.  
                    - Use clear, structured, and professional wording typical of a cybersecurity expert.  
                    - Ensure the report is accurate, complete, and formatted for readability (e.g., tables, bullet points, or sections as appropriate).  
                    - Avoid unnecessary phrases or prefixes like "Sure! Here is."  
                    - Be concise while maintaining the required level of detail.  

                    [Your Response]  

                    """
                    report = g4f_generate(prompt)
                    if len(report) > 200:
                      os.makedirs(os.path.dirname(report_path), exist_ok=True)
                      with open(report_path, "w") as _f:
                          _f.write(report)
                    
                                    