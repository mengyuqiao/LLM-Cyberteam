import requests
from bs4 import BeautifulSoup
from g4f.client import Client

# load data by year
import os
import json
import pandas as pd
from tqdm import tqdm

# save data
from sklearn.model_selection import train_test_split
def save_json(df, folder, file_name):
    init_path = "data/secure_dataset/"
    if not os.path.exists(init_path+folder):
        os.makedirs(init_path+folder)
    train_df, test_df = train_test_split(df, test_size=0.2, random_state=42)
    save_by_chunk(train_df, os.path.join(folder, "train"), file_name)
    save_by_chunk(test_df, os.path.join(folder, "test"), file_name)

def save_by_chunk(df, folder, file_name):
    init_path = "data/secure_dataset/"
    max_file_size = 100 * 1024 * 1024
    df_json = df.to_json(orient='records')
    total_size = len(df_json.encode('utf-8'))
    folder_path = os.path.join(init_path, folder)
    
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)

    if total_size <= max_file_size:
        file_path = os.path.join(folder_path, f"{file_name}.json")
        print(f"Saving {file_path}")
        # df_json = df.to_json(orient='records')
        with open(file_path, 'w') as f:
            f.write(df_json)
    else:
        chunk_size = len(df) // (total_size // max_file_size + 1)
        for i, chunk in enumerate(range(0, len(df), chunk_size)):
            chunk_file_name = f"{file_name}-{i + 1}.json"
            file_path = os.path.join(folder_path, chunk_file_name)
            chunk_df = df.iloc[chunk:chunk + chunk_size]
            print(f"Chunk Saving {file_path}")
            chunk_df.to_json(file_path, orient='records')
            
def load_data(data_path):
    blank_files = []
    extracted_dataset = {}
    for folders in os.listdir(data_path):
        extracted_data = {}
        for root, _, files in os.walk(os.path.join(data_path, folders)):
            for file in files:
                if file.endswith(".json"):  
                    file_path = os.path.join(root, file)
                    with open(file_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    if type(data) != dict:
                        if len(data) != 0: # data/cve_ref/2024/February/CVE-2024-23553.json blank
                            extracted_data[file] = []
                            for d in data:
                                if type(d) == dict:
                                    extracted_data[file].append(d)
                            data = data[0]
                        else:
                            blank_files.append(file)
                            continue
                    else:
                        extracted_data[file] = data
        extracted_dataset[folders] = extracted_data
        # print(f"Number of {folders}: ", len(extracted_data))
        # print(f"Blank files in {folders}: ", len(blank_files))
    return extracted_dataset

def g4f_generate(prompt):
    client = Client()
    response = None
    for llm in [
        'gpt-4o', # login to continue using
        'gpt-4',
        'blackboxai-pro',
        'blackboxai',
        'gpt-4o-mini',
        
        "gemini-1.5-pro", 
        "gemini-1.5-flash", 
        
        'llama-3.1-405b',
        'llama-3.1-70b',
        'llama-3.1-8b',

        'claude-3.5-sonnet',
    ]:
        print('calling', llm)
        try:
            response = client.chat.completions.create(
                model=llm,
                messages=[
                    {"role": "user", "content":
                    prompt}],
                timeout=60,
                # Add any other necessary parameters
            ).choices[0].message.content.strip()
        except:
            continue
        
        if "Login to continue using" in response:
            print(llm, "Login to continue using")
            continue
        if response is not None and \
            'sorry' not in response and \
            'cannot' not in response  and \
            'rate limit' not in response and \
            "can't" not in response and \
            'not safe' not in response and \
            "don't know" not in response and \
            "403 Forbidden" not in response and \
            'invisible' not in response and \
            'try unlimited chat' not in response and \
            "Login to continue using" not in response and \
            len(response) > 0:
            return response
        else: 
            print('-'*100)
            print(response)
            print('-'*100)
            
    return None


def skip_url(url: str):
    skip_list = [
        "https://helpx.adobe.com/",
        "https://https://jpn.nec.com/",
        "https://support.hcltechsw.com/"
    ]
    for l in skip_list:
        if url.startswith(l):
            return True
        
    return False



def get_related_cve(url):
    # Send a GET request to the URL
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
    }
    response = requests.get(url, headers=headers)
    
    # Parse the HTML content of the page
    html = BeautifulSoup(response.text, 'html.parser')
    
    # Extract all related CVEs
    related_CVEs = set()
    for cve_block in html.find_all('h3', {'data-tsvfield': 'cveId'}):
        related_CVEs.add(cve_block.get_text(strip=True))

    return list(related_CVEs)

    # # Example usage
    # url = "https://www.cvedetails.com/reference-url-info/xCSiEu3wk5DvlJ07SyGYDqO02es.html"
    # get_related_cve(url)


def get_cvss_vector(url):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
    }
    response = requests.get(url, headers=headers)
    html = BeautifulSoup(response.text, 'html.parser')
    
    rst = []
    for cvss_vector in html.find_all('a', {'title': 'Show CVSS vector details'}):
        rst.append(cvss_vector.get_text(strip=True))
        
    if len(rst) == 0:
        print(f"Failed to extract CVSS vector from {url}")
        return None
    return rst[-1]