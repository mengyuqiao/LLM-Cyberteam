# 🛡️ CYBERTEAM: Benchmarking LLM-Assisted Blue Teaming via Standardized Threat Hunting

> A Unified Framework for Large Language Model-Driven Cyber Threat Intelligence (CTI) Collaboration and Analysis
> This repository accompanies our ICLR 2026 paper:  
> **"Benchmarking LLM-Assisted Blue Teaming via Standardized Threat Hunting"**

## 🔍 Overview

`LLM-Cyberteam` explores the synergy between **Large Language Models (LLMs)** and **human-machine cyber defense collaboration**, with a particular focus on enabling **multi-agent CTI analysis**, **evidence collection**, **threat attribution**, and **automated prioritization/remediation planning** in realistic cybersecurity scenarios.

This repository provides code, data, and case studies to support research in:

- 🧠 Multi-agent LLM collaboration for CTI
- 🔗 Chain-of-Thought evidence reasoning
- 🧩 Structured context construction from noisy CTI artifacts
- 🔍 Failure mode discovery and analysis
- 🛡️ Threat remediation and decision-making


---

## 🧠 Motivation

While LLMs have shown promise in individual CTI tasks (e.g., CVE summarization, TTP detection), real-world cyber operations require **collaborative reasoning**, structured evidence retrieval, and continuous prioritization.  
`LLM-Cyberteam` simulates and analyzes how LLMs can serve as **autonomous agents** or **copilots** in cyber defense settings.

---

## 📁 Modules

| Module | Description |
|--------|-------------|
| `__pycache__/` | Python bytecode cache |
| `crawl/` | Scripts for retrieving CVE, vendor, and dark web threat reports |
| `data/` | Structured CTI benchmark datasets (e.g., MITRE, EPSS, ATT&CK) |
| `data_code/` | Data processing scripts for transforming raw threat intelligence |
| `epss_prediction/` | EPSS score prediction based on structured evidence |
| `har_and_cookies/` | Browser-based threat simulation: HTTP request artifacts |
| `keyword_match_cvss/` | CVSS keyword rules for severity extraction |
| `src/` | Core pipeline: context synthesis and LLM-based reasoning |


---

## 🧪 Tasks Supported

- [x] Threat Entity Linking (CVE ↔ ATT&CK ↔ CPE)
- [x] Contextual Evidence Grounding
- [x] Exploitability Forecasting (EPSS)
- [x] Chain-of-Thought Generation
- [x] Failure Mode Analysis (R1–R5)
- [x] LLM-Aided Prioritization
- [x] Remediation Plan Drafting

---

## 🧪 Pipeline Example

```bash
# Example: Run end-to-end CVE reasoning with CoT and EPSS prediction
python src/run_pipeline.py \
    --query "CVE-2023-34362" \
    --model "gpt-4" \
    --steps "evidence_retrieval,context_building,CoT_reasoning,epss_prediction" \
    --verbose
```


---

## 🧨 Failure Modes (R1–R5)

| Failure Code | Failure Type         | Description                                                     |
|--------------|----------------------|-----------------------------------------------------------------|
| R1           | Misattribution       | Incorrect assignment of threat entities or references          |
| R2           | Missing Context      | Omission of key evidence or improper grounding                  |
| R3           | Spurious Correlation | Incorrect reasoning steps based on misleading context          |
| R4           | Prioritization Error | Failure to rank high-risk threats appropriately                 |
| R5           | Remediation Gaps     | Recommendations that are too vague or impractical              |


---

---

## 📁 Dataset

We include:

- ✅ **Human-annotated CTI samples**  
  Ground-truth examples for model evaluation and training.

- ✅ **CTI failure type taxonomy**  
  Covers misattribution, missing context, prioritization error, and more (R1–R5).

- ✅ **CoT-augmented examples for CVE analysis**  
  Multi-hop reasoning traces based on real-world CVEs.

- ✅ **Mapping to MITRE ATT&CK, EPSS scores, and vendor intel**  
  Structured knowledge aligned with external threat intelligence sources.

---

## ✏️ Citation

> Coming soon – we are preparing a paper submission (ICLR/USENIX Security)

If you find this project helpful, please consider citing us. Citation formats will be updated upon preprint release.

---

## 🧩 Related Projects

- [**LLM-CTI**](https://github.com/mengyuqiao/LLM-CTI):  
  Prompt-level evaluations of LLMs on CTI tasks with failure analysis.

- [**CTIBench**](https://github.com/alaminopu/CTIBench):  
  Benchmarking LLM performance across a variety of cyber intelligence challenges.


---

## 🛡️ License

This project is licensed under the [MIT License](LICENSE).
