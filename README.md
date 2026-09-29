# 🛡️ ZYDER

### Hybrid AI-Driven Network Intrusion Detection System

ZYDER is a hybrid **Network Intrusion Detection System (NIDS)** combining **Machine Learning, Signature-Based Detection, Explainable AI, and Generative AI** for network security analysis.

It uses **XGBoost + Suricata** for hybrid detection, **CICFlowMeter** for network-flow extraction, **SHAP** for explainability, and **Google Gemini** for SOC-oriented incident reports.

> **Current scope:** ZYDER analyzes uploaded `.pcap` and `.pcapng` files. Real-time live traffic monitoring is not currently implemented.

<p align="center">

![Python](https://img.shields.io/badge/Python-3.13.0-3776AB?logo=python\&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688?logo=fastapi\&logoColor=white)
![XGBoost](https://img.shields.io/badge/XGBoost-ML-FF6600)
![Suricata](https://img.shields.io/badge/Suricata-IDS-EF3B2D)
![SHAP](https://img.shields.io/badge/Explainability-SHAP-8A2BE2)
![Gemini](https://img.shields.io/badge/GenAI-Gemini-4285F4)

</p>

---

## ✨ Features

* 🧠 Hybrid Detection — **XGBoost + Suricata**
* 📁 PCAP/PCAPNG Analysis — **CICFlowMeter**
* 🔎 Explainable AI — **SHAP**
* 🤖 AI Incident Reports — **Google Gemini**
* 🖥️ SOC Dashboard — **FastAPI + JavaScript**
* 📊 Security Analytics & Incident Management
* 🧪 ML Training & Evaluation Utilities

---

## 🏗️ Architecture

```mermaid
flowchart TD
    A[PCAP Upload] --> B[Suricata First]
    B --> C[Dataset-Specific Extractor]
    
    C -->|CICIDS| D[CICFlowMeter]
    C -->|UNSW-NB15| E[Zeek + Scapy + State Tracker]
    
    D --> F[Dataset-Specific XGBoost]
    E --> F
    
    F --> G[Hybrid Correlation]
    B --> G
    
    G --> H[SOC Dashboard & Analytics]
    H --> I[SHAP Analysis]
    I --> J[Google Gemini]
    J --> K[SOC Incident Report]
```

---

## 🛠️ Tech Stack

### Core
![Python](https://img.shields.io/badge/Python%203.13-3776AB?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![XGBoost](https://img.shields.io/badge/XGBoost-189C75?style=for-the-badge&logo=xgboost&logoColor=white)
![Scikit-learn](https://img.shields.io/badge/Scikit--learn-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)

### Network Security
![CICFlowMeter](https://img.shields.io/badge/CICFlowMeter-333333?style=for-the-badge)
![Zeek](https://img.shields.io/badge/Zeek-4D9DE0?style=for-the-badge&logo=zeek&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-1679A7?style=for-the-badge&logo=python&logoColor=white)
![Suricata](https://img.shields.io/badge/Suricata-EF3B2D?style=for-the-badge)

### Explainability & GenAI
![SHAP](https://img.shields.io/badge/SHAP-8A2BE2?style=for-the-badge)
![Google Gemini](https://img.shields.io/badge/Gemini-8E75B2?style=for-the-badge&logo=google-gemini&logoColor=white)

### Frontend
![HTML5](https://img.shields.io/badge/HTML5-E34F26?style=for-the-badge&logo=html5&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)
![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-06B6D4?style=for-the-badge&logo=tailwindcss&logoColor=white)
![Chart.js](https://img.shields.io/badge/Chart.js-FF6384?style=for-the-badge&logo=chartdotjs&logoColor=white)

### Datasets
![CICIDS2017](https://img.shields.io/badge/CICIDS2017-111827?style=for-the-badge)
![UNSW-NB15](https://img.shields.io/badge/UNSW--NB15-111827?style=for-the-badge)
## 📂 Project Structure

```text
ZYDER/
├── api.py
├── main.py
├── frontend/
├── detection/
├── preprocessing/
├── explainability/
├── reporting/
├── genai/
├── training/
├── evaluation/
├── models/
├── config/
├── results/
├── requirements.txt
├── README.md
└── SETUP.md
```

Large datasets, PCAP files, virtual environments, generated outputs, and secrets are excluded from Git.

---

## 🚀 Quick Start

### Clone

```bash
git clone https://github.com/Shaurya-Chauhan-16/ZYDER.git
cd ZYDER
```

### Create Environment

```bash
python3.13 -m venv .venv
source .venv/bin/activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Configure Gemini

```bash
export GEMINI_API_KEY="your_api_key"
```

### Start ZYDER

```bash
.venv/bin/python api.py
```

Dashboard:

```text
http://127.0.0.1:8000
```

API Docs:

```text
http://127.0.0.1:8000/docs
```

### 📖 Complete Setup Guide

For complete installation, Suricata setup, datasets, configuration, testing, and troubleshooting:

**→ [Read SETUP.md](SETUP.md)**

---

## 🔬 Detection Pipeline

```text
PCAP / PCAPNG
      ↓
SURICATA (First Layer)
      ↓
DATASET-SPECIFIC FEATURE EXTRACTION
(CICFlowMeter OR Zeek + Scapy + Tracker)
      ↓
DATASET-SPECIFIC XGBOOST
      ↓
SURICATA + ML CORRELATION (Hybrid Verdict)
      ↓
SHAP EXPLAINABILITY
      ↓
GOOGLE GEMINI (SOC Report)
```

---

## 🧠 Explainability

ZYDER uses **SHAP** to identify the features that contribute to an XGBoost prediction, helping analysts understand the reasoning behind ML-based detections.

---

## 🤖 AI Incident Reporting

ZYDER combines available detection evidence including:

* XGBoost prediction
* ML confidence
* Suricata alerts
* SHAP feature contributions
* Network-flow metadata

Google Gemini generates a structured **SOC-oriented incident report** from this evidence.

---

## 🔬 Research

ZYDER explores the combination of:

**Signature Detection + Machine Learning + Explainable AI + Generative AI**

The project features a rigorously audited, mathematically validated native PCAP-to-UNSW-NB15 feature extraction pipeline, bridging the gap between historical dataset ML models and live traffic ingestion.

The project is intended for **network-security research, experimentation, and academic use**.

---

## ⚠️ Limitations

* PCAP/PCAPNG analysis only
* No real-time traffic monitoring
* Suricata & Zeek require separate installations
* **UNSW-NB15 Feature Limitations:** `ct_state_ttl` cannot be perfectly reconstructed from live PCAPs as the original dataset employs an unpublished categorical mapping. UDP packet loss (`sloss`/`dloss`) is identically constrained to 0 as per the original methodology.
* Large datasets are not included
* Gemini reporting requires an API key

---

## 📜 License

MIT License

---

## 👤 Author

**Shaurya Chauhan**


[GitHub](https://github.com/Shaurya-Chauhan-16)
