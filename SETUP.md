# ZYDER Setup Guide

This guide covers the complete process for installing dependencies, configuring Suricata, setting up datasets and models, running the ZYDER application, testing, and troubleshooting. 

> ZYDER currently analyzes uploaded PCAP/PCAPNG files. Real-time live traffic monitoring is not implemented.

---

## 1. System Requirements

* **Python:** 3.13.0
* **Package Manager:** pip
* **Version Control:** Git
* **Intrusion Detection System:** Suricata (installed system-wide)
* **Flow Extraction:** CICFlowMeter
* **Operating System:** macOS (officially supported; paths in code assume macOS/Homebrew structures). Linux can be supported with manual path adjustments.

---

## 2. Clone the Repository

Clone the project from GitHub and enter the directory:

```bash
git clone https://github.com/Shaurya-Chauhan-16/ZYDER.git
cd ZYDER
```

---

## 3. Python Virtual Environment

ZYDER strictly requires Python 3.13.0. Create and activate a virtual environment:

```bash
python3.13 --version
python3.13 -m venv .venv
source .venv/bin/activate
```

Verify your active environment:

```bash
python --version
```

It should output exactly:
```text
Python 3.13.0
```

---

## 4. Install Python Dependencies

With the virtual environment active, install all dependencies from the `requirements.txt`:

```bash
pip install -r requirements.txt
```

Key dependencies included in this file:
* **cicflowmeter:** Used for translating raw PCAPs into 70+ network flow features.
* **google-genai:** The modern Google SDK used for Gemini reporting (do not use the legacy `google-generativeai`).
* **FastAPI & Uvicorn:** Powers the SOC dashboard and API backend.
* **XGBoost & SHAP:** Machine learning classification and explainable AI logic.
* **Scapy:** Core network packet manipulation (underlying CICFlowMeter).

---

## 5. Verify Python Installation

Run the following quick test to ensure the critical packages imported correctly without missing dependencies:

```bash
python -c "import fastapi, xgboost, shap, cicflowmeter, google.genai, scapy; print('ZYDER Python environment is working perfectly!')"
```

---

# SURICATA

## 6. Install Suricata

Suricata is a system dependency and is **not** installed via `requirements.txt`.

For macOS (via Homebrew):

```bash
brew install suricata
```

Verify the installation:

```bash
suricata --build-info
```

## 7. Configure Suricata

ZYDER expects Suricata to be configured at specific macOS/Homebrew paths. The Python backend (`api.py`) runs the following command during detection:

```bash
suricata -r <pcap_file> -c /opt/homebrew/etc/suricata/suricata.yaml -S /opt/homebrew/etc/suricata/rules/zyder.rules -l /tmp/zyder-api-suricata-...
```

**Configuration requirements:**
1. Your core configuration file must exist at `/opt/homebrew/etc/suricata/suricata.yaml`.
2. Custom rules must be placed at `/opt/homebrew/etc/suricata/rules/zyder.rules`.
3. During PCAP analysis, ZYDER executes Suricata on the uploaded file and stores the output temporarily. ZYDER consumes the generated `eve.json` log to determine signature-based alerts.

---

# ZEEK (For UNSW-NB15 PCAP Support)

## 7.5 Install Zeek

ZYDER requires **Zeek** to natively extract HTTP, FTP, and Connection telemetry required by the UNSW-NB15 machine learning model. (If you only plan to evaluate CICIDS2017, Zeek is not required).

**Install via Homebrew:**

```bash
sudo chown -R $(whoami) /opt/homebrew
brew install zeek
```

**Verify Installation:**

```bash
zeek --version
# Should output: zeek version 5.0.0 or higher
```

The `UNSWFeatureExtractor` automatically searches the system PATH for the `zeek` executable and uses the `tuning/json-logs` policy script to generate the underlying telemetry before applying Scapy timing logic and the 100-connection state tracker.

---

# GEMINI

## 8. Configure Google Gemini

Google Gemini is used to automatically generate SOC-style incident reports based on ML confidence, SHAP explanations, and Suricata alerts.

Export your API key as an environment variable:

```bash
export GEMINI_API_KEY="your_api_key_here"
```

*Note: The `GeminiReporter` class in `reporting/gemini_reporter.py` uses `os.getenv("GEMINI_API_KEY")`. Do **NOT** hardcode or commit this key into any file.*

---

# DATASETS AND MODELS

## 9. Dataset Setup

ZYDER supports the **CICIDS2017** and **UNSW-NB15** datasets. 
The configuration file (`config/config.yaml`) expects datasets to be located within a `Dataset/` folder (e.g., `Dataset/archivecicd/`).

**Important Distinction:**
> **Running the existing trained models ≠ Training models from scratch**

You **do not** need to download these massive datasets just to run the dashboard. The datasets are ONLY required if you plan on re-training the XGBoost models.

## 10. Model Files

The `models/` directory contains pre-trained, production-ready assets:
* `zyder_xgboost_cicids.json` (CICIDS XGBoost Model)
* `zyder_xgboost_unsw.json` (UNSW XGBoost Model)
* `preprocessing_cicids.pkl` & `preprocessing_unsw.pkl` (Scalers/Encoders)
* `label_mapping.json` & `feature_schema.json` (Metadata)

Because these models are already provided, **you do not need to train the models yourself** to run the application.

---

# RUNNING ZYDER

## 11. Start the Application

Start the FastAPI backend and SOC Dashboard using Uvicorn:

```bash
.venv/bin/python api.py
```

Access the application in your browser:
* **Dashboard:** http://127.0.0.1:8000
* **API Documentation:** http://127.0.0.1:8000/docs

## 12. Basic Health Check

To verify ZYDER started successfully:
1. Ensure the terminal output shows `Uvicorn running on http://0.0.0.0:8000`.
2. Open `http://127.0.0.1:8000` — the dark-themed SOC Dashboard should load immediately.
3. Open `http://127.0.0.1:8000/docs` — the Swagger UI should list the `POST /hybrid/pcap` and `POST /report/{detection_id}` routes.

---

# USING ZYDER

## 13. PCAP Analysis Workflow

When a user interacts with the dashboard, the following pipeline occurs:

```text
PCAP/PCAPNG
    ↓
Upload via Dashboard UI
    ↓
Suricata (First Layer)
    ↓
Feature Extraction (CICFlowMeter OR Zeek+Scapy)
    ↓
XGBoost ML Classification
    ↓
Hybrid Detection (Suricata + ML Correlation)
    ↓
SOC Dashboard Rendering
```

* Supported Formats: `.pcap` and `.pcapng`.

## 14. Valid PCAP Testing

**Important:** An HTML file renamed to `.cap` or `.pcap` is **not** a valid PCAP and will crash the flow extractor. 

To safely test the system's Machine Learning detection capabilities, ZYDER includes custom-engineered PCAPs in the `test_pcaps/` directory designed to trigger specific attack classes on both models:
* `ml_test_synflood.pcap`: Triggers CICIDS (DoS) and UNSW (DoS) via massive TCP SYN volume.
* `ml_test_portscan.pcap`: Triggers CICIDS (PortScan) and UNSW (Reconnaissance) via sequential rapid port access.
* `ml_test_http_exploit.pcap`: Triggers CICIDS (Web Attack) and UNSW (Exploits) via fragmented oversized POST payloads.

You can also generate a minimal benign PCAP for baseline testing:
```bash
.venv/bin/python create_real_pcap.py
```

---

# ML / SHAP / REPORTING

## 15. Machine Learning Detection
ZYDER uses an XGBoost tree-based classifier to analyze network flows. 
* The preprocessing pipeline maps raw CICFlowMeter data into 70+ specific numerical features.
* The model evaluates these features and returns a prediction (`BENIGN` or an attack class) alongside a confidence probability.
* Models are loaded directly from the `models/` directory.

## 16. SHAP Explainability
When an intrusion is detected, you can click "View Report" in the dashboard. This triggers SHAP (SHapley Additive exPlanations) to dynamically evaluate the specific network flow and identify precisely which features (e.g., Destination Port, Flow Duration) most heavily influenced the ML model's decision. 

## 17. Gemini Incident Reports

```text
Detection
   ↓
Detection Evidence
   ↓
SHAP Feature Importance
   ↓
Gemini AI Prompt
   ↓
SOC Incident Report
```
The report generation is triggered manually on-demand via the dashboard UI, calling the `POST /report/{detection_id}` endpoint.

---

# TRAINING AND EVALUATION

*Note: These steps require downloading the full datasets.*

## 18. Training Models
To train models from scratch, use the `main.py` CLI:

* Train on CICIDS: `.venv/bin/python main.py train --dataset cicids`
* Train on UNSW: `.venv/bin/python main.py train --dataset unsw`

These commands read the raw dataset CSVs, train XGBoost, and output the resulting `.json` models into the `models/` directory.

## 19. Evaluation
To evaluate existing models against test data:

* `.venv/bin/python main.py evaluate --dataset cicids`

This measures Accuracy, Precision, Recall, F1 Score, and generates Confusion Matrix / ROC curve plots in the `outputs/` directory.

---

# TROUBLESHOOTING

## 20. Common Problems

### `ModuleNotFoundError: No module named 'cicflowmeter'`
Ensure your virtual environment is activated. If it persists, install it manually:
```bash
.venv/bin/python -m pip install cicflowmeter
```

### Gemini import errors
Ensure you have `google-genai` installed, not `google-generativeai`. Check your `.venv`:
```bash
.venv/bin/python -m pip show google-genai
```

### Invalid PCAP (`Not a supported capture file`)
If you upload an invalid file (e.g., HTML text downloaded via `curl`), CICFlowMeter will fail. Ensure you are uploading a genuine binary packet capture. Use `create_real_pcap.py` to test.

### JSON serialization errors
Previously, XGBoost and CICFlowMeter produced NumPy integers (`np.int64`) that crashed FastAPI's JSON response. The current `api.py` includes a `sanitize_for_json` function to seamlessly clean these types before returning them.

### Suricata not found
Verify Suricata is installed globally and added to your system PATH:
```bash
suricata --build-info
which suricata
```

### Gemini API key missing
Verify the environment variable is loaded in your shell without echoing it directly:
```bash
printenv | grep GEMINI
```

### Port 8000 already in use
If another process is using port 8000, find it using `lsof -i :8000` and kill it, or modify the final line of `api.py` to bind to a different port (e.g., `port=8080`).

---

# SECURITY

## 21. Security and Secrets

* **Never commit API keys** to GitHub.
* **Never commit `.env`** files.
* **Never commit private PCAPs** containing sensitive network traffic.
* **Never commit `.venv`** directories.
* **Large datasets** must remain outside Git (they are included in `.gitignore`).
* **Only analyze traffic** that you are legally authorized to inspect.

---

# PROJECT LIMITATIONS

## 22. Current Limitations

* ZYDER currently only supports offline PCAP/PCAPNG file analysis. 
* There is no real-time live traffic interface or network sniffing implemented in the web application.
* Suricata is a hard-coded macOS system dependency expecting specific paths.
* Automated incident reporting requires a valid Google Gemini API key.

---

# FINAL VERIFICATION

## 23. Installation Verification Checklist

```text
[ ] Python 3.13.0 installed
[ ] Virtual environment created
[ ] requirements.txt installed
[ ] CICFlowMeter working
[ ] Suricata installed
[ ] Suricata configuration working\n[ ] Zeek installed (Optional: for UNSW)
[ ] Gemini API key configured
[ ] Models available
[ ] FastAPI starts
[ ] Dashboard loads
[ ] /docs loads
[ ] Valid PCAP successfully analyzed
[ ] Hybrid detection works
[ ] SHAP explanation works
[ ] Gemini report generation works
```
