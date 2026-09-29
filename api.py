import os
import json
import uuid
import tempfile
import subprocess
from pathlib import Path
from fastapi import FastAPI, File, UploadFile, HTTPException, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Dict, Any, List

# Import ZYDER modules
from main import load_config, get_detection_threshold, PROJECT_ROOT
from detection.detector import ZyderMLDetector
from detection.pcap_pipeline import extract_cicids_flows
from detection.suricata_detector import SuricataDetector
from detection.hybrid_detector import HybridDetector
from explainability.shap_explainer import ZyderSHAPExplainer


import numpy as np

def sanitize_for_json(obj):
    if isinstance(obj, dict):
        return {k: sanitize_for_json(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [sanitize_for_json(v) for v in obj]
    elif isinstance(obj, (np.integer, np.int64, np.int32)):
        return int(obj)
    elif isinstance(obj, (np.floating, np.float64, np.float32)):
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return sanitize_for_json(obj.tolist())
    elif isinstance(obj, np.bool_):
        return bool(obj)
    return obj

from reporting.gemini_reporter import IncidentReport, GeminiReporter

app = FastAPI(title="ZYDER Backend API", description="API for ZYDER Network Intrusion Detection System")

# In-memory store for detection results
# detection_id -> {"hybrid_result": HybridResult, "flow": Dict, "dataset": str}
detection_store = {}
pcap_store = {}


# Allow CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class FlowRequest(BaseModel):
    dataset: str = "cicids"
    flow: Dict[str, Any]

@app.post("/predict")
async def predict_flow(request: FlowRequest):
    """Run ML-only prediction on a single JSON flow."""
    config = load_config("config/config.yaml")
    threshold = get_detection_threshold(config, request.dataset)

    try:
        detector = ZyderMLDetector(
            model_dir=config["paths"]["models_dir"],
            dataset=request.dataset,
            threshold=threshold,
            base_dir=PROJECT_ROOT,
        )
        detector.load()
        result = detector.predict(request.flow)
        
        return {
            "status": "success", 
            "result": result.to_dict() if hasattr(result, 'to_dict') else {
                "is_intrusion": result.is_intrusion,
                "confidence": getattr(result, 'confidence', 0.0)
            }
        }
    except Exception as e:
        err_msg = str(e)
        if "Not a supported capture file" in err_msg:
            raise HTTPException(status_code=400, detail="Invalid PCAP file format. Please upload a valid .pcap or .pcapng file.")
        raise HTTPException(status_code=500, detail=err_msg)

@app.post("/explain")
async def explain_flow(request: FlowRequest):
    """Generate SHAP explanation for a single JSON flow."""
    config = load_config("config/config.yaml")
    threshold = get_detection_threshold(config, request.dataset)
    
    try:
        detector = ZyderMLDetector(
            model_dir=config["paths"]["models_dir"],
            dataset=request.dataset,
            threshold=threshold,
            base_dir=PROJECT_ROOT,
        )
        detector.load()
        features = detector._prepare_features(request.flow)
        
        explainer = ZyderSHAPExplainer(
            model=detector.get_model(),
            feature_names=detector.get_feature_names(),
        )
        explanation = explainer.explain_single(features, threshold=threshold)
        
        return {
            "status": "success", 
            "explanation": {
                "base_value": float(explanation.base_value),
                "prediction": float(explanation.prediction),
                "is_intrusion": bool(explanation.is_intrusion),
                "top_features": explanation.top_features
            }
        }
    except Exception as e:
        err_msg = str(e)
        if "Not a supported capture file" in err_msg:
            raise HTTPException(status_code=400, detail="Invalid PCAP file format. Please upload a valid .pcap or .pcapng file.")
        raise HTTPException(status_code=500, detail=err_msg)

@app.post("/hybrid/pcap")
def hybrid_pcap(dataset: str = Form(...), file: UploadFile = File(...)):
    """Run full Hybrid (ML + Suricata) detection on an uploaded PCAP file."""
    if dataset not in ("cicids", "unsw"):
        raise HTTPException(status_code=400, detail="Invalid dataset specified.")
        
    config = load_config("config/config.yaml")
    threshold = get_detection_threshold(config, dataset)
    
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        tmp.write(file.file.read())
        pcap_path = tmp.name

    try:
        # STEP 1: Run Suricata FIRST
        suricata_output = Path(tempfile.mkdtemp(prefix="zyder-api-suricata-"))
        suricata_config = "/opt/homebrew/etc/suricata/suricata.yaml"
        zyder_rules = "/opt/homebrew/etc/suricata/rules/zyder.rules"
        
        import subprocess
        subprocess.run(
            ["suricata", "-r", pcap_path, "-c", suricata_config, "-S", zyder_rules, "-k", "none", "-l", str(suricata_output)],
            check=False, capture_output=True, text=True
        )
        
        eve_log = suricata_output / "eve.json"
        if not eve_log.exists():
            with open(eve_log, "w") as f: f.write("")
            
        # Parse Suricata results into memory
        from detection.suricata_detector import SuricataDetector
        sig_detector = SuricataDetector(str(eve_log))
        
        # STEP 2: Independently extract ML features
        from detection.pcap_pipeline import get_feature_extractor
        extractor = get_feature_extractor(dataset)
        flows = extractor.extract_features(pcap_path)
        
        if not flows:
            raise HTTPException(status_code=400, detail="No network flows were extracted from the PCAP.")
            
        # STEP 3: Load dataset-specific ML model
        ml_detector = ZyderMLDetector(
            model_dir=config["paths"]["models_dir"],
            dataset=dataset,
            threshold=threshold,
            base_dir=PROJECT_ROOT,
        )
        ml_detector.load()
        
        # STEP 4: Correlation / Hybrid Engine
        from detection.hybrid_detector import HybridDetector
        import uuid
        hybrid_detector = HybridDetector(ml_detector, sig_detector)
        
        results = []
        for flow in flows:
            # Detect runs ML and checks the pre-parsed Suricata results
            result = hybrid_detector.detect(flow)
            
            detection_id = f"det-{uuid.uuid4().hex[:8]}"
            
            if result.is_intrusion:
                detection_store[detection_id] = {
                    "hybrid_result": result,
                    "flow": flow,
                    "dataset": dataset,
                }
            
            severity = "LOW"
            signature_str = ""
            if result.is_intrusion:
                if result.signature_result and result.signature_result.severity and result.signature_result.severity != "NONE":
                    severity = result.signature_result.severity.upper()
                    signature_str = result.signature_result.matched_rules[0] if result.signature_result.matched_rules else ""
                else:
                    conf = result.ml_result.attack_probability
                    if conf >= 0.95: severity = "CRITICAL"
                    elif conf >= 0.85: severity = "HIGH"
                    elif conf >= 0.70: severity = "MEDIUM"
            
            res_dict = {
                "detection_id": detection_id,
                "is_intrusion": result.is_intrusion,
                "final_verdict": result.final_verdict,
                "triggered_by": result.triggered_by,
                "severity": severity,
                "ml_result": {
                    "verdict": "ATTACK" if result.ml_result.is_intrusion else "BENIGN",
                    "prediction": result.ml_result.prediction,
                    "confidence": result.ml_result.attack_probability
                },
                "suricata_result": {
                    "verdict": "ALERT" if result.signature_result and result.signature_result.is_intrusion else "BENIGN",
                    "signature": signature_str,
                    "severity": result.signature_result.severity if result.signature_result else "NONE"
                },
                "ml_prediction": result.ml_result.prediction, # kept for backward compatibility
                "ml_confidence": result.ml_result.attack_probability, # kept for backward compatibility
                "signature": signature_str, # kept for backward compatibility
                "timestamp": getattr(result, "timestamp", ""),
                "src_ip": flow.get("src_ip", flow.get("source_ip", "")),
                "dst_ip": flow.get("dst_ip", flow.get("destination_ip", "")),
                "src_port": flow.get("src_port", flow.get("source_port", "")),
                "dst_port": flow.get("dst_port", flow.get("destination_port", "")),
                "protocol": flow.get("protocol", ""),
                "flow_timestamp": flow.get("timestamp", ""),
            }
            
            results.append({
                "flow": flow,
                "result": res_dict
            })
            
        analysis_id = f"pcap-{uuid.uuid4().hex[:8]}"
        response_data = {
            "status": "success", 
            "analysis_id": analysis_id,
            "flow_count": len(flows), 
            "total_intrusions": sum(1 for r in results if r["result"]["is_intrusion"]),
            "results": results
        }
        pcap_store[analysis_id] = {
            "analysis_id": analysis_id,
            "dataset": dataset,
            "flow_count": len(flows),
            "total_intrusions": response_data["total_intrusions"],
            "ml_only": sum(1 for r in results if r["result"]["triggered_by"] == "ML"),
            "sig_only": sum(1 for r in results if r["result"]["triggered_by"] == "SIGNATURE"),
            "hybrid": sum(1 for r in results if r["result"]["triggered_by"] in ("BOTH", "HYBRID"))
        }
        return sanitize_for_json(response_data)
        
    except Exception as e:
        err_msg = str(e)
        if "Not a supported capture file" in err_msg:
            raise HTTPException(status_code=400, detail="Invalid PCAP file format. Please upload a valid .pcap or .pcapng file.")
        raise HTTPException(status_code=500, detail=err_msg)
    finally:
        if os.path.exists(pcap_path):
            os.remove(pcap_path)

@app.post("/report/{detection_id}")
def generate_report(detection_id: str):
    if detection_id not in detection_store:
        raise HTTPException(status_code=404, detail="Detection not found or expired.")
        
    store_item = detection_store[detection_id]
    hybrid_result = store_item["hybrid_result"]
    flow = store_item["flow"]
    dataset = store_item["dataset"]
    
    config = load_config("config/config.yaml")
    threshold = get_detection_threshold(config, dataset)
    
    try:
        # Load ML detector for SHAP
        ml_detector = ZyderMLDetector(
            model_dir=config["paths"]["models_dir"],
            dataset=dataset,
            threshold=threshold,
            base_dir=PROJECT_ROOT,
        )
        ml_detector.load()
        
        # Calculate SHAP for this specific flow
        features = ml_detector._prepare_features(flow)
        explainer = ZyderSHAPExplainer(
            model=ml_detector.get_model(),
            feature_names=ml_detector.get_feature_names(),
        )
        shap_explanation = explainer.explain_single(features, threshold=threshold)
        
        # Build Incident Report
        incident = IncidentReport.from_hybrid_result(
            hybrid_result=hybrid_result,
            flow=flow,
            shap_features=shap_explanation.top_features
        )
        
        # Run Gemini
        reporter = GeminiReporter()
        if not reporter.api_key:
            raise HTTPException(status_code=500, detail="GEMINI_API_KEY is not set on the server.")
            
        gemini_text = reporter.generate_report(incident)
        
        # Construct exact JSON expected by the frontend
        response = {
            "detection_id": detection_id,
            "incident": {
                "timestamp": incident.timestamp,
                "src_ip": incident.src_ip,
                "dst_ip": incident.dst_ip,
                "src_port": incident.src_port,
                "dst_port": incident.dst_port,
                "protocol": incident.protocol,
                "severity": incident.severity,
                "triggered_by": incident.triggered_by
            },
            "ml_analysis": {
                "prediction": incident.ml_prediction,
                "confidence": incident.ml_confidence
            },
            "signature_analysis": {
                "matched": bool(hybrid_result.signature_result and hybrid_result.signature_result.is_intrusion),
                "signature": hybrid_result.signature_result.matched_rules[0] if hybrid_result.signature_result and hybrid_result.signature_result.matched_rules else "None",
                "severity": hybrid_result.signature_result.severity if hybrid_result.signature_result else "NONE"
            },
            "shap_features": incident.top_shap_features,
            "gemini_report": gemini_text
        }
        
        return sanitize_for_json(response)
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")

# Serve frontend dashboard

@app.post("/report/pcap/{analysis_id}")
def generate_pcap_report(analysis_id: str):
    if analysis_id not in pcap_store:
        raise HTTPException(status_code=404, detail="PCAP analysis not found or expired.")
        
    store_item = pcap_store[analysis_id]
    
    try:
        from reporting.gemini_reporter import GeminiReporter
        reporter = GeminiReporter()
        
        # If API key is not set, it will fallback inside generate_pcap_report
        gemini_text = reporter.generate_pcap_report(store_item)
        
        response = {
            "analysis_id": analysis_id,
            "summary": store_item,
            "gemini_report": gemini_text
        }
        
        return sanitize_for_json(response)
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"PCAP report generation failed: {str(e)}")

app.mount("/static", StaticFiles(directory="frontend"), name="static")

@app.get("/")
async def root():
    return HTMLResponse(content=open("frontend/index.html", "r").read(), status_code=200)

if __name__ == "__main__":
    import uvicorn
    # Start the server with: python api.py
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)
