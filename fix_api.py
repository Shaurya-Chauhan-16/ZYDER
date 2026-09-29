import re

with open("api.py", "r") as f:
    content = f.read()

sanitize_func = """
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
"""

# Insert sanitize_func right after imports
import_end = content.find("from explainability.shap_explainer")
if import_end != -1:
    import_end = content.find("\n", import_end) + 1
    content = content[:import_end] + "\n" + sanitize_func + "\n" + content[import_end:]

# Apply sanitize_for_json to the return statement of hybrid_pcap
old_return = """        return {
            "status": "success", 
            "flow_count": len(flows), 
            "total_intrusions": sum(1 for r in results if r["result"]["is_intrusion"]),
            "results": results
        }"""
new_return = """        response_data = {
            "status": "success", 
            "flow_count": len(flows), 
            "total_intrusions": sum(1 for r in results if r["result"]["is_intrusion"]),
            "results": results
        }
        return sanitize_for_json(response_data)"""

content = content.replace(old_return, new_return)

with open("api.py", "w") as f:
    f.write(content)
