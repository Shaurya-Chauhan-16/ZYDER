import subprocess
import tempfile
import shutil
from pathlib import Path
import json
import logging

logger = logging.getLogger("zyder.detection.zeek")

class ZeekUNSWBackend:
    """
    Safely executes Zeek against a PCAP to generate structured logs.
    """
    def __init__(self):
        self.zeek_path = shutil.which("zeek")
        
    def is_installed(self) -> bool:
        return self.zeek_path is not None

    def execute(self, pcap_path: str | Path) -> dict:
        if not self.is_installed():
            raise RuntimeError(
                "Zeek is not installed or not in PATH. "
                "For macOS Apple Silicon, install via: brew install zeek"
            )
            
        pcap_path = Path(pcap_path).resolve()
        if not pcap_path.exists():
            raise FileNotFoundError(f"PCAP not found: {pcap_path}")

        with tempfile.TemporaryDirectory(prefix="zyder-zeek-") as tmp:
            tmp_dir = Path(tmp)
            
            # Run zeek with JSON logging enabled
            cmd = [
                self.zeek_path, 
                "-C",  # Ignore invalid checksums
                "-r", str(pcap_path),
                "tuning/json-logs"
            ]
            
            try:
                # Timeout of 120s to prevent hanging on malformed PCAPs
                res = subprocess.run(cmd, cwd=str(tmp_dir), capture_output=True, text=True, timeout=120)
                if res.returncode != 0:
                    logger.error(f"Zeek execution failed: {res.stderr}")
                    raise RuntimeError("Zeek failed to process the PCAP.")
            except subprocess.TimeoutExpired:
                raise RuntimeError("Zeek execution timed out after 120 seconds.")

            logs = {}
            for log_file in tmp_dir.glob("*.log"):
                log_name = log_file.stem
                parsed = []
                with open(log_file, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                parsed.append(json.loads(line))
                            except json.JSONDecodeError:
                                pass
                logs[log_name] = parsed
                
            return logs
