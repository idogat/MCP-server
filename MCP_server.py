from mcp.server.fastmcp import FastMCP
from AnomalyLoader import AnomalyLoader
import pandas as pd
import json
from pathlib import Path
import os

mcp = FastMCP("forensics-mcp")

# -------------------------
# TOOL 1: List anomalies
# -------------------------
@mcp.tool()
def list_anomalies(base_dir: str = "."):
    """
    List anomalies from the investigation directory:
    - anomalies/ folder (manual analyst notes)
    - ioc/ folder (IOCs)
    - reports/ folder (PDFs)

    Returns anomalies grouped with their source type.
    """
    loader = AnomalyLoader(base_dir)
    anomalies = loader.load()

    results = []

    # manual anomalies
    for idx, a in enumerate(anomalies["anomalies"].get("manual", [])):
        results.append({"id": f"manual_{idx}", "query": a, "source": "manual"})

    # IOC anomalies
    for idx, a in enumerate(anomalies["anomalies"].get("ioc", [])):
        results.append({"id": f"ioc_{idx}", "query": a, "source": "ioc"})

    # Reports (PDF)
    reports = loader._load_reports(loader.base_dir / "reports")
    for idx, a in enumerate(reports["file"]):
        results.append({"id": f"report_file_{idx}", "query": a, "source": "report"})
    for idx, a in enumerate(reports["network"]):
        results.append({"id": f"report_net_{idx}", "query": a, "source": "report"})
    for idx, a in enumerate(reports["hash"]):
        results.append({"id": f"report_hash_{idx}", "query": a, "source": "report"})

    return {"success": True, "anomalies": results}


# -------------------------
# TOOL 2: Search anomalies
# -------------------------
@mcp.tool()
def search_anomalies(base_dir: str, anomalies: list, artifact_types: list = None, max_results: int = 50):
    """
    Search anomalies inside artifacts (CSV, JSON, TXT).
    - base_dir: Path to investigation folder containing artifacts.
    - anomalies: List of anomalies (strings or dicts with 'query').
    - artifact_types: Optional filter for artifact filenames (e.g. ["MFT.csv", "EVTX.csv"]).
    - max_results: Limit results per anomaly per file.
    """
    base_path = Path(base_dir)
    if not base_path.exists():
        return {"success": False, "error": f"Base dir not found: {base_dir}"}

    results = []

    # Collect artifact files
    artifact_files = []
    artifact_files.extend(base_path.rglob("*.csv"))
    artifact_files.extend(base_path.rglob("*.json"))
    artifact_files.extend(base_path.rglob("*.txt"))

    if artifact_types:
        artifact_files = [f for f in artifact_files if f.name in artifact_types]

    for anomaly in anomalies:
        if isinstance(anomaly, str):
            query = anomaly
            anomaly_id = None
        elif isinstance(anomaly, dict):
            query = anomaly.get("query")
            anomaly_id = anomaly.get("id")
        else:
            continue

        if not query:
            continue

        for artifact in artifact_files:
            try:
                matches = []

                # CSV search
                if artifact.suffix.lower() == ".csv":
                    df = pd.read_csv(artifact, low_memory=False)
                    mask = df.astype(str).apply(lambda col: col.str.contains(query, case=False, na=False))
                    found = df[mask.any(axis=1)]
                    if not found.empty:
                        matches = found.head(max_results).to_dict(orient="records")

                # JSON search
                elif artifact.suffix.lower() == ".json":
                    with open(artifact, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    text = json.dumps(data)
                    if query.lower() in text.lower():
                        matches = [f"Match found in {artifact.name}"]

                # TXT search
                elif artifact.suffix.lower() == ".txt":
                    with open(artifact, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                    for idx, line in enumerate(lines):
                        if query.lower() in line.lower():
                            matches.append({"line": idx + 1, "content": line.strip()})
                            if len(matches) >= max_results:
                                break

                if matches:
                    results.append({
                        "anomaly_id": anomaly_id,
                        "query": query,
                        "artifact": str(artifact),
                        "matches": matches
                    })

            except Exception as e:
                results.append({
                    "anomaly_id": anomaly_id,
                    "query": query,
                    "artifact": str(artifact),
                    "error": str(e)
                })

    return {"success": True, "results": results}


# -------------------------
# TOOL 3: List artifacts
# -------------------------
@mcp.tool()
def list_artifacts(base_dir: str = "."):
    """
    List all artifact files available in the investigation directory.
    Returns name, size, and last modified timestamp.
    """
    base_path = Path(base_dir)
    if not base_path.exists():
        return {"success": False, "error": f"Base dir not found: {base_dir}"}

    artifacts = []
    for ext in ("*.csv", "*.json", "*.txt"):
        for file in base_path.rglob(ext):
            artifacts.append({
                "name": file.name,
                "path": str(file),
                "size": os.path.getsize(file),
                "modified": os.path.getmtime(file)
            })

    return {"success": True, "artifacts": artifacts}


if __name__ == "__main__":
    mcp.run()
