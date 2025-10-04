import os
import pandas as pd
import json

class ArtifactScanner:
    def __init__(self, root_dir: str):
        self.root_dir = root_dir

    def scan(self):
        if not os.path.isdir(self.root_dir):
            return {"success": False, "message": f"{self.root_dir} is not a valid directory."}

        artifacts = []
        for fname in os.listdir(self.root_dir):
            fpath = os.path.join(self.root_dir, fname)
            if not os.path.isfile(fpath):
                continue

            ext = os.path.splitext(fname)[1].lower().lstrip(".")
            artifact_name = os.path.splitext(fname)[0].lower()

            try:
                if ext == "csv":
                    df = pd.read_csv(fpath, nrows=5).fillna("")
                    artifacts.append({
                        "filename": fname,
                        "artifact": artifact_name,
                        "path": fpath,
                        "extension": "csv",
                        "columns": df.columns.tolist(),
                        "sample": df.to_dict(orient="records")
                    })

                elif ext == "json":
                    with open(fpath, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    sample = data[0] if isinstance(data, list) and len(data) > 0 else data
                    artifacts.append({
                        "filename": fname,
                        "artifact": artifact_name,
                        "path": fpath,
                        "extension": "json",
                        "sample": sample if isinstance(sample, dict) else str(sample)[:200]
                    })

                elif ext == "txt":
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        lines = [next(f).strip() for _ in range(5)]
                    artifacts.append({
                        "filename": fname,
                        "artifact": artifact_name,
                        "path": fpath,
                        "extension": "txt",
                        "preview": lines
                    })

                else:
                    artifacts.append({
                        "filename": fname,
                        "artifact": artifact_name,
                        "path": fpath,
                        "extension": ext or "unknown"
                    })

            except Exception as e:
                artifacts.append({
                    "filename": fname,
                    "artifact": artifact_name,
                    "path": fpath,
                    "error": str(e)
                })

        return {"success": True, "artifacts": artifacts}
