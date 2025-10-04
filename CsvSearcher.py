import pandas as pd

class CsvSearcher:
    def __init__(self, csv_path: str):
        self.csv_path = csv_path

    def search(self, query_str: str):
        try:
            df = pd.read_csv(self.csv_path).fillna("")
            matches = df.query(query_str, engine="python")
            return {
                "success": True,
                "count": len(matches),
                "matches": matches.to_dict(orient="records")[:50],
                "columns": df.columns.tolist()
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
