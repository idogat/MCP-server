import json

class JsonSearcher:
    def __init__(self, json_path: str):
        self.json_path = json_path

    def search(self, key: str = None, keyword: str = None):
        try:
            with open(self.json_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            if isinstance(data, dict):
                data = [data]

            results = []
            for obj in data:
                if isinstance(obj, dict):
                    if key and key in obj:
                        results.append(obj)
                    elif keyword and any(keyword.lower() in str(v).lower() for v in obj.values()):
                        results.append(obj)

            return {"success": True, "count": len(results), "matches": results[:50]}
        except Exception as e:
            return {"success": False, "error": str(e)}
