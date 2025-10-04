class TxtSearcher:
    def __init__(self, txt_path: str):
        self.txt_path = txt_path

    def search(self, keyword: str):
        try:
            matches = []
            with open(self.txt_path, "r", encoding="utf-8", errors="ignore") as f:
                for i, line in enumerate(f, start=1):
                    if keyword.lower() in line.lower():
                        matches.append({"line_number": i, "text": line.strip()})

            return {"success": True, "count": len(matches), "matches": matches[:50]}
        except Exception as e:
            return {"success": False, "error": str(e)}
