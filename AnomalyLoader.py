import os
from pathlib import Path
from pdfminer.high_level import extract_text
import fitz
import shutil

try:
    from pdf2image import convert_from_path
    import pytesseract
    TESSERACT_AVAILABLE = shutil.which("tesseract") is not None
except ImportError:
    TESSERACT_AVAILABLE = False


def extract_pdf_text(file_path: str) -> str:
    # 1. Try pdfminer.six
    try:
        text = extract_text(file_path)
        if text and text.strip():
            return text
    except Exception:
        pass

    # 2. Try PyMuPDF (fitz)
    try:
        doc = fitz.open(file_path)
        text = ""
        for page in doc:
            text += page.get_text()
        if text.strip():
            return text
    except Exception:
        pass

    # 3. OCR fallback (if Tesseract is installed)
    if TESSERACT_AVAILABLE:
        try:
            images = convert_from_path(file_path)
            text = ""
            for img in images:
                text += pytesseract.image_to_string(img)
            return text
        except Exception:
            return ""

    # If all failed
    return ""


class AnomalyLoader:
    def __init__(self, base_dir: str):
        self.base_dir = Path(base_dir)

    def load(self):
        return {
            "success": True,
            "anomalies": {
                "manual": self._load_txt(self.base_dir / "anomalies"),
                "ioc": self._load_iocs(self.base_dir / "ioc"),
                "report_file_iocs": [],
                "report_network_iocs": [],
                "report_hash_iocs": [],
                "errors": []
            }
        }

    def _load_txt(self, folder: Path):
        out = []
        if not folder.exists():
            return out
        for file in folder.glob("*.txt"):
            try:
                text = file.read_text(encoding="utf-8").strip()
                if text:
                    out.append({
                        "id": file.stem,
                        "source": str(file),
                        "scope": "global",
                        "type": "manual",
                        "query": text
                    })
            except Exception as e:
                out.append({"source": str(file), "error": str(e)})
        return out

    def _load_iocs(self, folder: Path):
        out = []
        if not folder.exists():
            return out
        for file in folder.glob("*.txt"):
            try:
                for i, line in enumerate(file.read_text(encoding="utf-8").splitlines(), start=1):
                    line = line.strip()
                    if not line:
                        continue
                    out.append({
                        "id": f"{file.stem}_{i}",
                        "source": str(file),
                        "scope": "global",
                        "type": "ioc",
                        "query": line
                    })
            except Exception as e:
                out.append({"source": str(file), "error": str(e)})
        return out

    def _load_reports(self, folder: Path):
        if not folder.exists():
            return {"file": [], "network": [], "hash": [], "errors": []}

        file_iocs, network_iocs, hash_iocs, errors = [], [], [], []

        for file in folder.glob("*.pdf"):
            try:
                text = extract_pdf_text(str(file))
                if not text.strip():
                    continue

                f_iocs, n_iocs, h_iocs = set(), set(), set()

                for token in text.split():
                    token = token.strip(",.()[]{}<>\"'")

                    # File-based IOCs
                    if token.lower().endswith((".exe", ".dll", ".bat", ".ps1")):
                        f_iocs.add(token)

                    # Hashes
                    elif len(token) in [32, 40, 64] and all(c in "0123456789abcdefABCDEF" for c in token):
                        h_iocs.add(token.lower())

                    # Network indicators
                    elif "." in token or "@" in token:
                        n_iocs.add(token)

                for i in f_iocs:
                    file_iocs.append({
                        "id": f"{file.stem}_{i}",
                        "source": str(file),
                        "scope": "global",
                        "type": "report_file_iocs",
                        "query": i
                    })
                for i in n_iocs:
                    network_iocs.append({
                        "id": f"{file.stem}_{i}",
                        "source": str(file),
                        "scope": "global",
                        "type": "report_network_iocs",
                        "query": i
                    })
                for i in h_iocs:
                    hash_iocs.append({
                        "id": f"{file.stem}_{i}",
                        "source": str(file),
                        "scope": "global",
                        "type": "report_hash_iocs",
                        "query": i
                    })

            except Exception as e:
                errors.append({"source": str(file), "error": str(e)})

        return {
            "file": file_iocs,
            "network": network_iocs,
            "hash": hash_iocs,
            "errors": errors
        }
