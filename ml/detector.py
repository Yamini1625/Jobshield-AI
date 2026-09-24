import os
import re
import json
import zlib
import html
from urllib.parse import urlparse

import joblib

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "scam_model.pkl")
DATASET_PATH = os.path.join(BASE_DIR, "dataset.csv")
WHITELIST_PATH = os.path.join(BASE_DIR, "verified_companies.json")

# Threat vector categories:
# 1. financial: Advance fee, deposits, kit charges, payment requests
# 2. identity: Aadhaar, PAN, OTP, bank credentials, CVV
# 3. channel: WhatsApp, Telegram, unverified free communications
# 4. terms: Guaranteed selection, no interview, unrealistic daily/weekly pay
# 5. technical: Suspicious TLDs, non-HTTPS, domain mismatches

CATEGORIZED_RULES = [
    # Financial Extortion
    {
        "pattern": r"\b(registration|processing|security|refundable|joining|training|verification|equipment|courier|laptop)\s+(fee|charge|deposit|amount|cost|money|payment)\b",
        "weight": 12,
        "category": "financial",
        "label": "Upfront fee or security deposit demanded before employment",
        "description": "Legitimate employers never require candidates to pay for interviews, onboarding kits, or job placements."
    },
    {
        "pattern": r"\b(pay|transfer|send|deposit)\s+(rs\.?|inr|rupees|\$|usd|eur|usdt)?\s?\d{2,}\b",
        "weight": 10,
        "category": "financial",
        "label": "Direct instruction asking candidate to send money",
        "description": "Demanding cash or wire transfers for employment confirmation is a primary hallmark of job fraud."
    },
    {
        "pattern": r"\b(stamp\s*duty|bond\s*charge|courier\s*charge|delivery\s*insurance|dispatch\s*fee)\b",
        "weight": 9,
        "category": "financial",
        "label": "Bogus administrative or dispatch fee demanded in offer letter",
        "description": "Scammers frequently fabricate delivery fees for work-from-home laptops or identity cards."
    },
    {
        "pattern": r"\b(buy|purchase)\b.{0,30}\b(laptop|kit|software|course|training|license|materials?)\b",
        "weight": 8,
        "category": "financial",
        "label": "Candidate asked to purchase training, software or equipment",
        "description": "Fraudulent schemes often redirect job-seekers to pay for mandatory proprietary courses or kits."
    },
    {
        "pattern": r"[\w\.\-]+@(okaxis|okicici|oksbi|okhdfc|paytm|ybl|axl|ibl|apl|upi)\b",
        "weight": 10,
        "category": "financial",
        "label": "Personal UPI ID listed for direct money transfer",
        "description": "Corporate entities do not collect candidate payments via personal UPI accounts."
    },
    {
        "pattern": r"\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b|0x[a-fA-F0-9]{40}\b",
        "weight": 10,
        "category": "financial",
        "label": "Cryptocurrency wallet address detected",
        "description": "Cryptocurrency demands are completely non-standard for legitimate hiring and represent high fraud risk."
    },

    # Identity & Phishing Theft
    {
        "pattern": r"\b(aadhaar|bank\s*details|account\s*number|netbanking|otp|one\s*time\s*password|pan\s*card|upi\s*pin|cvv|atm\s*pin)\b",
        "weight": 12,
        "category": "identity",
        "label": "Sensitive identity, banking or authentication secrets requested",
        "description": "Demanding banking passwords, OTPs, or debit card pins is identity theft and cyber fraud."
    },
    {
        "pattern": r"\b(send\s*(cancelled\s*cheque|passbook\s*copy|signature|blank\s*cheque))\b",
        "weight": 8,
        "category": "identity",
        "label": "Direct submission of blank cheque or sensitive banking proofs",
        "description": "Legitimate HR collects bank info only via secure employee portals after formal on-boarding."
    },

    # Communication & Channel Security
    {
        "pattern": r"\bwhatsapp\s*(only|number|group|chat)?\b|\btelegram\s*(only|link|group|handle|bot)?\b",
        "weight": 9,
        "category": "channel",
        "label": "Recruitment redirected exclusively to WhatsApp / Telegram",
        "description": "Impersonators use end-to-end encrypted messaging to avoid corporate logging and traceability."
    },
    {
        "pattern": r"\bcontact\s*(us\s*)?(via|on|through)\s*(whatsapp|telegram)\b",
        "weight": 8,
        "category": "channel",
        "label": "Sole contact channel is an instant messaging handle",
        "description": "Professional hiring involves verifiable corporate email communication."
    },

    # Employment Terms Credibility
    {
        "pattern": r"\b(no\s*interview|without\s*interview|no\s*resume\s*required|instant\s*selection|instant\s*job|direct\s*joining|selected\s*directly)\b",
        "weight": 10,
        "category": "terms",
        "label": "Hiring promised without any formal interview or screening",
        "description": "Guaranteed instant selection without evaluation is designed to trap unsuspecting applicants."
    },
    {
        "pattern": r"\b(guarantee(d)?|100%)\s*(job|placement|selection|income|salary)\b",
        "weight": 8,
        "category": "terms",
        "label": "Unrealistic placement or income guarantee",
        "description": "Commercial job guarantees are predatory tactics frequently used by unaccredited agencies."
    },
    {
        "pattern": r"\b(earn|salary|income).{0,20}\b(\d{2,3},?\d{3,})\b.{0,20}(week|weekly|day|daily|hour|hourly)\b",
        "weight": 8,
        "category": "terms",
        "label": "Disproportionately high earnings promised for part-time/daily work",
        "description": "Promises of ₹5,000–₹50,000 daily for typing, SMS or simple tasks are hallmark bait-and-switch scams."
    },
    {
        "pattern": r"\b(limited\s*seats|hurry|apply\s*within\s*\d+\s*(hours|mins?)|only\s*\d+\s*(slots|seats)|offer\s*(will\s*be\s*)?cancelled)\b",
        "weight": 6,
        "category": "terms",
        "label": "High-pressure urgency tactics to rush decision-making",
        "description": "Scammers manufacture false urgency so victims make hasty financial transfers without verification."
    },
    {
        "pattern": r"\bno\s*(skills?|experience|qualification)s?\s+(required|needed)\b",
        "weight": 5,
        "category": "terms",
        "label": "High-paying role claiming zero skills or qualifications required",
        "description": "Generic 'zero qualifications' promises target inexperienced students and fresh graduates."
    },
    {
        "pattern": r"!{2,}",
        "weight": 3,
        "category": "terms",
        "label": "Excessive hype punctuation (! / ?)",
        "description": "Spam-style typography indicates non-professional, promotional copy."
    }
]

FREE_EMAILS = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "rediffmail.com", "protonmail.com", "zoho.com"}
SUSPICIOUS_TLDS = {".xyz", ".top", ".click", ".buzz", ".work", ".rest", ".site", ".online", ".club", ".surf", ".space", ".fit", ".gq", ".ml", ".cf"}


def _load_whitelist():
    try:
        with open(WHITELIST_PATH, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return [
            "Google", "Microsoft", "Amazon", "Infosys", "Tata Consultancy Services",
            "TCS", "Wipro", "Accenture", "Cognizant", "Meta", "Apple", "Netflix",
            "IBM", "Cisco", "Adobe", "Salesforce", "Oracle", "Intel", "HCLTech",
            "Capgemini", "Deloitte", "Goldman Sachs", "JPMorgan Chase", "Flipkart"
        ]


class ScamDetector:
    def __init__(self):
        self._model = None
        self._whitelist = _load_whitelist()
        self.model_status = "Model loaded"
        self._load_model()

    def _load_model(self):
        if not os.path.exists(MODEL_PATH):
            self.model_status = "Model file missing"
            return
        try:
            self._model = joblib.load(MODEL_PATH)
        except Exception as exc:
            try:
                from sklearn.feature_extraction.text import TfidfVectorizer
                from sklearn.linear_model import LogisticRegression
                import pandas as pd
                df = pd.read_csv(DATASET_PATH)
                text_col = next((c for c in ["text", "job_description", "description"] if c in df.columns), None)
                label_col = next((c for c in ["label", "fraudulent", "is_fake", "target"] if c in df.columns), None)
                if not text_col or not label_col:
                    raise ValueError("Training columns not found")
                vec = TfidfVectorizer(ngram_range=(1, 2), max_features=8000, stop_words="english")
                X = vec.fit_transform(df[text_col].fillna(""))
                model = LogisticRegression(max_iter=1500)
                model.fit(X, df[label_col].astype(int))
                self._model = (vec, model)
                joblib.dump(self._model, MODEL_PATH)
                self.model_status = "Model retrained for this environment"
            except Exception:
                self.model_status = f"ML model unavailable: {type(exc).__name__}"

    def ml_probability(self, text):
        if not self._model or not text.strip():
            return 0.5
        try:
            if isinstance(self._model, tuple):
                vec, model = self._model
                return float(model.predict_proba(vec.transform([text]))[0][1])
            return float(self._model.predict_proba([text])[0][1])
        except Exception:
            return 0.5

    def scan_red_flags(self, text):
        text_l = text.lower()
        hits = []
        points = 0
        cat_points = {"financial": 0, "identity": 0, "channel": 0, "terms": 0}
        cat_max = {"financial": 50, "identity": 20, "channel": 17, "terms": 40}

        for rule in CATEGORIZED_RULES:
            if re.search(rule["pattern"], text_l):
                hits.append(rule["label"])
                points += rule["weight"]
                cat_points[rule["category"]] += rule["weight"]

        total_max = sum(r["weight"] for r in CATEGORIZED_RULES)
        score = min(100, round(points / total_max * 100)) if total_max else 0

        # Vector scores normalized to 0-100
        vectors = {
            k: min(100, round((cat_points[k] / cat_max[k]) * 100))
            for k in cat_points
        }
        return score, hits, vectors

    def verify_company(self, company_name, company_url, contact_email):
        notes, confidence = [], 50
        technical_score = 30  # 0 to 100 representing technical trust / safety
        name = (company_name or "").strip().lower()

        if name and any(name == c.lower() for c in self._whitelist):
            notes.append("Company name matches a recognized organization in verified reference database.")
            confidence += 30
            technical_score += 25
        elif name:
            notes.append("Company is not in the recognized reference database; independent verification advised.")

        domain = ""
        if company_url:
            raw_url = company_url if "://" in company_url else "https://" + company_url
            parsed = urlparse(raw_url)
            domain = (parsed.netloc or parsed.path).lower().replace("www.", "")

            # Check suspicious TLDs
            tld = "." + domain.split(".")[-1] if "." in domain else ""
            if tld in SUSPICIOUS_TLDS:
                notes.append(f"Domain uses high-risk disposable extension '{tld}' commonly associated with fraudulent sites.")
                confidence -= 25
                technical_score -= 30
            else:
                technical_score += 15

            if parsed.scheme == "https":
                notes.append("Company website utilizes encrypted HTTPS connection.")
                confidence += 5
                technical_score += 10
            else:
                notes.append("Company website does NOT use HTTPS.")
                confidence -= 15
                technical_score -= 15

            if name:
                clean_name = re.sub(r"[^a-z]", "", name)
                clean_domain = re.sub(r"[^a-z]", "", domain.split(".")[0])
                if clean_name and (clean_name in clean_domain or clean_domain in clean_name):
                    notes.append("Website domain matches corporate identity.")
                    confidence += 10
                    technical_score += 15
                else:
                    notes.append("Website domain does not clearly match the stated company name.")
                    confidence -= 10
                    technical_score -= 10
        else:
            notes.append("No official corporate website was provided.")
            confidence -= 15
            technical_score -= 10

        if contact_email and "@" in contact_email:
            email_domain = contact_email.rsplit("@", 1)[1].lower()
            if email_domain in FREE_EMAILS:
                notes.append(f"Recruiter uses a public/free email domain (@{email_domain}). Official corporate email preferred.")
                confidence -= 15
            else:
                notes.append(f"Recruiter uses dedicated enterprise email domain (@{email_domain}).")
                if domain and email_domain == domain:
                    notes.append("Recruiter email domain strictly matches the company website domain.")
                    confidence += 20
                    technical_score += 15
                else:
                    confidence += 5
        elif contact_email:
            notes.append("Contact email format appears non-standard.")
            confidence -= 5
        else:
            notes.append("No recruiter email was provided.")

        technical_risk = max(0, min(100, 100 - technical_score))
        return max(0, min(100, confidence)), notes, technical_risk

    def salary_risk(self, salary_text):
        text = (salary_text or "").lower()
        if not text:
            return 0, "No salary/stipend information provided."
        numbers = [int(x.replace(",", "")) for x in re.findall(r"\d[\d,]{2,}", text)]
        if any(n >= 100000 for n in numbers) and any(k in text for k in ["week", "weekly", "day", "daily"]):
            return 85, "Extremely high pay frequency (e.g. ₹100,000+/week) is an alarming bait signal."
        if any(n >= 50000 for n in numbers) and any(k in text for k in ["day", "daily"]):
            return 90, "Unrealistic daily payout promised."
        if any(k in text for k in ["guaranteed", "instant payout", "no work"]):
            return 75, "Salary terms contain non-commercial guaranteed payout wording."
        return 10, "Salary description falls within plausible parameters."

    def highlight_text(self, raw_text):
        """
        Produce explainable AI (XAI) highlighted HTML markup showing exactly which
        words triggered scam detections, color-coded by category.
        """
        if not raw_text:
            return "", []

        matches = []
        for rule in CATEGORIZED_RULES:
            for m in re.finditer(rule["pattern"], raw_text, re.IGNORECASE):
                matches.append({
                    "start": m.start(),
                    "end": m.end(),
                    "matched": m.group(0),
                    "category": rule["category"],
                    "label": rule["label"],
                    "desc": rule["description"]
                })

        # Sort matches by start index, filter out overlapping
        matches.sort(key=lambda x: (x["start"], -(x["end"] - x["start"])))
        filtered = []
        last_end = -1
        for m in matches:
            if m["start"] >= last_end:
                filtered.append(m)
                last_end = m["end"]

        # Build highlighted HTML
        out = []
        curr = 0
        for m in filtered:
            if m["start"] > curr:
                out.append(html.escape(raw_text[curr:m["start"]]))
            cat = m["category"]
            snippet = html.escape(m["matched"])
            tip = html.escape(f"[{cat.upper()}] {m['label']}: {m['desc']}")
            badge = f'<mark class="xai-chip xai-{cat}" title="{tip}" data-category="{cat}" data-label="{html.escape(m["label"])}">{snippet}</mark>'
            out.append(badge)
            curr = m["end"]

        if curr < len(raw_text):
            out.append(html.escape(raw_text[curr:]))

        return "".join(out), filtered

    def analyze(self, job_text, company_name="", company_url="", contact_email="", salary_text=""):
        full_text = " ".join([job_text or "", salary_text or ""])
        ml = self.ml_probability(full_text)
        rule_score, flags, vectors = self.scan_red_flags(full_text)
        company_conf, notes, tech_risk = self.verify_company(company_name, company_url, contact_email)
        salary_score, salary_note = self.salary_risk(salary_text)

        if salary_score >= 60:
            flags.append(salary_note)
            vectors["terms"] = min(100, vectors["terms"] + 30)
        notes.append(salary_note)

        # 5-Axis Threat Vector Breakdown:
        threat_vectors = {
            "financial_extortion": vectors["financial"],
            "identity_theft": vectors["identity"],
            "channel_security": vectors["channel"],
            "terms_credibility": vectors["terms"],
            "technical_trust": tech_risk
        }

        # Weighted calculation
        vector_avg = sum(threat_vectors.values()) / 5.0
        final = round(
            0.35 * (ml * 100) +
            0.30 * rule_score +
            0.20 * vector_avg +
            0.15 * (100 - company_conf)
        )
        final = max(0, min(100, final))
        level = "High" if final >= 65 else "Medium" if final >= 35 else "Low"
        recs = self._recommendations(level, flags, company_conf)

        highlighted_html, detected_keywords = self.highlight_text(job_text)

        return {
            "ml_probability": round(ml * 100, 1),
            "rule_score": rule_score,
            "company_confidence": company_conf,
            "salary_risk": salary_score,
            "final_score": final,
            "risk_level": level,
            "flags": flags,
            "company_notes": notes,
            "recommendations": recs,
            "threat_vectors": threat_vectors,
            "highlighted_html": highlighted_html,
            "detected_keywords": detected_keywords,
            "model_status": self.model_status,
        }

    @staticmethod
    def _recommendations(level, flags, company_conf):
        recs = []
        if level == "High":
            recs.append("CRITICAL: Under no circumstances transfer money, purchase kits, or share OTPs / banking proofs.")
            recs.append("Cease communications on WhatsApp/Telegram immediately and report the contact handle.")
        elif level == "Medium":
            recs.append("Proceed with caution. Verify the company via official registration records (e.g. MCA, corporate registry) before attending calls.")
            recs.append("Request an official interview conducted on standard video platforms or company corporate offices.")
        else:
            recs.append("No critical scam markers detected in the analyzed text.")
            recs.append("Standard diligence advised: Never share confidential passwords or banking pins with recruiters.")

        if any("pay" in f.lower() or "fee" in f.lower() or "deposit" in f.lower() for f in flags):
            recs.append("Legitimate companies do not charge candidates security deposits, gate pass fees, or laptop insurance.")
        if company_conf < 40:
            recs.append("Verify recruiter identity on LinkedIn and check if their email matches the official enterprise domain.")
        return recs


def parse_document_text(file_bytes: bytes, filename: str) -> str:
    """
    Extract readable text from uploaded documents (PDF, TXT, DOC) with zero external network dependencies.
    Uses pypdf if available, otherwise native PDF stream decompressor, or text decoder.
    """
    if not file_bytes:
        return ""

    lower_name = filename.lower()
    
    # 1. Plain text file
    if lower_name.endswith((".txt", ".md", ".log", ".csv", ".json")):
        for enc in ["utf-8", "latin-1", "windows-1252"]:
            try:
                return file_bytes.decode(enc)
            except Exception:
                continue
        return file_bytes.decode("utf-8", errors="ignore")

    # 2. PDF file
    if lower_name.endswith(".pdf") or file_bytes.startswith(b"%PDF"):
        # Try pypdf if installed
        try:
            import io
            import pypdf
            reader = pypdf.PdfReader(io.BytesIO(file_bytes))
            text_parts = [page.extract_text() or "" for page in reader.pages]
            full = " ".join(text_parts).strip()
            if len(full) >= 20:
                return full
        except Exception:
            pass

        # Fallback: Robust native PDF stream decompressor
        extracted = []
        # Find FlateDecode streams
        stream_matches = re.finditer(b"stream\r?\n(.*?)\r?\nendstream", file_bytes, re.DOTALL)
        for m in stream_matches:
            raw_stream = m.group(1)
            try:
                decompressed = zlib.decompress(raw_stream)
                # Look for PDF text show operations: (text) Tj or [(t)(e)(x)(t)] TJ
                tj_matches = re.findall(rb"\((.*?)\)\s*Tj", decompressed)
                for t in tj_matches:
                    extracted.append(t.decode("latin-1", errors="ignore"))
            except Exception:
                # Try raw decode if not zlib
                tj_matches = re.findall(rb"\((.*?)\)\s*Tj", raw_stream)
                for t in tj_matches:
                    extracted.append(t.decode("latin-1", errors="ignore"))

        if extracted:
            combined = " ".join(extracted)
            combined = re.sub(r"\s+", " ", combined).strip()
            if len(combined) >= 20:
                return combined

        # Final string extraction heuristic
        text = file_bytes.decode("utf-8", errors="ignore")
        strings = re.findall(r"[A-Za-z0-9\s.,!?;:/()@#\-_₹$%]{4,}", text)
        clean = " ".join(s.decode("latin-1", errors="ignore") for s in strings)
        return re.sub(r"\s+", " ", clean).strip()

    # Generic fallback
    return file_bytes.decode("utf-8", errors="ignore")


detector = ScamDetector()
