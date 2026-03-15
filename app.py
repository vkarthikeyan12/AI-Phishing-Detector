import os
import requests
from email import policy
from email.parser import BytesParser

from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash


# Load environment variables from .env (GROK_API_KEY, etc.)
load_dotenv()

GROK_API_KEY = os.getenv("GROK_API_KEY")

# TODO: if the Groq endpoint/model name changes, update these:
# Groq uses an OpenAI-compatible chat completions endpoint.
GROK_API_URL = "https://api.groq.com/openai/v1/chat/completions"
# Use any valid Groq chat model you have access to, for example:
#   - "llama-3.1-8b-instant"
#   - "llama-3.1-70b-versatile"
GROK_MODEL = os.getenv("GROK_MODEL", "llama-3.1-8b-instant")


app = Flask(__name__)
# In a real app, set this via env var; hardcoded for demo
app.secret_key = os.getenv("FLASK_SECRET_KEY", "change-me-in-production")


def parse_eml(file_bytes: bytes) -> dict:
    """
    Parse a raw .eml file (bytes) and extract basic fields.
    Returns a dict with subject, from, to, body.
    """
    msg = BytesParser(policy=policy.default).parsebytes(file_bytes)

    subject = msg["subject"]
    from_addr = msg["from"]
    to_addr = msg["to"]

    # Prefer plain-text body; fall back to HTML if needed
    body_text = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = str(part.get_content_disposition())
            if ctype == "text/plain" and "attachment" not in disp:
                try:
                    body_text = part.get_content()
                except Exception:
                    body_text = part.get_payload(decode=True) or ""
                break

        if not body_text:
            for part in msg.walk():
                if part.get_content_type() == "text/html":
                    try:
                        body_text = part.get_content()
                    except Exception:
                        body_text = part.get_payload(decode=True) or ""
                    break
    else:
        try:
            body_text = msg.get_content()
        except Exception:
            body_text = msg.get_payload(decode=True) or ""

    # Ensure strings
    if isinstance(body_text, bytes):
        body_text = body_text.decode(errors="replace")

    return {
        "subject": subject or "",
        "from": from_addr or "",
        "to": to_addr or "",
        "body": body_text or "",
    }


def build_prompt(email_data: dict) -> str:
    """
    Build the phishing-analysis prompt sent to Grok.
    The expected output is a small JSON object for easy parsing.
    """
    return f"""
You are a cybersecurity assistant specialized in phishing detection.

Analyze the following email and decide if it is a phishing attempt.

Return ONLY a compact JSON object with fields:
  "is_phishing": true or false
  "risk_level": "low" | "medium" | "high"
  "reasons": string (short explanation)
  "recommended_action": string (short suggestion)

Do not include any extra text or explanation outside the JSON.

Email details:
Subject: {email_data['subject']}
From: {email_data['from']}
To: {email_data['to']}

Body:
{email_data['body']}
"""


def analyze_with_grok(prompt: str) -> dict:
    """
    Send the prompt to Grok LLM and return a structured result.
    Adjust this function if the Grok API response schema changes.
    """
    if not GROK_API_KEY:
        return {
            "error": "GROK_API_KEY is not set. Please configure it in your .env file."
        }

    headers = {
        "Authorization": f"Bearer {GROK_API_KEY}",
        "Content-Type": "application/json",
    }

    payload = {
        "model": GROK_MODEL,
        "messages": [
            {"role": "system", "content": "You are an expert phishing detector."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.1,
        "max_tokens": 500,
    }

    try:
        resp = requests.post(GROK_API_URL, json=payload, headers=headers, timeout=30)
        print("STATUS:", resp.status_code)
        print("BODY:", resp.text)

        resp.raise_for_status()
    except requests.RequestException as exc:
        return {
            "error": str(exc),
            "response_text": resp.text if 'resp' in locals() else None
        }

    data = resp.json()

    # Expected shape (similar to OpenAI-style):
    # { "choices": [ { "message": { "content": "...json..." } } ], ... }
    content = ""
    try:
        content = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        return {
            "error": "Unexpected response format from Grok API.",
            "raw_response": data,
        }

    # Try to parse the JSON the model returned.
    import json
    import re

    # First, try direct JSON.
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass

    # Fallback: extract the first {...} block.
    match = re.search(r"\{.*\}", content, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass

    # Final fallback: just pass raw content through.
    return {"raw_response": content}


@app.route("/", methods=["GET", "POST"])
def upload_eml():
    """
    Single-page app:
      - GET: show upload form
      - POST: accept .eml, parse, call Grok, show result
    """
    if request.method == "POST":
        if "eml_file" not in request.files:
            flash("No file part in the request.")
            return redirect(request.url)

        file = request.files["eml_file"]
        if file.filename == "":
            flash("No file selected.")
            return redirect(request.url)

        if not file.filename.lower().endswith(".eml"):
            flash("Please upload a .eml file.")
            return redirect(request.url)

        eml_bytes = file.read()
        if not eml_bytes:
            flash("Uploaded file is empty.")
            return redirect(request.url)

        email_data = parse_eml(eml_bytes)
        prompt = build_prompt(email_data)
        result = analyze_with_grok(prompt)

        return render_template(
            "upload.html",
            result=result,
            email_data=email_data,
        )

    # GET request
    return render_template("upload.html", result=None, email_data=None)


if __name__ == "__main__":
    # For local development
    app.run(host="127.0.0.1", port=5000, debug=True)

