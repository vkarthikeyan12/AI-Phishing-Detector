# Phishing Detector (Flask + Grok)

Simple local web app to upload `.eml` files and have Grok (LLM) classify whether the email is phishing, along with a risk level and recommended action.

## 1. Requirements

- Python 3.9+ recommended
- Grok API key (`GROK_API_KEY`)

## 2. Install dependencies

From the project root (same folder as `app.py` and `requirements.txt`):

```bash
pip install -r requirements.txt
```

On Windows PowerShell you might run:

```powershell
python -m pip install -r requirements.txt
```

## 3. Configure environment

1. Copy `.env.example` to `.env`:

```bash
cp .env .env
```

On Windows PowerShell:

```powershell
Copy-Item .env.example .env
```

2. Edit `.env` and set your Grok key:

```text
GROK_API_KEY=your_real_key_here
FLASK_SECRET_KEY=some_random_string
```

## 4. Run the app

From the project root:

```bash
python app.py
```

Then open your browser at:

```text
http://127.0.0.1:5000
```

Upload a `.eml` file and the app will:

- Parse basic fields (subject, from, to, body)
- Send a prompt with those details to Grok
- Display whether it looks like phishing, the risk level, reasons, and a suggested action

## 5. Notes

- This is a **prototype** for experimentation, not a replacement for enterprise security tooling.
- Always validate results and follow your organization's security policies.

