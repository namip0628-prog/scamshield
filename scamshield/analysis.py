import re
from functools import lru_cache
from urllib.parse import urlparse

import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline

from .models import Indicator

_TRAINING_EXAMPLES = [
    ("Your bank statement is ready to view in the official app.", "Safe"),
    ("Your UPI payment of Rs 240 was successful. Thank you.", "Safe"),
    ("Your appointment is confirmed for tomorrow at 10 am.", "Safe"),
    ("Your order has shipped. Track it in the shopping app.", "Safe"),
    ("Electricity bill paid successfully. Thank you for using the service.", "Safe"),
    ("Your monthly account summary is now available.", "Safe"),
    ("A delivery is scheduled for today. Open the official app for details.", "Safe"),
    ("Your ticket booking is confirmed. Have a pleasant journey.", "Safe"),
    ("Your payment receipt is available in your account.", "Safe"),
    ("Your subscription renewal is complete.", "Safe"),
    ("Your package delivery was attempted. Check the courier's official app.", "Suspicious"),
    ("A KYC update is requested. Please verify this message with your bank.", "Suspicious"),
    ("A refund is waiting. Contact customer support using the number on the official website.", "Suspicious"),
    ("Your account needs attention. Do not share your PIN or OTP with anyone.", "Suspicious"),
    ("An unfamiliar payment request arrived. Confirm the recipient before proceeding.", "Suspicious"),
    ("A link claims to offer a reward. Verify the offer through the company's official app.", "Suspicious"),
    ("Your service may be interrupted. Check your bill using the provider's official app.", "Suspicious"),
    ("A caller says they are from the bank and asks you to confirm account details.", "Suspicious"),
    ("You have an unexpected parcel fee. Verify it with the courier before paying.", "Suspicious"),
    ("An unknown person asks you to install an app to receive a refund.", "Suspicious"),
    ("URGENT: Your bank account will be blocked today. Click this link to update KYC now.", "Scam"),
    ("You won a prize. Pay a processing fee immediately to claim your reward.", "Scam"),
    ("Share your OTP and UPI PIN to reverse the failed transaction.", "Scam"),
    ("Approve this collect request to receive your money.", "Scam"),
    ("Electricity will be disconnected tonight. Pay now at this shortened link.", "Scam"),
    ("Install this remote access app so we can help you get your refund.", "Scam"),
    ("Your SIM will be deactivated. Send your bank details to verify your account.", "Scam"),
    ("KYC expired. Click here and enter your card PIN to prevent account closure.", "Scam"),
    ("Transfer a small fee now to release your parcel and claim a cash reward.", "Scam"),
    ("This is police. Pay immediately or a case will be filed against you.", "Scam"),
    ("Congratulations, you are selected for a cash prize. Pay tax to unlock it.", "Scam"),
    ("Your UPI refund failed. Scan this QR and enter your PIN to receive money.", "Scam"),
]

_RULES = (
    (
        "OTP or PIN request",
        re.compile(r"\b(?:otp|one[- ]time password|upi pin|atm pin|card pin|password)\b", re.I),
        38,
        "The message mentions an OTP, PIN, or password. Never share these with anyone.",
    ),
    (
        "Payment approval pressure",
        re.compile(r"\b(?:approve|accept|authorize)\b.{0,45}\b(?:collect request|payment|upi)\b|\bcollect request\b", re.I),
        35,
        "A UPI collect request asks you to approve a payment; it does not send you money.",
    ),
    (
        "Threat or urgency",
        re.compile(r"\b(?:urgent|immediately|today|tonight|within \d+ hours|will be (?:blocked|disconnected|deactivated))\b", re.I),
        24,
        "Urgent threats are commonly used to pressure people into acting without checking.",
    ),
    (
        "KYC or account threat",
        re.compile(r"\b(?:kyc|account|sim)\b.{0,50}\b(?:block|suspend|deactivat|expir|close)\w*\b|\b(?:block|suspend|deactivat|expir)\w*.{0,50}\b(?:kyc|account|sim)\b", re.I),
        30,
        "A threat involving KYC, an account, or a SIM should be checked through the official provider.",
    ),
    (
        "Unexpected payment or reward",
        re.compile(r"\b(?:prize|reward|won|cashback|refund|processing fee|claim)\b", re.I),
        20,
        "Unexpected rewards or refunds that require action or payment may be fraudulent.",
    ),
    (
        "Remote access request",
        re.compile(r"\b(?:remote access|screen sharing|anydesk|teamviewer|install this app)\b", re.I),
        35,
        "A request to install remote-access software can expose your banking activity.",
    ),
)

_UPI_RE = re.compile(r"(?<![\w.-])[\w.-]{2,256}@[a-zA-Z][a-zA-Z0-9.-]{1,63}")
_URL_RE = re.compile(
    r"(?<![@\w])(?:https?://[^\s<>'\"]+|(?:www\.)?(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/[^\s<>'\"]*)?)",
    re.I,
)
_PHONE_RE = re.compile(r"(?<!\d)(?:\+?91[\s-]?)?[6-9]\d{9}(?!\d)")
_URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "cutt.ly"}


def normalize_value(kind, value):
    value = value.strip()
    if kind == "sms":
        return " ".join(value.casefold().split())
    if kind == "upi_id":
        return value.casefold()
    if kind == "phone":
        digits = re.sub(r"\D", "", value)
        return digits[-10:]
    if kind == "url":
        candidate = value if "://" in value else f"https://{value}"
        parsed = urlparse(candidate)
        return f"{(parsed.hostname or '').casefold()}{parsed.path.rstrip('/')}"
    raise ValueError(f"Unsupported indicator kind: {kind}")


def _candidates(text):
    found = []
    for match in _UPI_RE.finditer(text):
        found.append(("upi_id", normalize_value("upi_id", match.group())))
    for match in _URL_RE.finditer(text):
        url = match.group().rstrip(".,!?)]}")
        normalized = normalize_value("url", url)
        if normalized:
            found.append(("url", normalized))
    for match in _PHONE_RE.finditer(text):
        found.append(("phone", normalize_value("phone", match.group())))
    found.append(("sms", normalize_value("sms", text)))
    return found


def _report_kind(text):
    value = text.strip()
    if _UPI_RE.fullmatch(value):
        return "upi_id"
    if _URL_RE.fullmatch(value):
        return "url"
    if _PHONE_RE.fullmatch(value):
        return "phone"
    return "sms"


@lru_cache(maxsize=1)
def _model():
    data = pd.DataFrame(_TRAINING_EXAMPLES, columns=["text", "label"])
    pipeline = make_pipeline(
        TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, strip_accents="unicode"),
        LogisticRegression(max_iter=1000, class_weight="balanced", random_state=42),
    )
    pipeline.fit(data["text"], data["label"])
    return pipeline


def analyze_text(text):
    normalized = text.strip()
    model = _model()
    probabilities = model.predict_proba([normalized])[0]
    model_risk = sum(
        probability * {"Safe": 0, "Suspicious": 50, "Scam": 90}[label]
        for label, probability in zip(model.classes_, probabilities)
    )

    rule_risk = 0
    reasons = []
    for _name, pattern, points, reason in _RULES:
        if pattern.search(normalized):
            rule_risk += points
            reasons.append(reason)

    for match in _URL_RE.finditer(normalized):
        candidate = match.group().rstrip(".,!?)]}")
        parsed_url = candidate if "://" in candidate else f"https://{candidate}"
        host = (urlparse(parsed_url).hostname or "").casefold()
        if host in _URL_SHORTENERS:
            rule_risk += 25
            reasons.append("The message contains a link-shortening domain that hides its destination.")
            break
        if host:
            rule_risk += 8
            reasons.append("The message contains a link. Verify its destination before opening it.")
            break

    matches = []
    candidates = set(_candidates(normalized))
    if candidates:
        matches = (
            Indicator.query.filter(
                db_or_conditions(candidates),
            ).all()
        )
    if matches:
        for indicator in matches:
            reasons.append(
                f"This {indicator.kind.replace('_', ' ')} matches a community-verified report."
            )

    score = min(100, int(round(max(model_risk, min(rule_risk, 95)))))
    if matches:
        score = 100
    if score >= 65:
        label = "Scam"
    elif score >= 30:
        label = "Suspicious"
    else:
        label = "Safe"

    if not reasons:
        reasons.append(
            "No strong scam indicators were detected. This is not a guarantee of safety."
        )
    return {
        "score": score,
        "label": label,
        "reasons": reasons,
        "model_label": model.predict([normalized])[0],
        "model_note": "Starter model trained on a small illustrative sample; not a verified production dataset.",
        "report_kind": _report_kind(normalized),
    }


def db_or_conditions(candidates):
    from sqlalchemy import and_, or_

    return or_(*(and_(Indicator.kind == kind, Indicator.value == value) for kind, value in candidates))
