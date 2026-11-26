import re
from urllib.parse import urlparse

from .ml_model import predict_scam
from .models import Indicator

_RULES = (
    (
        "Credential request",
        re.compile(
            r"\b(?:share|send|tell|provide|enter|submit|type|reveal|confirm)\b"
            r".{0,50}\b(?:otp|one[- ]time password|upi pin|atm pin|card pin|password)\b",
            re.I,
        ),
        50,
        "The message asks for a secret such as an OTP, PIN, or password. Never share these with anyone.",
    ),
    (
        "Payment approval pressure",
        re.compile(
            r"\b(?:approve|accept|authorize)\b.{0,45}\b(?:collect request|payment|upi)\b"
            r"|\bcollect request\b",
            re.I,
        ),
        40,
        "A UPI collect request asks you to approve a payment; it does not send you money.",
    ),
    (
        "Threat and urgency",
        re.compile(
            r"\b(?:urgent|immediately|within \d+ hours)\b.{0,80}"
            r"\b(?:blocked|disconnected|deactivated|suspended|closed|legal action)\b"
            r"|\b(?:blocked|disconnected|deactivated|suspended|closed|legal action)\b"
            r".{0,80}\b(?:urgent|immediately|today|tonight|within \d+ hours)\b",
            re.I,
        ),
        25,
        "A threat combined with urgency can pressure you to act before verifying independently.",
    ),
    (
        "KYC or account threat",
        re.compile(
            r"\b(?:kyc|account|sim)\b.{0,50}\b(?:block|suspend|deactivat|expir|close)\w*\b"
            r"|\b(?:block|suspend|deactivat|expir)\w*.{0,50}\b(?:kyc|account|sim)\b",
            re.I,
        ),
        25,
        "A threat involving KYC, an account, or a SIM should be checked through the official provider.",
    ),
    (
        "Reward or refund fee",
        re.compile(
            r"\b(?:pay|send|transfer)\b.{0,50}\b(?:fee|tax|charge)\b.{0,60}"
            r"\b(?:prize|reward|refund|cashback|claim)\b"
            r"|\b(?:prize|reward|refund|cashback)\b.{0,60}"
            r"\b(?:pay|send|transfer)\b.{0,50}\b(?:fee|tax|charge)\b",
            re.I,
        ),
        35,
        "Being asked to pay a fee to receive a prize, reward, or refund is a strong warning sign.",
    ),
    (
        "Remote access request",
        re.compile(
            r"\b(?:install|download|use)\b.{0,40}"
            r"\b(?:remote access|screen sharing|anydesk|teamviewer|quick support)\b"
            r"|\b(?:remote access|screen sharing|anydesk|teamviewer|quick support)\b"
            r".{0,40}\b(?:install|download|use)\b",
            re.I,
        ),
        40,
        "A request to install or use remote-access software can expose your banking activity.",
    ),
)

_HINDI_RULES = (
    (
        re.compile(
            r"(?:ओटीपी|otp|upi pin|पिन|पासवर्ड).{0,40}"
            r"(?:बताएं|बताओ|भेजें|भेजो|साझा करें|share|दर्ज करें|enter)"
            r"|(?:बताएं|बताओ|भेजें|भेजो|साझा करें|share|दर्ज करें|enter)"
            r".{0,40}(?:ओटीपी|otp|upi pin|पिन|पासवर्ड)",
            re.I,
        ),
        50,
        "संदेश OTP, PIN या पासवर्ड जैसी गोपनीय जानकारी मांगता है। इसे किसी के साथ साझा न करें।",
    ),
    (
        re.compile(
            r"(?:केवाईसी|kyc|खाता|account|सिम|sim).{0,55}"
            r"(?:बंद|ब्लॉक|निलंबित|डिएक्टिवेट|रोक).{0,45}"
            r"(?:आज|तुरंत|अभी|घंटे|today|urgent|immediately)"
            r"|(?:आज|तुरंत|अभी|घंटे|today|urgent|immediately).{0,55}"
            r"(?:केवाईसी|kyc|खाता|account|सिम|sim).{0,55}"
            r"(?:बंद|ब्लॉक|निलंबित|डिएक्टिवेट|रोक)",
            re.I,
        ),
        35,
        "KYC, खाते या SIM को बंद करने की धमकी और जल्दबाजी दबाव बनाने की कोशिश हो सकती है।",
    ),
    (
        re.compile(r"(?:कलेक्ट रिक्वेस्ट|collect request|पैसे पाने के लिए).{0,50}(?:स्वीकार|approve|accept)", re.I),
        40,
        "UPI कलेक्ट अनुरोध स्वीकार करने से भुगतान आपके खाते से जा सकता है।",
    ),
)

_HINDI_REASON_TRANSLATIONS = {
    "The message asks for a secret such as an OTP, PIN, or password. Never share these with anyone.": "संदेश OTP, PIN या पासवर्ड जैसी गोपनीय जानकारी मांगता है। इसे किसी के साथ साझा न करें।",
    "A UPI collect request asks you to approve a payment; it does not send you money.": "UPI कलेक्ट अनुरोध स्वीकार करने से भुगतान आपके खाते से जा सकता है; इससे आपको पैसे नहीं मिलते।",
    "A threat combined with urgency can pressure you to act before verifying independently.": "धमकी और जल्दबाजी आपको स्वतंत्र रूप से जांचने से पहले कार्रवाई करने के लिए दबाव डाल सकती है।",
    "A threat involving KYC, an account, or a SIM should be checked through the official provider.": "KYC, खाते या SIM से जुड़ी धमकी की जांच आधिकारिक सेवा प्रदाता से करें।",
    "Being asked to pay a fee to receive a prize, reward, or refund is a strong warning sign.": "इनाम, रिवॉर्ड या रिफंड पाने के लिए शुल्क मांगना एक मजबूत चेतावनी संकेत है।",
    "A request to install or use remote-access software can expose your banking activity.": "रिमोट-एक्सेस ऐप इंस्टॉल करने या इस्तेमाल करने का अनुरोध आपकी बैंकिंग गतिविधि उजागर कर सकता है।",
    "The message contains a link. Verify its destination before opening it.": "संदेश में लिंक है। खोलने से पहले उसका पता स्वतंत्र रूप से जांचें।",
    "The message contains a link-shortening domain that hides its destination.": "लिंक छोटा करने वाली सेवा असली वेबसाइट का पता छिपा सकती है।",
    "This rule-based score is not a probability and cannot verify who sent a message. A lack of detected warning signs does not establish that it is safe.": "यह नियम-आधारित स्कोर संभावना नहीं है और संदेश भेजने वाले की पहचान सत्यापित नहीं करता। चेतावनी न मिलना सुरक्षा का प्रमाण नहीं है।",
    "No strong scam indicators were detected. This is not a guarantee of safety.": "धोखाधड़ी के स्पष्ट संकेत नहीं मिले, लेकिन यह सुरक्षा की गारंटी नहीं है।",
    "The trained text model found patterns resembling its scam examples. Verify independently before acting.": "प्रशिक्षित टेक्स्ट मॉडल को अपने धोखाधड़ी उदाहरणों से मिलते-जुलते संकेत मिले। कार्रवाई से पहले स्वतंत्र रूप से जांचें।",
    "This result uses explicit rules and moderator-verified indicators. No trained ML model is deployed yet.": "यह परिणाम स्पष्ट नियमों और moderator-verified संकेतों पर आधारित है। अभी कोई प्रशिक्षित ML मॉडल उपलब्ध नहीं है।",
    "This result combines explicit rules, moderator-verified indicators, and a trained text model. The model can be wrong and cannot verify who sent a message.": "यह परिणाम स्पष्ट नियमों, moderator-verified संकेतों और प्रशिक्षित टेक्स्ट मॉडल को मिलाता है। मॉडल गलत हो सकता है और संदेश भेजने वाले की पहचान सत्यापित नहीं करता।",
}

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


def analyze_text(text, language="en"):
    normalized = text.strip()

    rule_risk = 0
    reasons = []
    rules = _RULES + tuple(
        (None, pattern, points, reason) for pattern, points, reason in _HINDI_RULES
    )
    for _, pattern, points, reason in rules:
        if pattern.search(normalized) and not _is_negated(normalized, pattern):
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
            rule_risk += 15
            reasons.append("The message contains a link. Verify its destination before opening it.")
            break

    ml_prediction = predict_scam(normalized)
    if ml_prediction:
        rule_risk = max(rule_risk, 30)
        reasons.append(
            "The trained text model found patterns resembling its scam examples. "
            "Verify independently before acting."
        )

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
            if language == "hi":
                indicator_kind = {
                    "sms": "संदेश",
                    "url": "लिंक",
                    "phone": "फोन नंबर",
                    "upi_id": "UPI ID",
                }.get(indicator.kind, "पहचान")
                reasons.append(
                    f"यह {indicator_kind} ScamShield की moderator-reviewed "
                    "community report से मेल खाता है।"
                )
            else:
                reasons.append(
                    f"This {indicator.kind.replace('_', ' ')} matches a community-verified report."
                )

    score = min(100, rule_risk)
    if matches:
        score = 100
    if score >= 60:
        label = "Scam"
    elif score >= 30:
        label = "Suspicious"
    else:
        label = "No clear warning signs"

    if not reasons:
        reasons.append(
            "No strong scam indicators were detected. This is not a guarantee of safety."
        )
    if language == "hi":
        reasons = [_HINDI_REASON_TRANSLATIONS.get(reason, reason) for reason in reasons]
    if ml_prediction is None:
        model_note = (
            "This result uses explicit rules and moderator-verified indicators. "
            "No trained ML model is deployed yet."
        )
    else:
        model_note = (
            "This result combines explicit rules, moderator-verified indicators, and a trained "
            "text model. The model can be wrong and cannot verify who sent a message."
        )
    if language == "hi":
        model_note = _HINDI_REASON_TRANSLATIONS[model_note]
    return {
        "score": score,
        "label": label,
        "reasons": reasons,
        "model_note": model_note,
        "report_kind": _report_kind(normalized),
    }


def _is_negated(text, pattern):
    for match in pattern.finditer(text):
        if re.search(r"(?:\b(?:never|don't|do not|not)\b|नहीं|मत|न\s)", match.group(), re.I):
            continue
        prefix = text[max(0, match.start() - 40) : match.start()]
        if re.search(
            r"\b(?:never|don't|do not|not|shouldn't|must not|avoid)\b"
            r"(?:\W+\w+){0,2}\W*$",
            prefix,
            re.I,
        ):
            continue
        return False
    return True


def db_or_conditions(candidates):
    from sqlalchemy import and_, or_

    return or_(*(and_(Indicator.kind == kind, Indicator.value == value) for kind, value in candidates))
