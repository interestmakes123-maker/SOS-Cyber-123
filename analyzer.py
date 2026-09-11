import re


def analyze_message(message):

    message_lower = message.lower()

    score = 0
    warning_signs = []
    detected_types = []

    # ---------------------------------
    # 1. URGENCY / THREAT DETECTION
    # ---------------------------------

    urgency_patterns = [
        r"\burgent\b",
        r"\bimmediately\b",
        r"\bact now\b",
        r"\bwithin\s+\d+\s*(hours?|minutes?)\b",
        r"\blast warning\b",
        r"\baccount.*blocked\b",
        r"\baccount.*suspended\b",
        r"\baccount.*closed\b",
        r"\bexpires?\s+(today|now|soon)\b"
    ]

    if any(re.search(pattern, message_lower)
           for pattern in urgency_patterns):

        warning_signs.append("Urgent or threatening language")
        score += 20


    # ---------------------------------
    # 2. SUSPICIOUS LINK DETECTION
    # ---------------------------------

    link_patterns = [
        r"https?://",
        r"www\.",
        r"\bbit\.ly\b",
        r"\btinyurl\b",
        r"\bt\.co\b",
        r"click\s+(here|this|the\s+link)",
        r"verify.*link"
    ]

    if any(re.search(pattern, message_lower)
           for pattern in link_patterns):

        warning_signs.append("Suspicious link or verification request")
        score += 25


    # ---------------------------------
    # 3. OTP / PIN / PASSWORD DETECTION
    # ---------------------------------

    sensitive_patterns = [
        r"\botp\b",
        r"\bpin\b",
        r"\bpassword\b",
        r"\bpasscode\b",
        r"\bverification\s+code\b",
        r"\bsecurity\s+code\b"
    ]

    if any(re.search(pattern, message_lower)
           for pattern in sensitive_patterns):

        warning_signs.append(
            "Request for OTP, PIN, password, or verification code"
        )

        score += 25


    # ---------------------------------
    # 4. MONEY / PAYMENT DETECTION
    # ---------------------------------

    money_patterns = [
        r"\bsend\s+money\b",
        r"\btransfer\s+money\b",
        r"\bpay\s+now\b",
        r"\bmake\s+a\s+payment\b",
        r"\bpayment\b",
        r"\bupi\b",
        r"\bbank\s+account\b",
        r"\baccount\s+number\b",
        r"\brefund\b",
        r"\bfee\b",
        r"\bprocessing\s+fee\b"
    ]

    if any(re.search(pattern, message_lower)
           for pattern in money_patterns):

        warning_signs.append(
            "Request involving money or financial information"
        )

        score += 25


    # ---------------------------------
    # 5. FAKE REWARD / PRIZE DETECTION
    # ---------------------------------

    reward_patterns = [
        r"\byou\s+won\b",
        r"\bwinner\b",
        r"\blottery\b",
        r"\bcash\s+prize\b",
        r"\bfree\s+gift\b",
        r"\breward\b",
        r"\bcongratulations\b",
        r"\bprize\b",
        r"\blucky\s+winner\b"
    ]

    if any(re.search(pattern, message_lower)
           for pattern in reward_patterns):

        warning_signs.append(
            "Possible fake reward or prize"
        )

        score += 25


    # ---------------------------------
    # 6. SCAM TYPE DETECTION
    # ---------------------------------

    # Phishing
    if (
        any(word in message_lower for word in
            ["verify your account", "login", "click here", "security alert"])
        and
        any(word in message_lower for word in
            ["link", "http", "account", "password"])
    ):
        detected_types.append("Phishing Scam")


    # OTP Scam
    if any(word in message_lower for word in
           ["otp", "verification code", "security code"]):

        detected_types.append("OTP Scam")


    # UPI / Payment Scam
    if any(word in message_lower for word in
           ["upi", "payment", "send money", "transfer money"]):

        detected_types.append("Money Transfer Scam")


    # Shopping Scam
    if any(word in message_lower for word in
           ["order", "delivery", "product", "seller", "refund"]):

        detected_types.append("Online Shopping Scam")


    # Job Scam
    if any(word in message_lower for word in
           ["job", "work from home", "salary", "interview",
            "joining fee", "registration fee"]):

        detected_types.append("Job Scam")


    # Call Scam
    if any(word in message_lower for word in
           ["call me", "customer care", "support team",
            "bank officer", "police officer"]):

        detected_types.append("Fake Call Scam")


    # ---------------------------------
    # 7. EXTRA CONTEXT CHECK
    # ---------------------------------

    # A single harmless word should not automatically
    # produce a high-risk result.

    strong_signals = 0

    if any(word in message_lower for word in
           ["otp", "pin", "password", "passcode",
            "verification code"]):
        strong_signals += 1

    if any(word in message_lower for word in
           ["send money", "transfer money", "upi",
            "payment", "bank account"]):
        strong_signals += 1

    if any(re.search(pattern, message_lower)
           for pattern in link_patterns):
        strong_signals += 1

    if any(re.search(pattern, message_lower)
           for pattern in urgency_patterns):
        strong_signals += 1


    # ---------------------------------
    # 8. LIMIT SCORE
    # ---------------------------------

    if score > 100:
        score = 100


    # ---------------------------------
    # 9. RISK LEVEL
    # ---------------------------------

    if score >= 70 and strong_signals >= 2:
        risk_level = "HIGH"

    elif score >= 40:
        risk_level = "MEDIUM"

    else:
        risk_level = "LOW"


    # ---------------------------------
    # 10. SCAM TYPE RESULT
    # ---------------------------------

    if detected_types:
        scam_type = detected_types[0]
    else:
        scam_type = "Unknown"


    # ---------------------------------
    # 11. RECOMMENDED ACTION
    # ---------------------------------

    if risk_level == "HIGH":

        recommended_action = (
            "Do not click links, share OTPs or passwords, "
            "or make payments. Verify the sender using an official source."
        )

    elif risk_level == "MEDIUM":

        recommended_action = (
            "Be cautious. Do not share sensitive information "
            "or make payments until the message is verified."
        )

    else:

        recommended_action = (
            "No major scam indicators were detected, "
            "but remain cautious with unexpected messages."
        )


    # ---------------------------------
    # FINAL RESULT
    # ---------------------------------

    return {
        "risk_level": risk_level,
        "scam_probability": score,
        "scam_type": scam_type,
        "warning_signs": warning_signs,
        "recommended_action": recommended_action
    }