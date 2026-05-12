from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
import json

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class InputText(BaseModel):
    text: str


def compute_trust_analysis(text: str):
    text = text.lower()
    score = 100
    reasons = []

    critical_phrases = [
        "otp", "one time password", "verify account",
        "account number", "login details", "credit card",
        "password", "security code"
    ]

    high_risk_terms = [
        "urgent", "immediate", "payment", "transfer",
        "lottery", "prize", "click link", "bank"
    ]

    moderate_terms = [
        "details", "info", "secure", "expire",
        "reset", "confirm", "update"
    ]

    for phrase in critical_phrases:
        if phrase in text:
            score -= 40
            reasons.append(f"Sensitive phrase detected: {phrase}")

    for term in high_risk_terms:
        if term in text:
            score -= 15
            reasons.append(f"Suspicious keyword: {term}")

    for term in moderate_terms:
        if term in text:
            score -= 8
            reasons.append(f"Moderate keyword: {term}")

    score = max(score, 0)

    risk = "Safe"
    alert = "No risk detected"

    if score < 60:
        risk = "High Risk"
        alert = "⚠️ Possible scam detected!"
    elif score < 80:
        risk = "Moderate Risk"
        alert = "Be cautious"

    return {
        "trust_score": score,
        "risk": risk,
        "alert": alert,
        "reasons": reasons if reasons else ["No suspicious patterns detected"]
    }


@app.post("/analyze")
def analyze(data: InputText):
    return compute_trust_analysis(data.text)


@app.websocket("/ws/chat")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            data = await websocket.receive_text()
            message_data = json.loads(data)

            analysis = compute_trust_analysis(message_data.get("text", ""))

            await websocket.send_text(json.dumps(analysis))

    except WebSocketDisconnect:
        print("WebSocket disconnected")