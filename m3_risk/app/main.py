from fastapi import FastAPI

app = FastAPI(title="M3 Unternehmensabgleich, Lieferkette und Risiko")


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "module": "m3_risk"}
