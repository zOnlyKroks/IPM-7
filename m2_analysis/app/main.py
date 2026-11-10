from fastapi import FastAPI

app = FastAPI(title="M2 KI-Analyse und Quellenbewertung")


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "module": "m2_analysis"}
