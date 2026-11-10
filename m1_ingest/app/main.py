from fastapi import FastAPI

app = FastAPI(title="M1 Datenerfassung und Plattform")


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "module": "m1_ingest"}
