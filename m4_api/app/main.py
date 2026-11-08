from fastapi import FastAPI

app = FastAPI(title="M4 Zentrale API und Benachrichtigung")


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "module": "m4_api"}
