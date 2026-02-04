from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
from typing import Optional
import os
from detector import TokenDetector
from models import DetectionResult

app = FastAPI(title="Honeypot & Scam Detection Agent")

INFURA_URL = os.getenv("WEB3_PROVIDER_URL")
if not INFURA_URL:
    # allow running but will error on calls if not provided
    INFURA_URL = None

detector = TokenDetector(provider_url=INFURA_URL)


@app.get("/", response_model=dict)
def root():
    return {"service": "honeypot-scam-detector", "version": "0.1"}


@app.get("/detect", response_model=DetectionResult)
def detect(token_address: str = Query(..., description="ERC20 token contract address to analyze")):
    if not detector.provider_available:
        raise HTTPException(status_code=503, detail="WEB3 provider URL is not configured. Set WEB3_PROVIDER_URL.")
    try:
        result = detector.analyze_token(token_address)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {e}")