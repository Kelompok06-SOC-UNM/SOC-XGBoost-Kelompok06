
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import joblib
import pandas as pd
import numpy as np

app = FastAPI(title="SOC Alert Threat Intelligence API", version="1.0")

# Load model pipeline
pipeline = joblib.load('model_soc_xgboost_pipeline.joblib')

class LogInput(BaseModel):
    connection_duration: float
    port_entropy: float
    bytes_ratio: float
    packet_count: int

@app.post("/predict")
def predict_threat(data: LogInput):
    try:
        df = pd.DataFrame([data.dict()])
        prediction = int(pipeline.predict(df)[0])
        probability = float(pipeline.predict_proba(df)[0][1])
        
        status = "Real Attack (1)" if prediction == 1 else "False Alarm (0)"
        return {
            "prediction": prediction,
            "status": status,
            "probability_real_attack": round(probability * 100, 2)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
