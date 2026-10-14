
from pathlib import Path

import joblib

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "artifacts" / "code_risk_model.joblib"


def load_ml_model():
    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            "ML model not found. Run python train_ml.py first."
        )
    return joblib.load(MODEL_PATH)


def predict_code_risk(source_code: str) -> dict:
    if not source_code.strip():
        raise ValueError("Please provide Python code.")

    model = load_ml_model()

    prediction = int(model.predict([source_code])[0])
    probabilities = model.predict_proba([source_code])[0]

    classes = list(model.named_steps["classifier"].classes_)
    risky_index = classes.index(1)
    risk_score = float(probabilities[risky_index])

    return {
        "prediction": (
            "Potentially risky pattern"
            if prediction == 1
            else "No known risky pattern detected"
        ),
        "risk_score": risk_score,
        "warning": (
            "This experimental model learned from only 40 "
            "illustrative examples. Its score is not a calibrated "
            "probability of a real vulnerability."
        ),
    }


if __name__ == "__main__":
    sample = "result = eval(user_input)"
    result = predict_code_risk(sample)

    print("Prediction:", result["prediction"])
    print(f"Model risk score: {result['risk_score']:.1%}")
    print(result["warning"])
