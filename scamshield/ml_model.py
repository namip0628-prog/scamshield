import os
from functools import lru_cache
from pathlib import Path

import joblib

_MODEL_FORMAT_VERSION = 1
_DEFAULT_MODEL_PATH = (
    Path(__file__).resolve().parent.parent
    / "model_artifacts"
    / "scamshield_text_classifier.joblib"
)


@lru_cache(maxsize=4)
def _load_artifact(path):
    model_path = Path(path)
    if not model_path.is_file():
        return None

    artifact = joblib.load(model_path)
    if not isinstance(artifact, dict) or artifact.get("format_version") != _MODEL_FORMAT_VERSION:
        raise ValueError(f"Unsupported ScamShield model artifact: {model_path}")
    estimator = artifact.get("estimator")
    if not callable(getattr(estimator, "predict", None)):
        raise ValueError(f"Model artifact has no usable estimator: {model_path}")
    if set(getattr(estimator, "classes_", ())) != {"legitimate", "scam"}:
        raise ValueError(f"Model artifact has unexpected labels: {model_path}")
    return artifact


def load_artifact():
    model_path = os.environ.get("SCAMSHIELD_MODEL_PATH", str(_DEFAULT_MODEL_PATH))
    return _load_artifact(model_path)


def predict_scam(text):
    artifact = load_artifact()
    if artifact is None:
        return None
    prediction = artifact["estimator"].predict([text])[0]
    if prediction not in {"legitimate", "scam"}:
        raise ValueError(f"Unexpected ScamShield model prediction: {prediction!r}")
    return prediction == "scam"
