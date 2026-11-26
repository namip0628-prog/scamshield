import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import FeatureUnion, Pipeline

_LABELS = ("legitimate", "scam")
_MIN_SAMPLES_PER_LABEL = 50
_MIN_CAMPAIGNS_PER_LABEL = 5


def _read_dataset(path):
    examples = {}
    with path.open(newline="", encoding="utf-8-sig") as source:
        reader = csv.DictReader(source)
        required_columns = {"text", "label", "campaign_id"}
        if not reader.fieldnames or not required_columns.issubset(reader.fieldnames):
            raise ValueError(
                "CSV must have text,label,campaign_id columns; campaign_id is used "
                "to keep related messages together during validation."
            )
        for line_number, row in enumerate(reader, start=2):
            text = " ".join((row.get("text") or "").split())
            label = (row.get("label") or "").strip().casefold()
            campaign_id = (row.get("campaign_id") or "").strip()
            if not text or label not in _LABELS or not campaign_id:
                raise ValueError(
                    f"Invalid row {line_number}: text, campaign_id, and label "
                    f"({', '.join(_LABELS)}) are required."
                )
            normalized = text.casefold()
            existing = examples.get(normalized)
            if existing and existing[1] != label:
                raise ValueError(
                    f"Conflicting labels for duplicate text on row {line_number}."
                )
            if existing is None:
                examples[normalized] = (text, label, campaign_id)

    if not examples:
        raise ValueError("The training CSV contains no examples.")

    texts, labels, groups = zip(*examples.values())
    counts = Counter(labels)
    campaign_counts = defaultdict(set)
    for label, group in zip(labels, groups):
        campaign_counts[label].add(group)
    for label in _LABELS:
        if counts[label] < _MIN_SAMPLES_PER_LABEL:
            raise ValueError(
                f"Need at least {_MIN_SAMPLES_PER_LABEL} distinct examples labeled "
                f"{label}; found {counts[label]}."
            )
        if len(campaign_counts[label]) < _MIN_CAMPAIGNS_PER_LABEL:
            raise ValueError(
                f"Need at least {_MIN_CAMPAIGNS_PER_LABEL} campaign_id groups "
                f"labeled {label}; found {len(campaign_counts[label])}."
            )
    return list(texts), list(labels), list(groups)


def _grouped_holdout(texts, labels, groups):
    splitter = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)
    candidates = []
    for train_indices, test_indices in splitter.split(texts, labels, groups):
        train_labels = {labels[index] for index in train_indices}
        test_labels = {labels[index] for index in test_indices}
        if train_labels == set(_LABELS) and test_labels == set(_LABELS):
            test_counts = Counter(labels[index] for index in test_indices)
            candidates.append((min(test_counts.values()), train_indices, test_indices))
    if not candidates:
        raise ValueError(
            "Could not make a campaign-separated train/test split containing both "
            "labels. Add more distinct campaigns for each label."
        )
    _, train_indices, test_indices = max(candidates, key=lambda candidate: candidate[0])
    return train_indices, test_indices


def _new_estimator():
    text_features = FeatureUnion(
        [
            (
                "word",
                TfidfVectorizer(
                    analyzer="word",
                    ngram_range=(1, 2),
                    min_df=2,
                    strip_accents="unicode",
                    sublinear_tf=True,
                ),
            ),
            (
                "character",
                TfidfVectorizer(
                    analyzer="char",
                    ngram_range=(3, 5),
                    min_df=2,
                    sublinear_tf=True,
                ),
            ),
        ]
    )
    return Pipeline(
        [
            ("features", text_features),
            (
                "classifier",
                LogisticRegression(
                    class_weight="balanced",
                    max_iter=2000,
                    random_state=42,
                ),
            ),
        ]
    )


def train_model(input_path, output_path):
    texts, labels, groups = _read_dataset(input_path)
    train_indices, test_indices = _grouped_holdout(texts, labels, groups)
    train_texts = [texts[index] for index in train_indices]
    train_labels = [labels[index] for index in train_indices]
    test_texts = [texts[index] for index in test_indices]
    test_labels = [labels[index] for index in test_indices]

    evaluation_model = _new_estimator()
    evaluation_model.fit(train_texts, train_labels)
    predictions = evaluation_model.predict(test_texts)
    report = classification_report(
        test_labels,
        predictions,
        labels=list(_LABELS),
        output_dict=True,
        zero_division=0,
    )
    metrics = {
        "balanced_accuracy": balanced_accuracy_score(test_labels, predictions),
        "legitimate_precision": report["legitimate"]["precision"],
        "legitimate_recall": report["legitimate"]["recall"],
        "scam_precision": report["scam"]["precision"],
        "scam_recall": report["scam"]["recall"],
        "confusion_matrix_labels": list(_LABELS),
        "confusion_matrix": confusion_matrix(
            test_labels,
            predictions,
            labels=list(_LABELS),
        ).tolist(),
    }
    print("Campaign-separated holdout metrics:")
    print(json.dumps(metrics, indent=2))
    print(
        f"Training examples: {len(train_indices)}; "
        f"holdout examples: {len(test_indices)}."
    )
    if metrics["scam_precision"] < 0.70 or metrics["scam_recall"] < 0.60:
        raise ValueError(
            "Holdout scam precision must be at least 0.70 and recall at least 0.60 "
            "before a model artifact is saved. Review labels/data and try again."
        )

    final_estimator = _new_estimator()
    final_estimator.fit(texts, labels)
    artifact = {
        "format_version": 1,
        "estimator": final_estimator,
        "labels": list(_LABELS),
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "example_count": len(texts),
        "campaign_count": len(set(groups)),
        "holdout_metrics": metrics,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, output_path)
    print(f"Saved validated model artifact to {output_path}.")


def main():
    parser = argparse.ArgumentParser(
        description="Train and validate ScamShield's text classifier."
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("data/scam_training.csv"),
        help="CSV with text,label,campaign_id columns.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("model_artifacts/scamshield_text_classifier.joblib"),
        help="Output path for the validated model artifact.",
    )
    arguments = parser.parse_args()
    try:
        train_model(arguments.input, arguments.output)
    except (OSError, ValueError) as error:
        print(f"Model training failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
