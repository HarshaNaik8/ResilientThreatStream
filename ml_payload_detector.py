"""
ml_payload_detector.py — Spark MLlib detector over the 1,500 payload dimensions.

Pipeline (one persisted ``PipelineModel``)::

    payload (array<double>, 1500) --ArrayToVector--> features
    features --PCA(k=32)--> pca_features
    [pca_features, ttl, total_len, t_delta, protocol_is_tcp] --VectorAssembler--> model_input
    model_input --RandomForestClassifier--> ml_prob (P[attack]), ml_attack

Hybrid detector = fast deterministic metadata rules  OR  ML payload inference.
The rules keep their ~98% precision on volumetric attacks; the ML stage recovers
the application-layer attacks (Infiltration, Web attacks, Bot, ...) where the
metadata rules have 0% recall.

ZERO DATA LEAKAGE: the ground-truth ``label`` is used here ONLY to derive the
training target (``is_attack``) and for post-prediction evaluation.  It is never
an input feature, and inference (``score_dataframe``) never reads it.

Usage::

    python ml_payload_detector.py train --input data/stream_sample_10k.csv \\
        --model-dir models/payload_rf --report docs/ml_benchmark.json
"""

import os as _os
import sys as _sys
# Python UDF workers must use the same interpreter as the driver (venv), not system python.
_os.environ.setdefault("PYSPARK_PYTHON", _sys.executable)
_os.environ.setdefault("PYSPARK_DRIVER_PYTHON", _sys.executable)

import argparse
import json
import os
import time
from typing import Dict, Optional

from pyspark.ml import Pipeline, PipelineModel
from pyspark.ml.classification import RandomForestClassifier
from pyspark.ml.feature import PCA, VectorAssembler
from pyspark.ml.functions import array_to_vector, vector_to_array
from pyspark.sql import DataFrame, SparkSession
from pyspark.sql import functions as F

PAYLOAD_DIM = 1500
PAYLOAD_COLUMNS = [f"payload_byte_{i}" for i in range(1, PAYLOAD_DIM + 1)]
PCA_K = 32
META_FEATURES = ["ttl_f", "total_len_f", "t_delta_f", "is_tcp"]
DEFAULT_THRESHOLD = 0.5


# ----------------------------------------------------------------------------
# Feature construction (shared by training and streaming inference)
# ----------------------------------------------------------------------------
def with_features_from_payload_array(df: DataFrame, payload_col: str = "payload") -> DataFrame:
    """Streaming path: ``payload`` is array<int> in the Kafka JSON message."""
    return _add_meta_features(
        df.withColumn("features", array_to_vector(F.col(payload_col).cast("array<double>")))
    )


def with_features_from_columns(df: DataFrame) -> DataFrame:
    """Training path: 1,500 ``payload_byte_N`` columns of the CSV."""
    arr = F.array(*[F.col(c).cast("double") for c in PAYLOAD_COLUMNS])
    return _add_meta_features(df.withColumn("features", array_to_vector(arr)))


def _add_meta_features(df: DataFrame) -> DataFrame:
    return (df
            .withColumn("ttl_f", F.coalesce(F.col("ttl").cast("double"), F.lit(0.0)))
            .withColumn("total_len_f", F.coalesce(F.col("total_len").cast("double"), F.lit(0.0)))
            .withColumn("t_delta_f", F.coalesce(F.col("t_delta").cast("double"), F.lit(0.0)))
            .withColumn("is_tcp", F.when(F.lower(F.col("protocol")) == "tcp", 1.0).otherwise(0.0)))


def with_attack_target(df: DataFrame) -> DataFrame:
    """Derive the binary TRAINING target from the label (training/evaluation only)."""
    return df.withColumn(
        "is_attack",
        F.when(F.upper(F.trim(F.col("label"))) != "BENIGN", 1.0).otherwise(0.0),
    )


def build_pipeline(num_trees: int = 60, max_depth: int = 12, k: int = PCA_K, seed: int = 42) -> Pipeline:
    pca = PCA(k=k, inputCol="features", outputCol="pca_features")
    assembler = VectorAssembler(inputCols=["pca_features"] + META_FEATURES, outputCol="model_input")
    rf = RandomForestClassifier(
        featuresCol="model_input", labelCol="is_attack", predictionCol="ml_attack_pred",
        probabilityCol="probability", rawPredictionCol="rawPrediction",
        numTrees=num_trees, maxDepth=max_depth, seed=seed, subsamplingRate=0.8,
    )
    return Pipeline(stages=[pca, assembler, rf])


# ----------------------------------------------------------------------------
# Inference
# ----------------------------------------------------------------------------
def score_dataframe(model: PipelineModel, df: DataFrame, threshold: float = DEFAULT_THRESHOLD) -> DataFrame:
    """
    Add ``ml_attack_prob`` and ``ml_attack`` to a DataFrame that already has a
    ``features`` vector and the metadata features.  Heavy intermediate columns
    are dropped so only light columns travel to executors afterwards.
    """
    scored = model.transform(df)
    scored = scored.withColumn("ml_attack_prob", vector_to_array(F.col("probability"))[1])
    scored = scored.withColumn("ml_attack", (F.col("ml_attack_prob") >= F.lit(float(threshold))).cast("int"))
    drop = [c for c in ("features", "pca_features", "model_input", "rawPrediction",
                        "probability", "ml_attack_pred", "payload") if c in scored.columns]
    return scored.drop(*drop)


def apply_hybrid(df: DataFrame) -> DataFrame:
    """
    Hybrid decision.  Expects ``predicted_attack`` (rule verdict) and ``ml_attack``.
    Keeps the rule verdict in ``rule_attack`` and overwrites ``predicted_attack``
    with ``rule OR ml`` so all downstream sinks/metrics work unchanged.
    """
    return (df
            .withColumn("rule_attack", F.col("predicted_attack"))
            .withColumn("predicted_attack",
                        F.when((F.col("rule_attack") == 1) | (F.col("ml_attack") == 1), 1).otherwise(0)))


def load_model(model_dir: str) -> PipelineModel:
    return PipelineModel.load(model_dir)


# ----------------------------------------------------------------------------
# Evaluation
# ----------------------------------------------------------------------------
def confusion_metrics(df: DataFrame, pred_col: str, truth_col: str = "is_attack") -> Dict[str, float]:
    row = (df.agg(
        F.sum(F.when((F.col(pred_col) == 1) & (F.col(truth_col) == 1), 1).otherwise(0)).alias("tp"),
        F.sum(F.when((F.col(pred_col) == 1) & (F.col(truth_col) == 0), 1).otherwise(0)).alias("fp"),
        F.sum(F.when((F.col(pred_col) == 0) & (F.col(truth_col) == 0), 1).otherwise(0)).alias("tn"),
        F.sum(F.when((F.col(pred_col) == 0) & (F.col(truth_col) == 1), 1).otherwise(0)).alias("fn"),
    ).collect()[0])
    return metrics_from_counts(int(row.tp or 0), int(row.fp or 0), int(row.tn or 0), int(row.fn or 0))


def metrics_from_counts(tp: int, fp: int, tn: int, fn: int) -> Dict[str, float]:
    total = tp + fp + tn + fn
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4),
        "accuracy": round((tp + tn) / total, 4) if total else 0.0,
        "fpr": round(fp / (fp + tn), 4) if (fp + tn) else 0.0,
    }


def rule_predictions(df: DataFrame, burst_delta: float = 0.00005) -> DataFrame:
    """Baseline metadata heuristic (same policy as spark_consumer / threat_detector)."""
    burst = (F.col("t_delta") >= 0.0) & (F.col("t_delta") <= F.lit(burst_delta))
    ttl_invalid = F.col("ttl").isNotNull() & ((F.col("ttl") < 1) | (F.col("ttl") > 255))
    ttl_susp = F.col("ttl").isNotNull() & (F.col("ttl").isin(61, 62) | ((F.col("ttl") > 0) & (F.col("ttl") < 32)))
    len_invalid = F.col("total_len").isNotNull() & (F.col("total_len") < 28)
    len_susp = F.col("total_len").isNotNull() & ((F.col("total_len") > 1500) | F.col("total_len").isin(40, 48, 52, 60))
    invalid = ttl_invalid | len_invalid
    return df.withColumn(
        "rule_pred",
        F.when(invalid | (burst & ttl_susp) | (burst & len_susp), 1).otherwise(0),
    )


def per_attack_recall(df: DataFrame, pred_col: str) -> Dict[str, Dict[str, float]]:
    """Recall per ground-truth attack family (evaluation only)."""
    rows = (df.filter(F.col("is_attack") == 1)
              .groupBy("label")
              .agg(F.count("*").alias("n"), F.sum(F.col(pred_col)).alias("detected"))
              .collect())
    return {r.label: {"n": int(r.n), "detected": int(r.detected or 0),
                      "recall": round((r.detected or 0) / r.n, 4)} for r in rows}


# ----------------------------------------------------------------------------
# Training CLI
# ----------------------------------------------------------------------------
def get_spark(app: str = "PayloadMLDetector", driver_memory: str = "3g") -> SparkSession:
    return (SparkSession.builder.appName(app)
            .config("spark.driver.memory", driver_memory)
            .config("spark.sql.shuffle.partitions", "8")
            .config("spark.ui.showConsoleProgress", "false")
            .getOrCreate())


def train_and_evaluate(spark: SparkSession, input_csv: str, model_dir: str,
                       train_fraction: float = 0.8, num_trees: int = 60, max_depth: int = 12,
                       threshold: float = DEFAULT_THRESHOLD, seed: int = 42, pca_k: int = PCA_K,
                       report_path: Optional[str] = None) -> Dict:
    raw = spark.read.csv(input_csv, header=True, inferSchema=False)
    # One single projection (never loop withColumn x1500: plan analysis is quadratic)
    raw = raw.select(
        *[F.col(c).cast("double").alias(c) for c in PAYLOAD_COLUMNS],
        F.col("ttl").cast("double").alias("ttl"),
        F.col("total_len").cast("double").alias("total_len"),
        F.col("t_delta").cast("double").alias("t_delta"),
        "protocol", "label",
    )
    df = with_attack_target(with_features_from_columns(raw))
    df = df.select("features", *META_FEATURES, "is_attack", "label", "ttl", "total_len", "t_delta", "protocol")
    df = df.repartition(8).cache()
    train_df, test_df = df.randomSplit([train_fraction, 1.0 - train_fraction], seed=seed)
    train_df.cache()
    n_train, n_test = train_df.count(), test_df.count()
    print(f"[ML] train={n_train:,} test={n_test:,}")

    t0 = time.time()
    model = build_pipeline(num_trees=num_trees, max_depth=max_depth, k=pca_k, seed=seed).fit(train_df)
    fit_s = time.time() - t0
    pca_model = model.stages[0]
    explained = float(sum(pca_model.explainedVariance.toArray()))
    print(f"[ML] fit {fit_s:.1f}s | PCA k={pca_k} explained variance = {explained:.4f}")

    t1 = time.time()
    scored = score_dataframe(model, test_df, threshold)
    scored = rule_predictions(scored)
    scored = (scored.withColumn("hybrid_pred",
                                F.when((F.col("rule_pred") == 1) | (F.col("ml_attack") == 1), 1).otherwise(0))
                    .cache())
    scored.count()
    infer_s = time.time() - t1

    report = {
        "train_rows": n_train, "test_rows": n_test, "threshold": threshold,
        "pca_k": pca_k, "pca_explained_variance": round(explained, 4),
        "num_trees": num_trees, "max_depth": max_depth,
        "fit_seconds": round(fit_s, 1), "inference_seconds_test": round(infer_s, 1),
        "rules_only": confusion_metrics(scored, "rule_pred"),
        "ml_only": confusion_metrics(scored, "ml_attack"),
        "hybrid": confusion_metrics(scored, "hybrid_pred"),
        "per_attack_recall": {
            "rules_only": per_attack_recall(scored, "rule_pred"),
            "ml_only": per_attack_recall(scored, "ml_attack"),
            "hybrid": per_attack_recall(scored, "hybrid_pred"),
        },
        "note": "Held-out random split of the sample; label used for training target and evaluation only.",
    }
    os.makedirs(os.path.dirname(model_dir) or ".", exist_ok=True)
    model.write().overwrite().save(model_dir)
    print(f"[ML] model saved to {model_dir}")
    if report_path:
        os.makedirs(os.path.dirname(report_path) or ".", exist_ok=True)
        with open(report_path, "w") as fh:
            json.dump(report, fh, indent=2)
        print(f"[ML] report written to {report_path}")
    return report


def main():
    ap = argparse.ArgumentParser(description="Train/evaluate the Spark MLlib payload detector.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    tr = sub.add_parser("train", help="Train PCA+RandomForest on a labelled CSV and benchmark vs rules")
    tr.add_argument("--input", default="data/stream_sample_10k.csv")
    tr.add_argument("--model-dir", default="models/payload_rf")
    tr.add_argument("--report", default="docs/ml_benchmark.json")
    tr.add_argument("--trees", type=int, default=60)
    tr.add_argument("--depth", type=int, default=12)
    tr.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)
    tr.add_argument("--pca-k", type=int, default=PCA_K)
    tr.add_argument("--driver-memory", default="3g")
    args = ap.parse_args()
    spark = get_spark(driver_memory=args.driver_memory)
    spark.sparkContext.setLogLevel("ERROR")
    rep = train_and_evaluate(spark, args.input, args.model_dir, num_trees=args.trees,
                             max_depth=args.depth, threshold=args.threshold, pca_k=args.pca_k, report_path=args.report)
    for name in ("rules_only", "ml_only", "hybrid"):
        m = rep[name]
        print(f"{name:11s} P={m['precision']:.4f} R={m['recall']:.4f} F1={m['f1']:.4f} "
              f"Acc={m['accuracy']:.4f} FPR={m['fpr']:.4f}")
    spark.stop()


if __name__ == "__main__":
    main()
