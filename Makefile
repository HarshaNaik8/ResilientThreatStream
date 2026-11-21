# Developer entry points. Uses the Python 3.11 venv (PySpark 3.5.6 does not support 3.14).
PY      ?= .venv311/bin/python
export JAVA_HOME ?= /usr/lib/jvm/java-17-openjdk-amd64
export PYSPARK_PYTHON ?= $(abspath $(PY))

.PHONY: help test services train batch backup drill shards-up shards-down shards-status shard-demo data-loss-demo dashboard

help:            ## list targets
	@grep -E '^[a-z-]+:.*##' Makefile | sed 's/:.*##/ -  /'
test:            ## run the full unit/integration suite
	$(PY) -W ignore -m unittest discover -s . -p "test_*.py"
services:        ## start MongoDB (standalone + sharded cluster) + Kafka and the 4-partition topic
	scripts/start_services.sh
train:           ## train the PCA+RandomForest payload model
	$(PY) ml_payload_detector.py train --input data/stream_sample_10k.csv
batch:           ## batch layer: Spark SQL over the Parquet lake -> rollups
	$(PY) batch_analytics.py --lake-dir data/lake
backup:          ## backup + verify + rotate (Mongo, checkpoints, lake)
	$(PY) scripts/backup_manager.py run --checkpoint-dir checkpoints/stage8_lambda --lake-dir data/lake
drill:           ## disaster-recovery drill: backup, restore to scratch DB, compare, report RTO
	$(PY) -m scripts.dr_drill --lake-dir data/lake
shards-up:       ## start the sharded + replicated MongoDB cluster (mongos :27019)
	scripts/sharded_cluster.sh start
shards-down:     ## stop the sharded cluster
	scripts/sharded_cluster.sh stop
shards-status:   ## shards, node roles, documents per shard
	scripts/sharded_cluster.sh status
shard-demo:      ## load alerts through mongos, show balance/routing, kill a shard primary
	$(PY) -m scripts.shard_demo --failover
data-loss-demo:  ## simulate data loss and recover (backup restore + lake rebuild)
	$(PY) -m scripts.data_loss_demo
dashboard:       ## Streamlit SOC dashboard
	$(PY) -m streamlit run dashboard.py
