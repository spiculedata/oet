#!/usr/bin/env bash
# OET BigQuery setup — creates the isolated `oet` dataset + GA4-shaped `oet_events` table.
# Idempotent: re-running is safe (existing dataset/table are left as-is).
#
#   bash deploy/bq-setup.sh [PROJECT] [LOCATION]
#   defaults: PROJECT=oet-telemetry  LOCATION=US
#
# Requires: gcloud/bq authenticated (`gcloud auth login`) with BigQuery admin on the project.
set -euo pipefail

PROJECT="${1:-oet-telemetry}"
LOCATION="${2:-US}"
DATASET="oet"
TABLE="oet_events"
SCHEMA="docs/spec/bigquery-schema.json"

echo ">> OET BigQuery setup — project=${PROJECT} location=${LOCATION} dataset=${DATASET}"

if bq --project_id="${PROJECT}" show --dataset "${DATASET}" >/dev/null 2>&1; then
  echo "   dataset ${PROJECT}:${DATASET} already exists — leaving as-is."
else
  echo "   creating dataset ${PROJECT}:${DATASET} ..."
  bq --project_id="${PROJECT}" --location="${LOCATION}" mk -d \
    --description "OET — Open Event Telemetry destination (GA4-shaped). Isolated from app analytics." \
    "${DATASET}"
fi

if bq --project_id="${PROJECT}" show "${DATASET}.${TABLE}" >/dev/null 2>&1; then
  echo "   table ${PROJECT}:${DATASET}.${TABLE} already exists — leaving as-is."
else
  echo "   creating table ${PROJECT}:${DATASET}.${TABLE} from ${SCHEMA} ..."
  bq --project_id="${PROJECT}" mk --table "${DATASET}.${TABLE}" "${SCHEMA}"
fi

echo ">> Done. Table ready: ${PROJECT}:${DATASET}.${TABLE}"
echo "   Union view (optional): docs/spec/union-view.sql — fill in your GA4 export dataset, then:"
echo "     bq --project_id=${PROJECT} query --use_legacy_sql=false < docs/spec/union-view.sql"
