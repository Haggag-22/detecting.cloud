#!/usr/bin/env bash
#
# Load SOF-ELK's Elasticsearch templates into an authenticated cluster.
#
# SOF-ELK ships supporting-scripts/load_all_dashboards.sh, but it curls
# Elasticsearch with no credentials and reads /usr/share/kibana/package.json for
# the Kibana version — neither of which holds outside the SOF-ELK VM. This does
# the template half of that job against a cluster with xpack.security enabled.
#
# MUST be run before the first ingest. Without these templates Elasticsearch
# applies dynamic mapping: source.ip becomes a string instead of an ip, ports
# become strings instead of integers, and the SOF-ELK dashboards render empty
# or wrong with no error anywhere. Fixing it afterwards means reindexing,
# because mappings cannot be changed in place.
#
# Usage:
#   ES_PASSWORD=... ./scripts/load-sof-elk-templates.sh [ES_URL] [SOF_ELK_DIR]

set -euo pipefail

ES_URL="${1:-${ES_URL:-http://localhost:9200}}"
SOF_ELK_DIR="${2:-${SOF_ELK_DIR:-/usr/local/sof-elk}}"
ES_USER="${ES_USER:-elastic}"
ES_PASSWORD="${ES_PASSWORD:-changeme}"

TEMPLATE_DIR="${SOF_ELK_DIR}/lib/elasticsearch_templates"

if [[ ! -d "${TEMPLATE_DIR}" ]]; then
  echo "ERROR: ${TEMPLATE_DIR} not found." >&2
  echo "       Point SOF_ELK_DIR at a SOF-ELK checkout, or see the README for" >&2
  echo "       where the repo has to live." >&2
  exit 2
fi

echo "Elasticsearch: ${ES_URL}"
echo "SOF-ELK:       ${SOF_ELK_DIR}"
echo

if ! curl -sf -u "${ES_USER}:${ES_PASSWORD}" "${ES_URL}/_cluster/health" >/dev/null; then
  echo "ERROR: cannot reach ${ES_URL} as ${ES_USER}. Check ES_PASSWORD." >&2
  exit 3
fi

failed=0

put_template() {
  local kind="$1" name="$2" file="$3"
  local code
  code=$(curl -s -o /tmp/tmpl-resp.$$ -w '%{http_code}' \
    -u "${ES_USER}:${ES_PASSWORD}" \
    -H 'Content-Type: application/json' \
    -X PUT "${ES_URL}/_${kind}/${name}" \
    --data-binary "@${file}")

  if [[ "${code}" =~ ^2 ]]; then
    printf '  ok    %-12s %s\n' "${kind}" "${name}"
  else
    printf '  FAIL  %-12s %s (HTTP %s)\n' "${kind}" "${name}" "${code}" >&2
    cat /tmp/tmpl-resp.$$ >&2
    echo >&2
    failed=$((failed + 1))
  fi
  rm -f /tmp/tmpl-resp.$$
}

# Component templates first: the index templates reference them by name via
# "composed_of", and Elasticsearch rejects an index template whose components
# do not yet exist.
echo "Component templates:"
shopt -s nullglob
for file in "${TEMPLATE_DIR}"/component_templates/component-*.json; do
  name=$(basename "${file}" .json)
  name="${name#component-}"
  put_template component_template "${name}" "${file}"
done

echo
echo "Index templates:"
for file in "${TEMPLATE_DIR}"/index_templates/index-*.json; do
  name=$(basename "${file}" .json)
  name="${name#index-}"
  put_template index_template "${name}" "${file}"
done

echo
if (( failed > 0 )); then
  echo "ERROR: ${failed} template(s) failed to load. Do NOT start ingest --" >&2
  echo "       fields will be mapped by dynamic inference and the only fix" >&2
  echo "       afterwards is a reindex." >&2
  exit 1
fi

echo "All templates loaded. Verify the AWS one with:"
echo "  curl -s -u ${ES_USER}:\$ES_PASSWORD '${ES_URL}/_index_template/aws' | jq '.index_templates[0].index_template.index_patterns'"
