#python -m venv .venv && source .venv/bin/activate
#pip install requests
python d3fend_to_oscal_catalog.py --out d3fend-oscal-catalog.json
# or pin versions / URLs explicitly:
#python d3fend_to_oscal_catalog.py \
#  --d3fend-version 1.2.0 \
#  --oscal-version 1.1.6 \
#  --out d3fend-oscal-catalog.json

