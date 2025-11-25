# default: fetch last 5 releases
python atlas_to_oscal.py --out atlas-oscal-catalog.json

# fetch last 10 releases
python atlas_to_oscal.py --out atlas-oscal-catalog.json --revisions-from-releases 10

# disable calling GitHub releases (only record current dataset + export)
python atlas_to_oscal.py --out atlas-oscal-catalog.json --revisions-from-releases 0

# preserve prior revisions from a previous file as well
python atlas_to_oscal.py --out atlas-oscal-catalog.json --carry-revisions-from previous.json

