# local imports
from .constants import IMPACT_DICT


def extract_vuln_impact(desc):
    desc = desc.lower()
    impacts = list()

    for key, items in IMPACT_DICT.items():
        for item in items:
            result = desc.find(item)
            if result > 0:
                impacts.append(key)

    return impacts
