# project imports
from commons.impact import extract_vuln_impact


def extract_and(children):
    parts = list()
    vendors = list()
    products = list()

    for child in children:
        operator = child.get('operator')

        if operator == 'AND':
            inner_child = child.get('children', None)
            cpe_match = child.get('cpe_match', None)

            if inner_child:
                tmp_parts, tmp_vendors, tmp_products = extract_and(inner_child)
            else:
                tmp_parts, tmp_vendors, tmp_products = extract_or(cpe_match)
        elif operator == 'OR':
            cpe_match = child.get('cpe_match', None)
            tmp_parts, tmp_vendors, tmp_products = extract_or(cpe_match)

        parts += tmp_parts
        vendors += tmp_vendors
        products += tmp_products

    return parts, vendors, products


def extract_or(cpe_match):
    parts = list()
    vendors = list()
    products = list()

    for cpe in cpe_match:
        '''
            CPE uri has the following format:

            cpe:<cpe-version>:<part>:<vendor>:<product>:*:*:*:*:*:*:*:*
        '''

        _, _, part, vendor, product, *_ = cpe.get('cpe23Uri').split(':')

        parts.append(part)
        vendors.append(vendor)
        products.append(product)

    return parts, vendors, products


def extract_part_vendor_product(nodes):
    parts = list()
    vendors = list()
    products = list()

    for node in nodes:
        operator = node.get('operator')

        if operator == 'AND':
            children = node.get('children', None)
            cpe_match = node.get('cpe_match', None)

            if children:
                parts, vendors, products = extract_and(children)
            elif cpe_match:
                parts, vendors, products = extract_or(cpe_match)

        elif operator == 'OR':
            cpe_match = node.get('cpe_match', None)

            if cpe_match:
                parts, vendors, products = extract_or(cpe_match)

    return list(set(parts)), list(set(vendors)), list(set(products))


def extract_attacks_and_description(cve):
    descriptions = cve.get('description_data')
    description = ''

    attack_list = list()
    for desc in descriptions:
        if desc.get('value'):
            description += f"\n{desc.get('value')}"
        attack_list += extract_vuln_impact(desc.get('value'))

    return list(set(attack_list)), description


def extract_cwe(cve):

    cwes = list()
    for problem_type in cve.get('problemtype_data'):
        for cwe in problem_type.get('description'):
            value = cwe.get('value')
            cwes.append(value)

    return list(set(cwes))


def extract_metrics(cve):
    if 'baseMetricV3' in cve.keys():
        baseMetricV3 = cve.get('baseMetricV3')
        cvssV3 = baseMetricV3.get('cvssV3')

        data = {
            'cvssType': 3,
            'attackVector': cvssV3.get('attackVector'),
            'attackComplexity': cvssV3.get('attackComplexity'),
            'privilegesRequired': cvssV3.get('privilegesRequired'),
            'userInteraction': cvssV3.get('userInteraction'),
            'scope': cvssV3.get('scope'),
            'confidentialityImpact': cvssV3.get('confidentialityImpact'),
            'integrityImpact': cvssV3.get('integrityImpact'),
            'availabilityImpact': cvssV3.get('availabilityImpact'),
            'baseScore': cvssV3.get('baseScore'),
            'baseSeverity': cvssV3.get('baseSeverity'),
            'exploitabilityScore': baseMetricV3.get('exploitabilityScore'),
            'impactScore': baseMetricV3.get('impactScore')
        }

    elif 'baseMetricV2' in cve.keys():
        baseMetricV2 = cve.get('baseMetricV2')
        cvssV2 = baseMetricV2.get('cvssV2')

        user_interation = None
        ui = baseMetricV2.get('userInteractionRequired', None)

        if ui is not None:
            user_interation = 'REQUIRED' if ui else 'NONE'

        data = {
            'cvssType': 2,
            'attackVector': cvssV2.get('accessVector'),
            'attackComplexity': cvssV2.get('accessComplexity'),
            'privilegesRequired': cvssV2.get('authentication'),
            'userInteraction': user_interation,
            'scope': None,
            'confidentialityImpact': cvssV2.get('confidentialityImpact'),
            'integrityImpact': cvssV2.get('integrityImpact'),
            'availabilityImpact': cvssV2.get('availabilityImpact'),
            'baseScore': cvssV2.get('baseScore'),
            'baseSeverity': baseMetricV2.get('severity'),
            'exploitabilityScore': baseMetricV2.get('exploitabilityScore'),
            'impactScore': baseMetricV2.get('impactScore'),
        }
    else:
        data = {
            'cvssType': None,
            'attackVector': None,
            'attackComplexity': None,
            'privilegesRequired': None,
            'userInteraction': None,
            'scope': None,
            'confidentialityImpact': None,
            'integrityImpact': None,
            'availabilityImpact': None,
            'baseScore': None,
            'baseSeverity': None,
            'exploitabilityScore': None,
            'impactScore': None,
        }

    return data
