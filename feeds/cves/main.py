# python imports
import json
import logging
from gzip import GzipFile
from dateutil.parser import parse, ParserError
from urllib.request import urlopen

# project imports
from commons.file import save_list_to_csv

# local imports
from .constants import BASE_URL
from .constants import OUTPUT_FILE_PATH
from .constants import START_YEAR
from .constants import END_YEAR
from .utils import extract_attacks_and_description
from .utils import extract_cwe
from .utils import extract_part_vendor_product
from .utils import extract_metrics


log = logging.getLogger(__name__)


def download_cves():
    cves = list()

    for year in range(START_YEAR, END_YEAR):

        try:
            with urlopen(BASE_URL.format(year)) as response:
                with GzipFile(fileobj=response) as uncompressed:
                    file = json.loads(uncompressed.read())
        except Exception as e:
            log.error(f'\tCould not download json file: {e}')

        for cve in file.get('CVE_Items'):
            id = cve.get('cve').get('CVE_data_meta').get('ID')

            description_data = cve.get('cve').get('description')
            attacks, description = extract_attacks_and_description(description_data)
            attacks = attacks if attacks else None

            problem_type = cve.get('cve').get('problemtype')
            cwes = extract_cwe(problem_type)

            nodes = cve.get('configurations').get('nodes')
            parts, vendors, products = extract_part_vendor_product(nodes)

            impact = cve.get('impact')
            base_metrics = extract_metrics(impact)

            try:
                published_date = cve.get('publishedDate')
                published_date = parse(published_date).strftime('%m/%d/%Y')
            except ParserError:
                log.error('\tError parsing vulnerability published date')

            try:
                modified_date = cve.get('lastModifiedDate')
                modified_date = parse(modified_date).strftime('%m/%d/%Y')
            except ParserError:
                log.error('\tError parsing vulnerability modification date')

            cves.append([
                id, cwes, parts, vendors, products,
                description, *base_metrics.values(),
                attacks, published_date, modified_date])

    header = [
        'cve_id', 'cwe', 'part', 'vendor', 'product', 'description', 'cvss_type', 'attack_vector',
        'attack_complexity', 'privileges_required', 'user_interaction', 'scope',
        'confidentiality_impact', 'integrity_impact', 'availability_impact',
        'base_score', 'base_severity', 'exploitability_score', 'impact_score',
        'attack_type', 'cve_published_date', 'cve_last_modified_date']
    save_list_to_csv(OUTPUT_FILE_PATH, header, cves)
