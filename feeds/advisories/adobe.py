# python imports
import re
import logging
from dateutil.parser import ParserError
from urllib.parse import urljoin

# third-party imports
from requests.exceptions import ConnectionError

# project imports
from commons.file import save_list_to_csv
from commons.parse import request_clean_page
from commons.parse import extract_table_info

# local imports
from .constants import ADOBE_BASE_URL
from .constants import ADOBE_SECURITY_BULLETIN
from .constants import ADOBE_OUTPUT_FILE_PATH
from .constants import ADOBE_IMPACT_MAP


log = logging.getLogger(__name__)


def download_adobe_advisory():

    url = urljoin(ADOBE_BASE_URL, ADOBE_SECURITY_BULLETIN)

    try:
        soup = request_clean_page(url)
    except ConnectionError:
        log.error(f'\tCould not connect to {url}.')
        return

    advisories_url = list()

    for table in soup.find_all('table'):
        for link in table.find_all('a'):
            href = link.attrs['href']

            if 'http' not in href:
                href = urljoin(ADOBE_BASE_URL, href)

            advisories_url.append(href)

    rows = list()

    for url in advisories_url:

        try:
            soup = request_clean_page(url)
        except ConnectionError:
            log.error(f'\tCould not connect to {url}.')
            continue

        tables = soup.find_all('table')

        try:
            summary_table = tables[0]
            vuln_details_table = tables[-1]
        except IndexError:
            log.error(f'\tCould not extract info from {url}.')
            continue

        try:
            summary = extract_table_info(summary_table)[0]
            vuln_details = extract_table_info(vuln_details_table)
        except ParserError:
            log.error(f'\tCould not parse details from {url}.')
            continue

        for vuln in vuln_details:
            if 'cve_numbers' in vuln.keys():
                vuln.update({'cve_number': vuln['cve_numbers']})

            if 'cve_number' not in vuln.keys():
                continue

            impact = vuln.get('vulnerability_impact')
            impact_list = [ADOBE_IMPACT_MAP.get(impact, 'none')]
            impact_list = list(set(impact_list)) if impact else None

            cve_list = re.split(r'\n+|\s+|,', vuln.get('cve_number'))
            cve_list = list(filter(None, cve_list))

            for cve_id in cve_list:
                rows.append([
                    cve_id, summary.get('date_published'),
                    impact_list, [summary.get('bulletin_id')]
                ])

    header = ['cve_id', 'advisory_published_date', 'attack_type', 'reference']
    save_list_to_csv(ADOBE_OUTPUT_FILE_PATH, header, rows)
