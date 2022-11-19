# python imports
import re
import logging
from urllib.parse import urljoin
from dateutil.parser import parse

# third-party imports
from requests.exceptions import ConnectionError

# project imports
from commons.file import save_list_to_csv
from commons.parse import request_clean_page

# local imports
from .constants import INTEL_BASE_URL
from .constants import INTEL_SECURITY_BULLETIN
from .constants import INTEL_OUTPUT_FILE_PATH
from .constants import INTEL_IMPACT_MAP


log = logging.getLogger(__name__)


def download_intel_advisory():

    url = urljoin(INTEL_BASE_URL, INTEL_SECURITY_BULLETIN)
    soup = request_clean_page(url)

    intel_main_table = soup.find_all('tr', {'class': 'data'})
    advisories_url = list()

    for item in intel_main_table:
        anchor = item.find('a')
        advisories_url.append(anchor['href'])

    advisories_info = list()

    for advisory in advisories_url:

        try:
            url = urljoin(INTEL_BASE_URL, advisory)
            soup = request_clean_page(url)
        except ConnectionError:
            log.error('\tFailed to estabilish a new connection.')
            continue

        features_table = soup.find('div', {'class': 'editorialtable'})

        _, impacts, _, published_date, *_ = features_table.find_all('tr', {'class': 'data'})

        impacts = impacts.find_all('td')[1].text.split(',')
        impacts = [value.strip().rstrip() for value in impacts]

        impact_list = list()
        for impact in impacts:
            impact_list.append(
                INTEL_IMPACT_MAP.get(impact, 'none'))

        impact_list = list(set(impact_list)) if impact_list else None

        published_date = published_date.find_all('td')[1].text.strip().rstrip()
        published_date = parse(published_date).strftime('%m/%d/%Y')

        cve_id_regex = re.compile('CVE-[0-9]{4}-[0-9]+')
        cves = list()

        for item in soup.find_all(text=cve_id_regex):
            for cve in re.findall(cve_id_regex, item):
                if cve not in cves:
                    cves.append(cve)

        intel_sa = re.search('intel-sa-[0-9]+', url).group(0).upper()

        for cve in cves:
            advisories_info.append([cve, published_date, impact_list, [intel_sa]])

    header = ['cve_id', 'advisory_published_date', 'attack_type', 'reference']
    save_list_to_csv(INTEL_OUTPUT_FILE_PATH, header, advisories_info)
