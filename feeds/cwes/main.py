# python imports
import zipfile
import logging
from io import BytesIO
from urllib.request import urlopen
from urllib.parse import urljoin

# project imports
from commons.file import mkdir, rm
from commons.parse import request_clean_page

# local imports
from .constants import BASE_URL
from .constants import MITRE_OUTPUT_FILE_PATH
from .constants import OWASP_OUTPUT_FILE_PATH
from .constants import MITRE_ID
from .constants import OWASP_ID

log = logging.getLogger(__name__)


def download_cwes():

    soup = request_clean_page(BASE_URL)

    ids = [MITRE_ID, OWASP_ID]
    outputs = [MITRE_OUTPUT_FILE_PATH, OWASP_OUTPUT_FILE_PATH]

    for id, output in zip(ids, outputs):
        # create output folder
        # if it doesnt exists
        mkdir(output)

        # delete output file
        # if it exists
        rm(output)

        try:
            feed = soup.find('tr', {'id': f'cwe{id}'}).find('a', string='CSV.zip')
            url = urljoin('https://cwe.mitre.org', feed.get('href'))

            with urlopen(url) as response:
                with zipfile.ZipFile(BytesIO(response.read())) as uncompressed:
                    with open(output, 'wb') as f:
                        f.write(uncompressed.read(f'{id}.csv'))
        except Exception as e:
            log.error(f'\tCould not download file: {e}')
