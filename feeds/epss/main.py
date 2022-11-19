# python imports
import logging
from gzip import GzipFile
from urllib.request import urlopen

# project imports
from commons.file import mkdir, rm

# local imports
from .constants import BASE_URL
from .constants import OUTPUT_FILE_PATH

log = logging.getLogger(__name__)


def download_epss():
    # create output folder
    # if it doesnt exists
    mkdir(OUTPUT_FILE_PATH)

    # delete output file
    # if it exists
    rm(OUTPUT_FILE_PATH)

    try:
        with urlopen(BASE_URL) as response:
            with GzipFile(fileobj=response) as uncompressed:
                with open(OUTPUT_FILE_PATH, 'wb') as f:
                    f.write(uncompressed.read())
    except Exception as e:
        log.error(f'\tCould not download json file: {e}')
