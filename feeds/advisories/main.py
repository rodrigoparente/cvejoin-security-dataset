
# local imports
from .microsoft import download_microsoft_advisory
from .intel import download_intel_advisory
from .adobe import download_adobe_advisory


def download_advisories():
    print(' - Downloading Microsoft advisory...')
    download_microsoft_advisory()

    print(' - Downloading Intel advisory...')
    download_intel_advisory()

    print(' - Downloading Adobe advisory...')
    download_adobe_advisory()
