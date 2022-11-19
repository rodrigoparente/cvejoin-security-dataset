# project imports
from feeds.cves import download_cves
from feeds.cwes import download_cwes
from feeds.exploits import download_exploits
from feeds.epss import download_epss
from feeds.advisories import download_advisories
from feeds.twitter import download_tweets
from feeds.trends import download_trends


def download_security_feeds():
    # download info about CVEs
    print('Downloading CVES...')
    download_cves()

    # download info about CWEs
    print('\nDownloading CWES...')
    download_cwes()

    # download info about exploits
    print('\nDownloading exploits...')
    download_exploits()

    # download info about future exploits
    print('\nDownloading EPSS...')
    download_epss()

    # download info about advisories
    print('\nDownloading advisories...')
    download_advisories()

    # download info from twitter
    print('\nDownloading tweets...')
    download_tweets()

    # download info from google trends
    print('\nDownloading trends...')
    download_trends()
