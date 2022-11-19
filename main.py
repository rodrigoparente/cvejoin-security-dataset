# third-party imports
from dotenv import load_dotenv

# local imports
from download import download_security_feeds
from process import process_security_feeds


if __name__ == '__main__':
    # take environment
    # variables from .env
    load_dotenv()

    # # download info from all different feeds
    download_security_feeds()

    # process and merge info from all
    # different feeds into a single dataset
    cves = process_security_feeds()

    # saving dataset to a csv file
    cves.to_csv('output/vulnerabilities.csv', index=False)
