# python imports
from dateutil.parser import parse, ParserError

# third-party imports
import requests
from bs4 import BeautifulSoup
from lxml.html.clean import Cleaner


def request_clean_page(url):
    resp = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'})

    cleaner = Cleaner(
        comments=True, meta=True, scripts=True,
        javascript=True, embedded=True, style=True, inline_style=True)

    return BeautifulSoup(cleaner.clean_html(resp.text.encode('utf-8')), 'lxml')


def extract_table_info(table):
    results = list()
    headers = list()

    for row_id, row in enumerate(table.find_all('tr')):
        if row_id == 0:
            header_items = row.find_all('th')
            if header_items:
                for name in header_items:
                    text = name.text.encode('ascii', 'ignore').decode()
                    text = text.lower().replace(' ', '_')
                    text = text.strip().rstrip().replace('\n', '_')
                    headers.append(text)
            else:
                # because some pages doesn't use <th><th/>
                # tag to define the header of the table
                for name in row.find_all('td'):
                    text = name.text.encode('ascii', 'ignore').decode()
                    text = text.lower().replace(' ', '_').strip().rstrip()
                    headers.append(text)
        else:
            row_dict = dict()
            for header, name in zip(headers, row.find_all('td')):

                text = name.text.encode('ascii', 'ignore').decode()
                text = text.strip().rstrip()

                if header == 'date_published':
                    try:
                        text = parse(text).strftime('%m/%d/%Y')
                    except ParserError:
                        raise ParserError

                row_dict.setdefault(header, text)
            results.append(row_dict)

    return results
