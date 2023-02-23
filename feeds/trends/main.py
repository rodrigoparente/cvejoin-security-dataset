# python imports
from time import sleep
from datetime import datetime
from dateutil.relativedelta import relativedelta

# third-party
import pandas as pd
import numpy as np

from pytrends.request import TrendReq

# project imports
from commons.file import save_dict_to_csv

# local imports
from .constants import OUTPUT_FILE_PATH
from .constants import TWEETS_FILE_PATH

# hide warnings
import warnings
warnings.filterwarnings('ignore')


def download_trends():
    tweets = pd.read_csv(TWEETS_FILE_PATH)
    tweets = tweets.sort_values(by=['audience'], ascending=False)

    # instantiating pytrends object
    pytrends = TrendReq()

    # getting dates
    today = datetime.now().strftime('%Y-%m-%dT%H')
    a_week_days_ago = (datetime.now() - relativedelta(days=7, hours=1)).strftime('%Y-%m-%dT%H')

    results = dict()

    error_limit = 0
    max_error_limit = 5
    error_wait_time = 60

    # retrieving interest of all vulns
    for row in zip(*tweets.to_dict("list").values()):
        cve = row[0]

        df = None

        while True:
            try:
                # building trend query
                pytrends.build_payload([cve], timeframe=f'{a_week_days_ago} {today}')
                df = pytrends.interest_over_time()
                break
            except Exception as e:
                if error_limit > max_error_limit:
                    print(f'Program failed: {e}')
                    exit(0)

                sleep(error_wait_time)
                error_limit += 1
                error_wait_time *= 2

        trend, interest = np.nan, 0

        if not df.empty:
            df = df.drop(['isPartial'], axis=1)
            df.reset_index('date', inplace=True)

            series = dict()
            for row in zip(*df.to_dict("list").values()):
                date = row[0].strftime('%Y-%m-%d')
                interest = row[1]

                if date not in series.keys():
                    series.setdefault(date, interest)
                elif interest > series[date]:
                    series[date] = interest

            # calculating the direction of the interest
            trend = np.gradient(list(series.values()))[-1]

            # calculating the overrall interest
            interest = sum(series.values()) / (len(series) * 100)

            if trend > 0:
                trend, interest = 'increasing', interest
            elif trend < 0:
                trend, interest = 'decreasing', interest
            else:
                trend, interest = 'steady', interest

        results.setdefault(cve, {
            'cve_id': cve,
            'google_trend': trend,
            'google_interest': interest
        })

    header = ['cve_id', 'google_trend', 'google_interest']
    save_dict_to_csv(OUTPUT_FILE_PATH, header, results)
