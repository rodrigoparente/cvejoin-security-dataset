# python imports
import json
import logging
from time import sleep
from collections import namedtuple
from urllib.parse import urlencode

# third-party imports
import requests


log = logging.getLogger(__name__)


class TwitterStream():
    def __init__(self, token):
        self.bearer_token = token

        self.running = False
        self.max_retries = 3
        self.session = requests.Session()

        self.base_url = 'https://api.twitter.com/2/tweets/search/stream'

        # remove old rules that are active
        self.delete_rules(self.get_rules())

    def _bearer_oauth(self, r):
        r.headers['Authorization'] = f'Bearer {self.bearer_token}'
        r.headers['User-Agent'] = 'v2FilteredStreamPython'

        return r

    def _connect(self, method, url):
        self.running = True
        http_error_wait = 5
        error_count = 0

        try:
            while self.running and error_count < self.max_retries:
                with self.session.request(
                    method, url, auth=self._bearer_oauth, stream=True
                ) as resp:

                    if resp.status_code == 200:
                        self.on_connect()
                        if not self.running:
                            break

                        for raw_data in resp.iter_lines():

                            if not self.running:
                                break

                            if raw_data:
                                data = json.loads(raw_data)

                                if "data" in data:
                                    tweet = namedtuple('tweet', data.keys())(*data.values())
                                    self.on_tweet(tweet)
                    else:
                        self.on_error(
                            f'An error occurred with the stream (HTTP {resp.status_code})')

                        if not self.running:
                            break

                        sleep(http_error_wait)
                        http_error_wait *= 2
                        error_count += 1

        except Exception as exc:
            log.error(f'\tStream encountered an exception: {exc}')
        finally:
            self.session.close()
            self.running = False
            self.on_disconnect()

    def disconnect(self):
        self.running = False

    def get_rules(self):
        resp = requests.get(
            f'{self.base_url}/rules',
            auth=self._bearer_oauth
        )

        if resp.status_code != 200:
            self.on_error(f'Cannot get rules (HTTP {resp.status_code})')

        return resp.json()

    def delete_rules(self, rules):
        if rules is None or 'data' not in rules:
            return None

        ids = list(map(lambda rule: rule['id'], rules['data']))
        payload = {'delete': {'ids': ids}}

        resp = requests.post(
            f'{self.base_url}/rules',
            auth=self._bearer_oauth,
            json=payload
        )

        if resp.status_code != 200:
            self.on_error(f'Cannot delete rules (HTTP {resp.status_code})')

    def add_rules(self, rules):
        """
        References
        ----------
        https://developer.twitter.com/en/docs/twitter-api/tweets/filtered-stream/integrate/build-a-rule
        """

        resp = requests.post(
            f'{self.base_url}/rules',
            auth=self._bearer_oauth,
            json={'add': rules}
        )

        if resp.status_code != 201:
            self.on_error(f'Cannot add rules (HTTP {resp.status_code})')

    def filter(self, expansions=None, tweet_fields=None, user_fields=None):
        """
        References
        ----------
        https://developer.twitter.com/en/docs/twitter-api/tweets/filtered-stream/api-reference/get-tweets-search-stream
        """

        query_dict = dict()

        if expansions:
            query_dict.update({'expansions': ','.join(expansions)})
        if tweet_fields:
            query_dict.update({'tweet.fields': ','.join(tweet_fields)})
        if user_fields:
            query_dict.update({'user.fields': ','.join(user_fields)})

        url = f'{self.base_url}?{urlencode(query_dict)}'

        self._connect('GET', url)

    def on_connect(self):
        log.info('\tSuccessfull connected to Twitter API.')

    def on_disconnect(self):
        log.info('\tSuccessfull disconnected from Twitter API.')

    def on_tweet(self, tweet):
        log.info('\tTweet received.')

    def on_error(self, error_msg):
        log.error(f'\t{error_msg}')
