# python imports
import os
import csv
import re
from datetime import datetime
from datetime import timedelta

# project imports
from commons.file import mkdir, rm

# local imports
from .constants import RAW_TWEETS_PATH
from .constants import PROCESSED_TWEETS_PATH
from .constants import SEARCH_RULES
from .constants import RUNTIME
from .api import TwitterStream
from .utils import process_tweets


class Listener(TwitterStream):
    def __init__(self, token, file_path, duration):
        super().__init__(token)

        self.tmp_file = file_path
        self.tweets = list()

        self.start_time = datetime.now()
        self.end_time = self.start_time + timedelta(**duration)

        self.prep_tmp_file()

    def prep_tmp_file(self):

        # create output folder if it doesnt exists
        mkdir(self.tmp_file)

        # remove tmp file if exists
        rm(self.tmp_file)

        self.write_to_file([
            'cve_id', 'published_date', 'text', 'lang',
            'tweet_id', 'tweet_retweet_count',
            'tweet_author_id', 'tweet_author_followers',
            'original_tweet_id', 'original_retweet_count',
            'original_author_id', 'original_author_followers'])

    def write_to_file(self, entries):
        with open(self.tmp_file, 'a') as f:
            writer = csv.writer(f)
            writer.writerow(entries)

    def on_connect(self):
        start = self.start_time.strftime('%H:%M %d/%m/%Y')
        end = self.end_time.strftime('%H:%M %d/%m/%Y')

        print(f' - Program start running at {start} and will finish at {end}')

    def on_tweet(self, tweet):

        # tweet info

        tweet_author_id = tweet.data.get('author_id')
        tweet_id = tweet.data.get('id')

        published_date = tweet.data.get('created_at')
        text = tweet.data.get('text')
        lang = tweet.data.get('lang')

        tweet_metrics = tweet.data.get('public_metrics')
        tweet_retweet_count = tweet_metrics.get('retweet_count')

        tweet_author = list(filter(
            lambda user: (user['id'] == tweet_author_id), tweet.includes.get('users')))[0]

        tweet_author_metrics = tweet_author.get('public_metrics')
        tweet_author_followers = tweet_author_metrics.get('followers_count')

        # reference tweet info

        original_author_id = 0
        original_tweet_id = 0
        original_retweet_count = 0
        original_author_followers = 0

        if tweet.data.get('referenced_tweets') is not None:
            for reference in tweet.data.get('referenced_tweets'):
                if reference.get('type') == 'retweeted':
                    original_tweet_id = reference.get('id')
                    break

            if original_tweet_id:
                referenced_tweets = tweet.includes.get('tweets')

                original_tweet =\
                    list(filter(lambda tweet: (tweet['id'] == original_tweet_id),
                                referenced_tweets))[0]

                original_author_id = original_tweet.get('author_id')
                original_tweet_id = original_tweet_id

                original_twitter_metrics = original_tweet.get('public_metrics')
                original_retweet_count = original_twitter_metrics.get('retweet_count')

                original_tweet_author =\
                    list(filter(lambda user: (user['id'] == original_author_id),
                                tweet.includes.get('users')))[0]

                original_tweet_author_metrics = original_tweet_author.get('public_metrics')
                original_author_followers = original_tweet_author_metrics.get('followers_count')

        # vulnerability identifier

        cve_id = re.search('CVE-[0-9]{4}-[0-9]+', text)

        if datetime.now() < self.end_time:
            if cve_id:
                self.write_to_file([
                    cve_id.group(0), published_date, text, lang,
                    tweet_id, tweet_retweet_count,
                    tweet_author_id, tweet_author_followers,
                    original_tweet_id, original_retweet_count,
                    original_author_id, original_author_followers])
        else:
            self.disconnect()

    def on_error(self, error_msg):
        print(f'\t{error_msg}')


def download_tweets(rules=SEARCH_RULES, duration=RUNTIME):

    bearer_token = os.environ.get('TWITTER_BEARER_TOKEN', None)

    if not bearer_token:
        print('You must set a bearer token to access Twitter API')
        return

    stream = Listener(
        bearer_token,
        file_path=RAW_TWEETS_PATH,
        duration=duration)

    stream.add_rules(rules)

    stream.filter(
        expansions=['author_id', 'referenced_tweets.id'],
        user_fields=['verified', 'public_metrics'],
        tweet_fields=['created_at', 'lang', 'public_metrics', 'text'])

    process_tweets(
        input_path=RAW_TWEETS_PATH,
        output_path=PROCESSED_TWEETS_PATH)
