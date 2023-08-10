# python imports
import os

# third-party imports
import pandas as pd

# project imports
from commons.file import save_list_to_csv
from commons.impact import extract_vuln_impact


def process_tweets(input_path, output_path):
    tweets_csv = pd.read_csv(input_path)

    if tweets_csv.empty:
        os.remove(input_path)
        return

    tweets_dict = dict()

    for row in tweets_csv.itertuples():
        if row.cve_id in tweets_dict.keys():
            tweet = tweets_dict[row.cve_id]

            if row.published_date > tweet['published_date']:
                tweet['published_date'] = row.published_date

            if row.lang not in tweet['lang']:
                tweet['lang'].append(row.lang)

            tweet_attack_type = extract_vuln_impact(row.text)
            tweet['attack_type'] += tweet_attack_type

            if row.tweet_author_id not in tweet['authors'].keys():
                tweet['authors'].update({
                    row.tweet_author_id: row.tweet_author_followers})

            if row.original_tweet_id:
                if row.original_author_id not in tweet['authors'].keys():
                    tweet['authors'].update({
                        row.original_author_id: row.original_author_followers})

                if row.original_tweet_id not in tweet['retweets'].keys():
                    tweet['retweets'].update({
                        row.original_tweet_id: row.original_retweet_count})
                elif row.original_retweet_count > tweet['retweets'][row.original_tweet_id]:
                    tweet['retweets'][row.original_tweet_id] = row.original_retweet_count

                if row.original_tweet_id not in tweet['tweets']:
                    tweet['tweets'].append(row.original_tweet_id)
            else:
                tweet['tweets'].append(row.tweet_id)
        else:
            tweets_dict.setdefault(row.cve_id, {
                'cve_id': row.cve_id,
                'published_date': row.published_date,
                'lang': [row.lang],
                'attack_type': extract_vuln_impact(row.text),
                'authors': {row.tweet_author_id: row.tweet_author_followers},
                'tweets': [],
                'retweets': {}
            })

            tweet = tweets_dict[row.cve_id]

            if row.original_tweet_id:
                tweet.update({
                    'authors': {row.original_author_id: row.original_author_followers},
                    'retweets': {row.original_tweet_id: row.original_retweet_count}
                })

                tweet['tweets'].append(row.original_tweet_id)
            else:
                tweet['tweets'].append(row.tweet_id)

    results = list()
    for value in tweets_dict.values():

        impact_list = list(set(value.get('attack_type')))
        impact_list = impact_list if impact_list else None

        results.append([
            value.get('cve_id'), value.get('published_date'), value.get('lang'),
            impact_list, len(value.get('tweets')),
            sum(value.get('retweets').values()), sum(value.get('authors').values())
        ])

    header = ['cve_id', 'tweet_published_date', 'lang',
              'attack_type', 'tweets', 'retweets', 'audience']
    save_list_to_csv(output_path, header, results)
