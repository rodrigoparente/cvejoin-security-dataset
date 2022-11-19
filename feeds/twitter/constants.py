RAW_TWEETS_PATH = 'output/raw_tweets.csv'
PROCESSED_TWEETS_PATH = 'output/tweets.csv'

SEARCH_RULES = [
    {
        'value': 'CVE -"$CVE"',  # search for CVE term excluding the cashtag $CVE
        'tag': 'vulnerability identifier'
    }
]

RUNTIME = {
    'hours': 24
}
