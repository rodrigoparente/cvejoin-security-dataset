# python imports
import logging

# third-party imports
import pandas as pd

log = logging.getLogger(__name__)


def process_cves(cves):
    cves = cves.drop_duplicates(subset=['cve_id'])

    cves['cwe'] = cves['cwe'].apply(eval)
    cves['part'] = cves['part'].apply(eval)
    cves['vendor'] = cves['vendor'].apply(eval)

    return cves


def process_mitre(cves, mitre_top_25):
    mitre_top_25 = mitre_top_25.drop_duplicates(subset=['CWE-ID'])

    mitre_ids = mitre_top_25['CWE-ID'].index.tolist()
    mitre_cwes = [f'CWE-{id}' for id in mitre_ids]

    cve_in_mitre = list()

    for row in zip(*cves.to_dict("list").values()):
        mitre = False

        for cwe in row[1]:
            if cwe in mitre_cwes:
                mitre = True

        cve_in_mitre.append(1 if mitre else 0)

    cves['mitre_top_25'] = cve_in_mitre

    return cves


def process_owasp(cves, owasp_top_10):
    owasp_top_10 = pd.read_csv('output/owasp_top_10.csv')
    owasp_top_10 = owasp_top_10.drop_duplicates(subset=['CWE-ID'])

    owasp_ids = owasp_top_10['CWE-ID'].index.tolist()
    owasp_cwes = [f'CWE-{id}' for id in owasp_ids]

    cve_in_owasp = list()

    for row in zip(*cves.to_dict("list").values()):
        owasp = False

        for cwe in row[1]:
            if cwe in owasp_cwes:
                owasp = True

        cve_in_owasp.append(1 if owasp else 0)

    cves['owasp_top_10'] = cve_in_owasp

    return cves


def process_exploits(cves, exploits):
    exploits = exploits.drop_duplicates(subset=['cve_id'])

    cves = cves.merge(exploits, how='left', on='cve_id')

    return cves


def process_epss(cves, epss):
    epss.rename(columns={'cve': 'cve_id'}, inplace=True)
    epss = epss.drop_duplicates(subset=['cve_id'])

    columns = ['cve_id', 'epss']
    cves = cves.merge(epss[columns], how='left', on='cve_id')

    return cves


def process_advisories(cves, advisories):

    advisories = pd.concat(advisories)
    advisories = advisories.drop_duplicates(subset=['cve_id'])

    columns = ['cve_id', 'advisory_published_date', 'reference']
    cves = cves.merge(advisories[columns], how='left', on='cve_id')

    for row in advisories.itertuples():
        cve_index = cves.loc[cves['cve_id'] == row.cve_id].index
        cves.loc[cve_index, 'attack_type'] = row.attack_type

    cves['update_available'] = 0
    cves.loc[~cves['reference'].isnull(), 'update_available'] = 1

    return cves


def process_tweets(cves, tweets):
    cve_ids = cves['cve_id'].tolist()
    tweets_cve_ids = tweets['cve_id'].tolist()

    intersection = set(cve_ids).intersection(tweets_cve_ids)
    tweets = tweets.loc[tweets['cve_id'].isin(intersection)]

    max_audience = tweets['audience'].max()
    tweets['audience_normalized'] =\
        tweets['audience'].apply(lambda value: f'{value / max_audience:.5f}')

    columns = ['cve_id', 'audience', 'audience_normalized']
    cves = cves.merge(tweets[columns], how='left', on='cve_id')

    for row in tweets.itertuples():
        cve_index = cves.loc[cves['cve_id'] == row.cve_id].index
        cves.loc[cve_index, 'attack_type'] = row.attack_type

    return cves


def process_trends(cves, trends):
    return cves.merge(trends, how='left', on='cve_id')


def process_security_feeds():
    print('\nProcessing output files...')

    cves = pd.DataFrame()
    indexes = list()

    try:
        cves = pd.read_csv('output/cves.csv')
    except FileNotFoundError:
        log.error('\tNo CVE information to process.')
        return

    if not cves.empty:
        cves = process_cves(cves)
        indexes.extend([
            'cve_id', 'cwe', 'part', 'vendor', 'product', 'description', 'cvss_type',
            'attack_vector', 'attack_complexity', 'privileges_required', 'user_interaction',
            'scope', 'confidentiality_impact', 'integrity_impact', 'availability_impact',
            'base_score', 'base_severity', 'exploitability_score', 'impact_score',
            'cve_published_date', 'cve_last_modified_date', 'attack_type'])

    # merging mitre weakness

    mitre_top_25 = pd.DataFrame()

    try:
        mitre_top_25 = pd.read_csv('output/cwe_top_25.csv')
    except FileNotFoundError:
        log.error('\tNo MITRE Top 25 information to process.')

    if not mitre_top_25.empty:
        cves = process_mitre(cves, mitre_top_25)
        indexes.extend(['mitre_top_25'])

    # merging owasp weakness

    owasp_top_10 = pd.DataFrame()

    try:
        owasp_top_10 = pd.read_csv('output/owasp_top_10.csv')
    except FileNotFoundError:
        log.error('\tNo OWASP Top 10 information to process.')

    if not owasp_top_10.empty:
        cves = process_owasp(cves, owasp_top_10)
        indexes.extend(['owasp_top_10'])

    # merging exploits

    exploits = pd.DataFrame()

    try:
        exploits = pd.read_csv('output/exploits.csv')
    except FileNotFoundError:
        log.error('\tNo exploits information to process.')

    if not exploits.empty:
        cves = process_exploits(cves, exploits)
        indexes.extend([
            'exploit_name', 'exploit_published_date',
            'exploit_type', 'exploit_platform', 'exploit_count'])

    # merging epss

    epss = pd.DataFrame()

    try:
        epss = pd.read_csv('output/epss.csv', comment='#')
    except FileNotFoundError:
        log.error('\tNo EPSS information to process.')

    if not epss.empty:
        cves = process_epss(cves, epss)
        indexes.extend(['epss'])

    # merging advisories

    advisories = list()

    try:
        microsoft_advisory = pd.read_csv('output/microsoft_advisory.csv')
        microsoft_advisory = microsoft_advisory.drop_duplicates(subset=['cve_id'])
        advisories.append(microsoft_advisory)
    except FileNotFoundError:
        log.error('\tNo Microsoft advisory information to process.')

    try:
        intel_advisory = pd.read_csv('output/intel_advisory.csv')
        intel_advisory = intel_advisory.drop_duplicates(subset=['cve_id'])
        advisories.append(intel_advisory)
    except FileNotFoundError:
        log.error('\tNo Intel advisory information to process.')

    try:
        adobe_advisory = pd.read_csv('output/adobe_advisory.csv')
        adobe_advisory = adobe_advisory.drop_duplicates(subset=['cve_id'])
        advisories.append(adobe_advisory)
    except FileNotFoundError:
        log.error('\tNo Adobe advisory information to process.')

    if advisories:
        cves = process_advisories(cves, advisories)
        indexes.extend(['advisory_published_date', 'reference', 'update_available'])

    # merging tweets

    tweets = pd.DataFrame()

    try:
        tweets = pd.read_csv('output/tweets.csv')
    except FileNotFoundError:
        log.error('\tNo tweet information to process')

    if not tweets.empty:
        cves = process_tweets(cves, tweets)
        indexes.extend(['audience', 'audience_normalized'])

    # merging trends

    trends = pd.DataFrame()

    try:
        trends = pd.read_csv('output/trends.csv')
    except FileNotFoundError:
        log.error('\tNo trend information to process')

    if not trends.empty:
        cves = process_trends(cves, trends)
        indexes.extend(['google_trend', 'google_interest'])

    # filtering indexes

    cves = cves[indexes]

    return cves
