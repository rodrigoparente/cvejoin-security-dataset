# third-party imports
import pandas as pd


def process_security_feeds():
    print('\nProcessing output files...')

    cves = pd.read_csv('output/cves.csv')
    cves = cves.drop_duplicates(subset=['cve_id'])

    cves['cwe'] = cves['cwe'].apply(eval)
    cves['part'] = cves['part'].apply(eval)
    cves['vendor'] = cves['vendor'].apply(eval)

    # merging weakness lists

    mitre_top_25 = pd.read_csv('output/cwe_top_25.csv')
    mitre_top_25 = mitre_top_25.drop_duplicates(subset=['CWE-ID'])

    owasp_top_10 = pd.read_csv('output/owasp_top_10.csv')
    owasp_top_10 = owasp_top_10.drop_duplicates(subset=['CWE-ID'])

    mitre_ids = mitre_top_25['CWE-ID'].index.tolist()
    mitre_cwes = [f'CWE-{id}' for id in mitre_ids]

    owasp_ids = owasp_top_10['CWE-ID'].index.tolist()
    owasp_cwes = [f'CWE-{id}' for id in owasp_ids]

    cve_in_mitre = list()
    cve_in_owasp = list()

    for row in zip(*cves.to_dict("list").values()):
        mitre = False
        owasp = False

        for cwe in row[1]:
            if cwe in mitre_cwes:
                mitre = True

            if cwe in owasp_cwes:
                owasp = True

        cve_in_mitre.append(1 if mitre else 0)
        cve_in_owasp.append(1 if owasp else 0)

    cves['mitre_top_25'] = cve_in_mitre
    cves['owasp_top_10'] = cve_in_owasp

    # merging exploits

    exploits = pd.read_csv('output/exploits.csv')
    exploits = exploits.drop_duplicates(subset=['cve_id'])

    cves = cves.merge(exploits, how='left', on='cve_id')

    # merging epss

    epss = pd.read_csv('output/epss.csv', comment='#')
    epss.rename(columns={'cve': 'cve_id'}, inplace=True)
    epss = epss.drop_duplicates(subset=['cve_id'])

    columns = ['cve_id', 'epss']
    cves = cves.merge(epss[columns], how='left', on='cve_id')

    # merging advisories

    microsoft_advisory = pd.read_csv('output/microsoft_advisory.csv')
    microsoft_advisory = microsoft_advisory.drop_duplicates(subset=['cve_id'])

    intel_advisory = pd.read_csv('output/intel_advisory.csv')
    intel_advisory = intel_advisory.drop_duplicates(subset=['cve_id'])

    adobe_advisory = pd.read_csv('output/adobe_advisory.csv')
    adobe_advisory = adobe_advisory.drop_duplicates(subset=['cve_id'])

    advisories = pd.concat([microsoft_advisory, intel_advisory, adobe_advisory])
    advisories = advisories.drop_duplicates(subset=['cve_id'])

    columns = ['cve_id', 'advisory_published_date', 'reference']
    cves = cves.merge(advisories[columns], how='left', on='cve_id')

    for row in advisories.itertuples():
        cve_index = cves.loc[cves['cve_id'] == row.cve_id].index
        cves.loc[cve_index, 'attack_type'] = row.attack_type

    cves['update_available'] = 0
    cves.loc[~cves['reference'].isnull(), 'update_available'] = 1

    # merging tweets

    tweets = pd.read_csv('output/tweets.csv')

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

    # merging trends

    trends = pd.read_csv('output/trends.csv')
    cves = cves.merge(trends, how='left', on='cve_id')

    cves = cves[[
        'cve_id', 'cwe', 'part', 'vendor', 'product', 'description', 'cvss_type', 'attack_vector',
        'attack_complexity', 'privileges_required', 'user_interaction', 'scope',
        'confidentiality_impact', 'integrity_impact', 'availability_impact', 'base_score',
        'base_severity', 'exploitability_score', 'impact_score', 'cve_published_date',
        'cve_last_modified_date', 'mitre_top_25', 'owasp_top_10',
        'exploit_name', 'exploit_published_date', 'exploit_type',
        'exploit_platform', 'exploit_count', 'attack_type', 'epss',
        'google_trend', 'google_interest', 'advisory_published_date',
        'reference', 'update_available', 'audience', 'audience_normalized'
    ]]

    return cves
