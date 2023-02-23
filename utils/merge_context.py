# python imports
import argparse
import pathlib

# third-party imports
import pandas as pd


def main(args):

    cves = pd.read_csv('../output/vulnerabilities.csv')
    context = pd.read_csv(args.input)

    output = pd.DataFrame()

    for index, row in context.iterrows():
        cve_ids = row['cves'].split(' ')
        output = pd.concat([output, context.loc[[index] * len(cve_ids)].assign(cve_id=cve_ids)])

    output.drop(columns=['cves'], inplace=True)
    output = output.merge(cves, how='left', on='cve_id')
    output.to_csv(args.output, index=False)


if __name__ == '__main__':

    parser = argparse.ArgumentParser(
        description='A simple script to merge context with vulnerability information')

    parser.add_argument(
        '-i', '--input', action='store', dest='input', required=True,
        help='The CSV file path to merge with the dataset information.')

    parser.add_argument(
        '-o', '--output', action='store', dest='output', required=False,
        help='The output CSV file after the merging is completed.', default='output.csv')

    args = parser.parse_args()

    if pathlib.Path(args.input).suffix != '.csv':
        exit('the input file must be a CSV file.')

    main(args)
