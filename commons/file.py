# python imports
import os
import csv
import json


def mkdir(path):
    # create output folder
    # if it doesnt exists
    dirs = os.path.split(path)[0]
    if not os.path.exists(dirs):
        os.makedirs(dirs)


def rm(path):
    # delete output
    # file if it exists
    if os.path.exists(path):
        os.remove(path)


def save_to_json(path, dict):
    mkdir(path)
    rm(path)

    with open(path, 'w') as file:
        json.dump(dict, file, indent=4)


def save_list_to_csv(path, header, rows):
    mkdir(path)
    rm(path)

    with open(path, 'w') as file:
        writer = csv.writer(file)
        writer.writerow(header)
        writer.writerows(rows)


def save_dict_to_csv(path, header, dict):
    mkdir(path)
    rm(path)

    with open(path, 'w') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=header)
        writer.writeheader()
        for data in dict.values():
            writer.writerow(data)
