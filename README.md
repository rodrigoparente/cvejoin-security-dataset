# CVEjoin: A Dataset of Information Security Vulnerability and Threat Intelligence

The code from this repository can be used to download and correlate information about known vulnerabilities from different security feed sources, such as:

 - NIST
 - MITRE
 - OWASP
 - ExploitDB
 - EPSS
 - Multiples Security Advisories (Microsoft, Adobe, Intel, etc)
 - Twitter
 - Google trends

For more information about the security feeds, methodology, and an exploratory analysis of the data collected, read the paper: [CVEjoin - A Dataset of Information Security Vulnerability and Threat Intelligence](https://link.springer.com/chapter/10.1007/978-3-031-29056-5_34), published at the international conference on Advanced Information Networking and Applications. Also, a version of the dataset can be downloaded from [Figshare](https://figshare.com/articles/dataset/CVEjoin_A_Security_Dataset_of_Vulnerability_and_Threat_Intelligence_Information/21586923/3).

## Requirements

Install requirements using the following command

```bash
$ pip install -r requirements.txt
```

## Execute

Execute the code using the following command

```bash
$ python main.py
```

## Output

The result will be a csv file (named `vulnerabilities.csv`) placed in the `output folder`, containing information about all known vulnerabilities, exploits, security advisories, software and hardware weakness, etc.

## Optional Configuration

The user can configure two optional environment variables. The first, `UPDATE_EXPLOIT_DB`, controls whether the local exploit db is updated during execution and should have one of the following values: `true` or `false`. The second, `TWITTER_BEARER_TOKEN`, is needed to access the [Twitter Stream](https://developer.twitter.com/en/docs/tutorials/stream-tweets-in-real-time) API and is the user bearer token.

## Reference 

If you re-use this work, please cite:

```
@inproceedings{da2023cvejoin,
  title={CVEjoin: An Information Security Vulnerability and Threat Intelligence Dataset},
  author={da Ponte, Francisco RP and Rodrigues, Emanuel B and Mattos, C{\'e}sar LC},
  booktitle={International Conference on Advanced Information Networking and Applications},
  pages={380--392},
  year={2023},
  organization={Springer}
}
```

## License

This project is [GNU GPLv3 licensed](./LICENSE).