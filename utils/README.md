# Merge Context Information

This script can be used to merge context information from the user network with the vulnerability and threat inteligence information.

## Usage

```bash
$ python merge_context.py [-h] -i INPUT [-o OUTPUT]
```

#### Parameters
+  ```-h```, ```--help```                 show this help message and exit
+  ```-i INPUT```, ```--input INPUT```    the CSV file path to merge with the dataset information
+  ```-o OUTPUT```, ```--output OUTPUT``` the output CSV file after the merging is completed


## Input Example

The CSV file given as input must contain at least two columns to work: 

 - asset: that identifier for the assets;
 - cves: a list separated by spaces with the cve identifiers affecting the asset.

Any other column can be passed and will be treated as context information about the asset.

| asset    | environment | type        | data | cves                                         |
|----------|-------------|-------------|------|----------------------------------------------|
| ASSET-01 | DMZ         | SERVER      | 1    | CVE-2021-46851 CVE-2021-46580 CVE-2021-46151 |
| ASSET-02 | LOCAL       | WORKSTATION | 0    | CVE-2017-10222 CVE-2021-46853                |