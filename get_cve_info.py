#!/usr/bin/env python
import requests
import json
import argparse


def main():
    # コマンドライン引数Parse
    parser = argparse.ArgumentParser()
    parser.add_argument('cve_id', help='CVE-ID')
    args = parser.parse_args()

    # CVE-IDに対応した脆弱性情報をNVDからJSON形式で取得
    cve_id = args.cve_id
    api = "https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"
    uri = api.format(cve_id=cve_id)
    response = requests.get(uri)
    json_data = json.loads(response.text)

    # NVDに記載されている脆弱性の説明(Current Description)を出力
    description_data_value = json_data['result']['CVE_Items'][0]['cve']['description']['description_data'][0]['value']
    print('------- Current Description -------')
    print(description_data_value)

    # CWE-IDを出力
    CWE_ID = json_data['result']['CVE_Items'][0]['cve']['problemtype']['problemtype_data'][0]['description'][0]['value']
    print('------- CWE-ID -------')
    print(CWE_ID)

    # CVSS V3 Scoreを出力
    cvssv3_score = json_data['result']['CVE_Items'][0]['impact']['baseMetricV3']
    print('------- CVSS V3 Score -------')
    print(cvssv3_score)


main()
