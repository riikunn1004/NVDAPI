#!/usr/bin/env python
import requests
import json
import argparse


def main():
    #  コマンドライン引数Parse
    parser = argparse.ArgumentParser()
    parser.add_argument('cpe_name', help='CPE-ID')
    args = parser.parse_args()

    #  CPEに対応した脆弱性情報をNVDからJSON形式で取得
    cpe_name = args.cpe_name
    api = "https://services.nvd.nist.gov/rest/json/cves/1.0?cpeMatchString={cpe_name}"
    uri = api.format(cpe_name=cpe_name)
    response = requests.get(uri)
    json_data = json.loads(response.text)

    vulnerabilities = json_data['result']['CVE_Items']

    for vuln in vulnerabilities:
        cve_id = vuln['cve']['CVE_data_meta']['ID'] # CVE-IDを取得
        current_description = vuln['cve']['description']['description_data'][0]['value'] # Current Descriptionを取得
        cwe_id = vuln['cve']['problemtype']['problemtype_data'][0]['description'][0]['value'] # CWE-IDを取得

        #  BaseScore, VectorStringを取得する。CVSS v3.xの情報が無ければCVSS v2の情報を取得する。
        if 'baseMetricV3' in vuln['impact']:
            base_score = vuln['impact']['baseMetricV3']['cvssV3']['baseScore']
            vector_string = vuln['impact']['baseMetricV3']['cvssV3']['vectorString']
        else:
            base_score = vuln['impact']['baseMetricV2']['cvssV2']['baseScore']
            vector_string = vuln['impact']['baseMetricV2']['cvssV2']['vectorString']

        #  出力
        text = "{cve_id}:{cwe_id}:{base_score}:{vector_string}:{current_description}"
        print(text.format(cve_id=cve_id, cwe_id=cwe_id, base_score=base_score, vector_string=vector_string, current_description=current_description))


main()
