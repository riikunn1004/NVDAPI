#!/usr/bin/env python
import requests
import json
import argparse
import textwrap


def main():
    #  コマンドライン引数Parse
    parser = argparse.ArgumentParser()
    parser.add_argument('cpe_name', help='CPE Name')
    args = parser.parse_args()

    #  CPEに対応した脆弱性情報をNVDからJSON形式で取得
    cpe_name = args.cpe_name
    api = 'https://services.nvd.nist.gov/rest/json/cves/1.0?cpeMatchString={cpe_name}'
    uri = api.format(cpe_name=cpe_name)
    response = requests.get(uri)
    json_data = json.loads(response.text)

    vulnerabilities = json_data['result']['CVE_Items']
    for vuln in vulnerabilities:
        cve_id = vuln['cve']['CVE_data_meta']['ID']  # CVE-IDを取得
        current_description = vuln['cve']['description']['description_data'][0]['value']  # Current Descriptionを取得
        cwe_id = vuln['cve']['problemtype']['problemtype_data'][0]['description'][0]['value']  # CWE-IDを取得

        #  CVSS v3の情報があればBaseScoreとVectorStringを取得
        if 'baseMetricV3' in vuln['impact']:
            cvssv3_base_score = vuln['impact']['baseMetricV3']['cvssV3']['baseScore']
            cvssv3_vector_string = vuln['impact']['baseMetricV3']['cvssV3']['vectorString']
            
        else:
            cvssv3_base_score = None
            cvssv3_vector_string = None

        #  CVSS v2のBaseScoreとVectorStringを取得
        cvssv2_base_score = vuln['impact']['baseMetricV2']['cvssV2']['baseScore']
        cvssv2_vector_string = vuln['impact']['baseMetricV2']['cvssV2']['vectorString']

        #  出力
        print('---------')
        text = textwrap.dedent('''
        CVE-ID:{cve_id}
        CWE-ID:{cwe_id}
        CVSSv3 BaseScore:{cvssv3_base_score} CVSSv3 VectorString:{cvssv3_vector_string}
        CVSSv2 BaseScore:{cvssv2_base_score} CVSSv2 VectorString: {cvssv2_vector_string}
        Current Description:
        {current_description}
        ''')
        print(text.format(cve_id=cve_id, cwe_id=cwe_id, cvssv3_base_score=cvssv3_base_score, cvssv3_vector_string=cvssv3_vector_string,
                          cvssv2_base_score=cvssv2_base_score, cvssv2_vector_string=cvssv2_vector_string, current_description=current_description))
        print('---------')


main()
