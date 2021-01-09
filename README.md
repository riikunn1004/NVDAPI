# NVD公開 REST API の簡易プログラム
## 概要
NVD (National Vulnerability Database) が公開しているREST APIを用いて脆弱性情報を取得するプログラム。
REST APIの仕様の原文は下記を参照。
https://csrc.nist.gov/CSRC/media/Projects/National-Vulnerability-Database/documents/web%20service%20documentation/Automation%20Support%20for%20CVE%20Retrieval.pdf

## 動作確認環境
Ubuntu 18.04 LTSC
Python 3.9.1

## Pythonプログラム概要
- get_cve_info.py
指定したCVEに関する情報を取得し、出力するプログラム

使用例 CVE-2020-35815の情報を取得し、出力する
```
python get_cve_info.py CVE-2020-35815
```

- get_software_vulns.py
指定したCPEに合致したCVE一覧について、各CVEの情報を取得し、出力するプログラム

使用例 openssl1.1.1cのCVEの情報を取得し、出力する
```
python get_software_vulns.py cpe:2.3:a:openssl:openssl:1.1.1c:*:*:*:*:*:*:*
```
※ 最大20個までしか取得できない。21個以上取得したい場合は複数回REST APIリクエストを送る必要が有る。
詳しくはREST APIの仕様を参照。
