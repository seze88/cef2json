# Script to convert CEF logs (from Incapsula) to JSON

import re
import json
import itertools

test = 'CEF:0|Incapsula|SIEMintegration|1|1|IncapRules(bad client)|11| fileId=295037710147327529 sourceServiceName=example.com siteid=10286633 suid=2047415 requestClientApplication=Mozilla/5.0 (compatible; Windows NT 6.1; Catchpoint) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36 deviceFacility=hkg cs2=false cs2Label=Javascript Support cs3=false cs3Label=CO Support src=110.202.200.66 cs1=NA cs1Label=Cap Support cs4=b4010c9c-14b7-4ce5-88e1-a5030cefa1e5 cs4Label=VID cs5=018cc31e00c7af9d29fb2058854cc90ccdd1c753ee28980c54416fe51f565f10eecacbc03108eeebe7554343a3c35bcc31da0cfc81013f2b8cbd5326ec0987ee4a4ea28155765b053669bcf12622383a7dc1702b74a21647b9f9fd9e6421b234 cs5Label=clappsig dproc=Site Helper cs6=Catchpoint cs6Label=clapp ccode=CN cicode=Shanghai cs7=31.0456 cs7Label=latitude cs8=121.3997 cs8Label=longitude Customer=Test - External ver= TLSv1.2 ECDHE-RSA-AES128-GCM-SHA256 start=1524770802082 request=example.com/ requestMethod=GET cn1=200 app=HTTPS act=REQ_PASSED deviceExternalId=284592737231615225 sip=141.34.25.158 spt=443 in=1044 xff=12.206.204.56, 186.240.270.97, 103.28.41.7 cpt=5353 fileType=90879 filePermission=0 cs9= cs9Label=Rule name'
cefFields = ['version', 'device_vendor', 'device_product', 'device_version', 'signature_id', 'name', 'severity', 'extension']

def recordToJson(record):
    regex = re.compile(r'''     # https://stackoverflow.com/a/5324269
        [\S]+=                  # a key (any word followed by a equals)
        (?:
        \s*                     # then a possible space
            (?!\S+=)\S+         # then a value (any word not followed by an equals)
        )+                      # match multiple values if present
        ''', re.VERBOSE)
    extension = dict()
    for pair in regex.findall(record):
        split = pair.split('=',1)
        extension[split[0]]=split[1]

    cefData = record.split("| ")[0].split("|")
    cefData.append(extension)
    cefRecord = dict(zip(cefFields, cefData))

    return cefRecord

def linesToJson(lines):
    json = ""
    records = lines.split("\n")

    for line in records:
        if len(line) > 0:
            json += str(recordToJson(line)) + '\n'
    return json


print(recordToJson(test))  # {'name': 'IncapRules(bad client)', 'extension': {'requestClientApplication': 'Mozilla/5.0 (compatible; Windows NT 6.1; Catchpoint) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36', 'cicode': 'Shanghai', 'deviceFacility': 'hkg', 'cs9Label': 'Rule name', 'app': 'HTTPS', 'deviceExternalId': '284592737231615225', 'cs2Label': 'Javascript Support', 'in': '1044', 'cs6Label': 'clapp', 'sip': '141.34.25.158', 'ver': ' TLSv1.2 ECDHE-RSA-AES128-GCM-SHA256', 'suid': '2047415', 'fileType': '90879', 'dproc': 'Site Helper', 'start': '1524770802082', 'cs8Label': 'longitude', 'sourceServiceName': 'example.com', 'ccode': 'CN', 'spt': '443', 'cs1Label': 'Cap Support', 'cs7Label': 'latitude', 'xff': '12.206.204.56, 186.240.270.97, 103.28.41.7', 'cs3Label': 'CO Support', 'fileId': '295037710147327529', 'src': '110.202.200.66', 'Customer': 'Test - External', 'cs4Label': 'VID', 'cn1': '200', 'cpt': '5353', 'cs5Label': 'clappsig', 'request': 'example.com/', 'requestMethod': 'GET', 'siteid': '10286633', 'cs8': '121.3997', 'act': 'REQ_PASSED', 'cs5': '018cc31e00c7af9d29fb2058854cc90ccdd1c753ee28980c54416fe51f565f10eecacbc03108eeebe7554343a3c35bcc31da0cfc81013f2b8cbd5326ec0987ee4a4ea28155765b053669bcf12622383a7dc1702b74a21647b9f9fd9e6421b234', 'cs4': 'b4010c9c-14b7-4ce5-88e1-a5030cefa1e5', 'cs7': '31.0456', 'cs6': 'Catchpoint', 'cs1': 'NA', 'filePermission': '0', 'cs3': 'false', 'cs2': 'false'}, 'version': 'CEF:0', 'device_product': 'SIEMintegration', 'device_version': '1', 'device_vendor': 'Incapsula', 'signature_id': '1', 'severity': '11'}