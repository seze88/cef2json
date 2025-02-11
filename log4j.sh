#!/bin/bash


for ip in {1..5}; do 
    echo -n "<164>CEF: 0|Palo Alto Networks|PAN-OS|11.2.3-h3|wildfire|THREAT|2|rt=Feb 03 2025 03:44:07 GMT deviceExternalId= src=10.10.0.69 dst=10.10.0.70 sourceTranslatedAddress=0.0.0.0 destinationTranslatedAddress=0.0.0.0 cs1Label=Rule cs1=Inside to Outside suser= duser= app=web-browsing cs3Label=Virtual System cs3=vsys1 cs4Label=Source Zone cs4=Inside cs5Label=Destination Zone cs5=Inside deviceInboundInterface=ethernet1/1 deviceOutboundInterface=ethernet1/1 cs6Label=LogProfile cs6=syslog-forwarding cn1Label=SessionID cn1=550 cnt=7 spt=57651 dpt=80 sourceTranslatedPort=0 destinationTranslatedPort=0 flexString1Label=Flags flexString1=0x2000 proto=tcp act=alert request="user.preference.php" cs2Label=URL Category cs2=not-resolved flexString2Label=Direction flexString2=server-to-client PanOSActionFlags=0x0 externalId=7466982072104517632 cat=Log4J File(57515) fileId=0 PanOSDGl1=0 PanOSDGl2=0 PanOSDGl3=0 PanOSDGl4=0 PanOSVsysName= dvchost=PANOSVM PanOSSrcUUID= PanOSDstUUID= PanOSTunnelID=0 PanOSMonitorTag= PanOSParentSessionID=0 PanOSParentStartTime= PanOSTunnelType=N/A PanOSThreatCategory=N/A PanOSContentVer=AppThreat-0-0 PanOSAssocID=0 PanOSPPID=4294967295 PanOSHTTPHeader= PanOSRuleUUID=7100098d-55e4-4d08-9d00-1d8a48d13041" | nc -u -w1 localhost 514; echo "${ip} done"; sleep 1;
     
done
