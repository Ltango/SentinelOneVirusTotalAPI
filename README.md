# SentinelOneVirusTotalAPI

Requires: 
virustotal
requests

python version 2.7
sentinelOne API version 1.6

This code uses both the SentinelOne API and VirusTotal API.  We retrieve a list of all threats inside sentinelOne and we retrieve the content_hash and ids of those threats.  Using this we plug in the threats into virusTotal through their API to determine if they are dangerous or not based on our own tolerances. Then if these are clean we automatically allow them (tagged as beniegn) or quarentine the process if they are deemed too dangerous.
