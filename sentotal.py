from __future__ import division
import virustotal
import time
import requests
import json
import sys
from util import Utilities
import getpass


# Ltango
# 6/12/2018
# Python 2.7
# SentinelOne API version 1.6


# This code uses both the SentinelOne API and VirusTotal API.  We retrieve a list of all threats inside sentinelOne
# and we retrieve the content_hash and ids of those threats.  Using this we plug in the threats into
# virusTotal through their API to determine if they are dangerous or not based on our own tolerances.
# Then if these are clean we automatically allow them (tagged as beniegn) or quarentine the process if
# they are deemed too dangerous.


#TODO change this url to fit your needs
baseurl = 'https://company.sentinelone.net'

def main():


	APIToken = 'your_sentinel_one_api_token'
	VTAPIToken = 'your_virus_total_api_token'

	s = requests.Session()
	# Bypass that can be implemented if you don't mind your username/password/token
	# hardcoded in plaintext into the script (which is bad practice but useful for testing)
	try:
		s.headers.update({'Authorization' : 'APIToken ' + APIToken})
		nestedList = constructNestedList(s)
		virusTotalChecks(s, nestedList, VTAPIToken)
		printSuccess("Finished Resolving Hashes!")
	except:
		print str(sys.exc_info()[0])
		return None
	s.close()


# Returns a nested list of all threat hashes and their ids in the form [[idList],[hashList]]
def getHashList(s, counter):
	printLog('Getting Threat Hash List...')
	payload = {
		'limit' : '500',
		'skip' : str(500 * counter),
		'resolved' : 'false'
	}
	r = s.get(baseurl + '/web/api/v1.6/threats', params = payload)
	if printAndCheckStatusCode(r):
		list1 = get_all(r.json(), 'id')
		list2 = get_all(r.json(), 'content_hash') 
		if len(list1) == 0:
			return None
		else:
			return [list1,list2]
	else:
		printError("failed to get threat hash list ")
		if r.json() is not none:
			print 'raw json data:' + str(r.json())
		return None


def constructNestedList(s):
	printLog('Constructing a list out of all of the threats...')
	counter = 0
	count = 0
	hashListBuilder = list()
	idListBuilder = list()
	builtNestedList = list()
	tempList = [0]
	while tempList is not None:
		tempList = getHashList(s, counter)
		if tempList is None:
			continue
		temphashList = tempList.pop()
		tempidList = tempList.pop()

		for i in temphashList:
			if i == 'ffffffffffffffffffffffffffffffffffffffff':
				pass
			else:
				hashListBuilder.append(temphashList[count])
				idListBuilder.append(tempidList[count])
			count = count + 1
		count = 0
		print 'number of hashes...' + str(len(hashListBuilder))

		counter = counter + 1
		printLog("constructing...")
	printSuccess("Successfully built list!")
	print 'Total number of hashes: ' + str(len(hashListBuilder))

	builtNestedList = [idListBuilder, hashListBuilder]

	#not nessesarily needed but I spent time writing it for some reason
	#printNumberOfUniqueHashes(idListBuilder,hashListBuilder)
	
	return builtNestedList



def printNumberOfUniqueHashes(idListBuilder,hashListBuilder):
	noRepeatHashList = list()
	#noRepeatIDList = list()
	#iteration = 0
	noRepeatHashList.append(hashListBuilder[0])
	#noRepeatIDList.append(idListBuilder[0])
	for i in hashListBuilder:
		for j in noRepeatHashList:
			if j == i:
				repeat = True
				continue
		if repeat == False:
			noRepeatHashList.append(i)
			#noRepeatIDList.append(idListBuilder[iteration])

		repeat = False

		#iteration = iteration + 1

	print "Unique number of hashes: " + len(noRepeatHashList)
	



# This method takes in a sentinelOne session, nested list of [[idList],[hashList]], and the VirusTotal
# API token.  Then based on values will determine if a file hash is dangerous based on VirusTotal's API
# calls, and the hard coded values below to find how many applications find the file dangerous.  It will
# also make calls to quarantine or allow files in the sentinelOne api based on how dangerous we determine
# them to be.
def virusTotalChecks(s,nestedList,VTAPIToken):
	printLog("Launching VirusTotal API module...")
	#Don't touch these
	totalCount = 0
	malwareCount = 0

	#change these values to change what is flagged as LOW and MEDIUM and HIGH
	# Virus total usually has about 70 AV applications to check the file hash so example values depending on
	# what risk you are looking for
	# 1/70  = 0.0142857142857143
	# 2/70  = 0.0285714285714286
	# 3/70  = 0.0428571428571429
	# 4/70  = 0.0571428571428571
	# 5/70  = 0.0714285714285714
	# 10/70 = 0.1428571428571429

	LOWPERCENTAGERISK = .05
	MEDPERCENTAGERISK = .10

	#change this value to change sleep time between file has checks
	hashCheckSleepTime = 15


	hashList = nestedList.pop()
	idList = nestedList.pop()


	loopCount = -1
	v = virustotal.VirusTotal(VTAPIToken)
	for i in hashList:
		loopCount = loopCount + 1

		try:
			#Read id
			report = v.get(i) 
			
			#wait for report to finish
			report.join()
			assert report.done == True
		except:
			#do nothing to the thing
			totalCount = 0
			malwareCount = 0
			printWarning('VirusTotal cannot find file hash: ' + i + ' is UKNOWN risk' + " for " + idList[loopCount])
			printLog('waiting ' + str(hashCheckSleepTime) +' seconds... VirusTotal Public API only supports 4 calls per minute...')
			time.sleep(hashCheckSleepTime)
			continue



		for antivirus, malware in report:
			if malware is not None:
				malwareCount = malwareCount + 1
				totalCount = totalCount + 1
				
			else:
				totalCount = totalCount + 1
				
		#VirusTotal Public API only 4 calls per minute
		#printLog(i + " has a VirusTotal Count of " + str(malwareCount) + "/" + str(totalCount))
		if malwareCount == 0:
			printSuccess("Hash:" + i + " is CLEAN " + str(malwareCount) + "/" + str(totalCount) + " for id:" + idList[loopCount])
			#print 'should allow'
			sentinelAllowHash(s,idList[loopCount])
			sentinelMarkThreatAsResolved(s,i)

		elif (malwareCount/totalCount) < LOWPERCENTAGERISK:
			printWarning("Hash:" + i + " is LOW risk "+ str(malwareCount) + "/" + str(totalCount) + " for id:" + idList[loopCount])

		elif (malwareCount/totalCount) < MEDPERCENTAGERISK:
			printWarning("Hash:" + i + " is MEDIUM risk " + str(malwareCount) + "/" + str(totalCount) + " for id:" + idList[loopCount])

		else:
			printError("Hash:" + i + " is HIGH risk " + str(malwareCount) + "/" + str(totalCount) + " for id:" + idList[loopCount])
			#Make thing not allowed
			#sentinelQuarantineHash(s,idList[loopCount])
			if not sentinelIsBlackHash(s, i):
				#print 'is not black listed'
				sentinelKillHash(s,idList[loopCount])
				sentinelQuarantineHash(s,idList[loopCount])
				sentinelBlacklistHash(s, i)
				sentinelMarkThreatAsResolved(s,i)
			else:
				#print 'is already black listed'
				sentinelKillHash(s,idList[loopCount])
				sentinelQuarantineHash(s,idList[loopCount])
				sentinelMarkThreatAsResolved(s,i)

			#reset counters for next iteration of checking file hash
			totalCount = 0
			malwareCount = 0
			printLog('waiting ' + str(hashCheckSleepTime) +' seconds... VirusTotal Public API only supports 4 calls per minute...')
			time.sleep(hashCheckSleepTime)

# This method attempts to allow and mark a threat as benign based on threatID
def sentinelAllowHash(s, threatID):
	printLog('Marking threat as benign id:' + threatID)
	r = s.post(baseurl + '/web/api/v1.6/threats/'+ threatID + '/mark-as-benign')
	if printAndCheckStatusCode(r):
		data = r.json()
		
		return None
	else:
		printError("failed to mark id:" + threatID + " as benign")
		if r.json() is not None:
			print 'raw json data:' + str(r.json())

# This method attempts to quarantine (either machine or process) responsible based on the threatID
def sentinelQuarantineHash(s, threatID):
	printLog('Quarantining threat id:' + threatID)
	r = s.post(baseurl + '/web/api/v1.6/threats/'+ threatID +'/mitigate/quarantine')
	if printAndCheckStatusCode(r):
		
		return None
	else:
		printError("failed to quarantine id:" + threatID)
		if r.json() is not None:
			print 'raw json data:' + r.json()

def sentinelKillHash(s, threatID):
	printLog('Killing threat id:' + threatID)
	r = s.post(baseurl + '/web/api/v1.6/threats/'+ threatID +'/mitigate/kill')
	if printAndCheckStatusCode(r):

		return None
	else:
		printError("failed to kill id:" + threatID)
		if r.json() is not None:
			print 'raw json data:' + r.json()


def sentinelMarkThreatAsResolved(s, contentHash):
	printLog('Marking threat id:' + contentHash + ' as resolved')
	payload = {
		'content_hash' : str(contentHash)
	}
	r = s.post(baseurl + '/web/api/v1.6/threats/resolve', params = payload)
	if printAndCheckStatusCode(r):
		
		return None
	else:
		printError('Failed to mark threat id:' + contentHash + ' as resolved')
		if r.json() is not None:
			print 'raw json data:' + str(r.json())





def sentinelBlacklistHash(s, contentHash):
	printLog('Blacklisting content hash:' + contentHash)
	payload = {
		'is_black' : 'true'
	}
	r = s.put(baseurl + '/web/api/v1.6/hashes/'+ contentHash, json = payload)
	if printAndCheckStatusCode(r):
		return None
	else:
		printError("failed to blacklist content hash:" + contentHash)
		if r.json() is not None:
			print 'raw json data:' + str(r.json())


def sentinelRemoveBlackHash(s, contentHash):
	printLog('Removing content hash:' + contentHash + " from blacklist")
	payload = {
		'is_black' : 'false'
	}
	r = s.put(baseurl + '/web/api/v1.6/hashes/'+ contentHash, json = payload)
	if printAndCheckStatusCode(r):
		return None
	else:
		printError('failed to remove content hash:' + contentHash + " from blacklist")
		if r.json() is not None:
			print 'raw json data:' + str(r.json())


def sentinelListAllHashes(s):
	printLog('Listing all hashes...')
	r = s.get(baseurl + '/web/api/v1.6/hashes')
	if printAndCheckStatusCode(r):
		print json.dumps(r.json(), indent=4)
	else:
		printError('failed to get hashes:')
		if r.json() is not None:
			print 'raw json data:' + str(r.json())



def sentinelCreateTestHash(s, testHash):
	printLog('Creating content hash:')
	payload = {
		'hash' : testHash,
		'is_black' : 'false',
		'description' : 'test hash',
		'os_family' : 'windows'
	}
	r = s.post(baseurl + '/web/api/v1.6/hashes', json = payload)
	if printAndCheckStatusCode(r):
		return None
	else:
		printError('failed to create content hash:')
		if r.json() is not None:
			print 'raw json data:' + str(r.json())


def sentinelDeleteHash(s, hashID):
	printLog('Deleting hash id:' + hashID)
	r = s.delete(baseurl + '/web/api/v1.6/hashes/' + hashID)
	if printAndCheckStatusCode(r):
		return None
	else:
		printError("failed to delete hash id:" + threatID)
		if r.json() is not None:
			print 'raw json data:' + str(r.json())



def sentinelGetHash(s, hashID):
	printLog('getting hash id:' + hashID)
	r = s.get(baseurl + '/web/api/v1.6/hashes/' + hashID)
	if printAndCheckStatusCode(r):
		return r.json()
	else:
		printError("failed to get hash id:" + hashID)
		if r.json() is not None:
			print 'raw json data:' + str(r.json())


def sentinelIsBlackHash(s, hashID):
	printLog('getting hash id:' + hashID)
	r = s.get(baseurl + '/web/api/v1.6/hashes/' + hashID)
	if printAndCheckStatusCode(r):
		if get_all(r.json(), 'is_black').pop() == 'True':
			return True
		else: 
			return False
	else:
		printError("failed to get hash id:" + threatID)
		if r.json() is not None:
			print 'raw json data:' + str(r.json())

# this is my beautiful recursive search function that returns an array of all instances of a key
# within a json response - Sentinel One has many different types of json inside lists and arrays
# all nested within each other so recursion is the only way to go - and it does have to go through
# the entire json response
# THIS WILL RETURN A LIST EVEN IF IT IS ONLY 1 ITEM FOUND SO YOU MUST POP() TO GET CLEAN INPUT
def get_all(myjson, key):
	recursiveResult = []
	if type(myjson) == str:
		myjson = json.loads(myjson)
	if type(myjson) is dict:
		for jsonkey in myjson:
			if type(myjson[jsonkey]) in (list, dict):
				recursiveResult += get_all(myjson[jsonkey], key)
			elif jsonkey == key:
				recursiveResult.append(str(myjson[jsonkey]))
	elif type(myjson) is list:
		for item in myjson:
			if type(item) in (list, dict):
				recursiveResult += get_all(item, key) 
	return recursiveResult

# based on status code from response; really just makes things green, red, or blue
def printAndCheckStatusCode(r):
	if r.status_code == 200 or r.status_code == 204 or r.status_code == 201:
		printSuccess(str(r))
		return True
	elif r.status_code == 405:
		printError(str(r) + " - may need to change 'post' method to 'get' or vise versa")
	else:
		printError(str(r))
	return False

# put these here from utilities file so we don't need 
# to instatiate every single time we need to print
# basically just makes your log pretty and easier to read
def printSuccess(msg):
	print(Utilities.OKGREEN + "[OK]" + msg + Utilities.ENDC)
def printError(msg):
	print(Utilities.FAIL + "[ERROR]" + msg + Utilities.ENDC + str(sys.exc_info()[0]))
def printException(msg):
	print(Utilities.FAIL + "[EXCEPTION]" + msg + Utilities.ENDC + str(sys.exc_info()[0]))
def printLog(msg):
	print(Utilities.OKBLUE + "[LOG]" + msg + Utilities.ENDC)
def printWarning(msg):
	print(Utilities.WARNING + "[ATTENTION]" + msg + Utilities.ENDC)

# launch main()
if __name__ == "__main__": main()