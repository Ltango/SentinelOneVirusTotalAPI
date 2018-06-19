from __future__ import division
import virustotal
import time
import requests
import json
import sys
from util import Utilities
import getpass
from time import gmtime, strftime, localtime
import os
import logging


# Ltango
# 6/12/2018
# Python 2.7
# SentinelOne API version 1.6


# This code uses both the SentinelOne API and VirusTotal API.  We retrieve a list of all threats inside sentinelOne
# and we retrieve the content_hash and ids of those threats.  Using this we plug in the threats into
# virusTotal through their API to determine if they are dangerous or not based on our own tolerances.
# Then if these are clean we automatically allow them (tagged as beniegn) or quarentine the process if
# they are deemed too dangerous.


#global counter variables
fffTypeCount = 0
cleanTypeCount = 0
lowTypeCount = 0
medTypeCount = 0
highTypeCount = 0
resolvedCount = 0
unknownCount = 0

#TODO change this url to fit your needs
baseurl = 'https://company.sentinelone.net'
def main():


	APIToken = 'your_sentinel_one_api_token'
	VTAPIToken = 'your_virus_total_api_token'



	while True:

		#We are going to run our main scirpt 20 times
		for x in range(20):

			logfileName = strftime('TimeS1 -- ' + "%Y-%m-%d -- %H-%M-%S", localtime()) + '.log'
			logging.basicConfig(filename = logfileName, format='%(asctime)s : %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p', level=logging.WARNING)

			unknownList = list()
			unknownTextFile = open("unknownlist.txt", "r")
			unknownList = unknownTextFile.read().splitlines()
			unknownTextFile.close()

			tempLowList = list()
			tempLowTextFile = open("lowPercentageRiskHashes.txt", "r")
			tempLowList = tempLowTextFile.read().splitlines()
			tempLowTextFile.close()

			tempMedList = list()
			tempMedTextFile = open("medPercentageRiskHashes.txt", "r")
			tempMedList = tempMedTextFile.read().splitlines()
			tempMedTextFile.close()

			statinfo = os.stat('unknownlist.txt')
			if statinfo.st_size > 50000000:
				print "unknownlist.txt has reached as size of 50 MB - consider action to reduce size..."


			s = requests.Session()

			try:

				s.headers.update({'Authorization' : 'APIToken ' + APIToken})
				nestedList = constructNestedList(s)



				if len(nestedList[0]) < 100:
					printWarning("Low amount of threats detected... sleeping 10 min to prevent out of control looping")
					time.sleep(600)



				virusTotalChecks(s, nestedList, VTAPIToken, unknownList, tempLowList, tempMedList)
				printSuccess("Finished Resolving Hashes!")
				
				print 'number of fffff: ' + str(fffTypeCount)
				print 'number of unknown: ' + str(unknownCount)
				print 'number of clean: ' + str(cleanTypeCount)
				print 'number of low: ' + str(lowTypeCount)
				print 'number of med: ' + str(medTypeCount)
				print 'number of high: ' + str(highTypeCount)
				print 'number of resolved threats: ' + str(resolvedCount)

				logging.WARNING('number of fffff: ' + str(fffTypeCount))
				logging.WARNING('number of unknown: ' + str(unknownCount))
				logging.WARNING('number of clean: ' + str(cleanTypeCount))
				logging.WARNING('number of low: ' + str(lowTypeCount))
				logging.WARNING('number of med: ' + str(medTypeCount))
				logging.WARNING('number of high: ' + str(highTypeCount))
				logging.WARNING('number of resolved threats: ' + str(resolvedCount))

				restartGlobalCounterVariables()
			except:
				print str(sys.exc_info()[0])
				return None
			s.close()

		#This is our side script that just goes through the list of 
		checkSavedListOnVT(VTAPIToken , unknownList)



def checkSavedListOnVT(VTAPIToken, unknownList):
	newCheckedHashList = list()
	printLog("Updating Unknown list to see if Virus Total has their hash now...")
	v = virustotal.VirusTotal(VTAPIToken)
	for i in unknownList:
		try:
			#Read id
			report = v.get(i) 
			#wait for report to finish
			report.join()
			assert report.done == True
			printWarning('Hash: ' + i + ' is now in VirusTotal and will be removed from unknownlist.txt')
		except:
			newCheckedHashList.append(i)			
			continue


	newUnknownTextFile = open("unknownlist.txt", "w")
	for j in newCheckedHashList:
		newUnknownTextFile.write(j + '\n')
	newUnknownTextFile.close()	
	printSuccess("unknownlist.txt has been successfully updated!")


def restartGlobalCounterVariables():
	global fffTypeCount
	fffTypeCount = 0
	global cleanTypeCount
	cleanTypeCount = 0
	global lowTypeCount
	lowTypeCount = 0
	global medTypeCount
	medTypeCount = 0
	global highTypeCount
	highTypeCount = 0
	global resolvedCount
	resolvedCount = 0
	global unknownCount
	unknownCount = 0


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
				global fffTypeCount
				fffTypeCount = fffTypeCount + 1
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
	logging.warning('Number of hashes to process: ' + str(len(hashListBuilder)))


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
def virusTotalChecks(s,nestedList,VTAPIToken,theUnknownList,theLowList,theMediumList):
	printLog("Launching VirusTotal API module...")


	global unknownCount
	global cleanTypeCount
	global highTypeCount
	global lowTypeCount
	global medTypeCount
	global resolvedCount

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


	hashList = nestedList.pop()
	idList = nestedList.pop()
	checkedHashList = list()
	benignResolvedHashList = list()
	killResolvedHashList = list()
	alreadyChecked = False
	threatAgentUserDescriptionList = list()




	loopCount = -1
	v = virustotal.VirusTotal(VTAPIToken)
	for i in hashList:
		loopCount = loopCount + 1


		


		for j in theUnknownList:
			if j == i:
				alreadyChecked = True
				unknownCount = unknownCount + 1
				printLog('Hash: ' + i + ' is in unknownlist.txt and will not be submitted to VirusTotal')
				#logging.warning('Hash: ' + i + ' is in unknownlist.txt and will not be submitted to VirusTotal')
				continue

		if alreadyChecked == True:
			alreadyChecked = False
			continue

		for j in theLowList:
			if j == i:
				alreadyChecked = True
				lowTypeCount = lowTypeCount + 1
				printLog('Hash: ' + i + ' is in lowPercentageRiskHashes.txt and will not be submitted to VirusTotal')
				#logging.warning('Hash: ' + i + ' is in lowPercentageRiskHashes.txt and will not be submitted to VirusTotal')
				continue

		if alreadyChecked == True:
			alreadyChecked = False
			continue

		for j in theMediumList:
			if j == i:
				alreadyChecked = True
				medTypeCount = medTypeCount + 1
				printLog('Hash: ' + i + ' is in medPercentageRiskHashes.txt and will not be submitted to VirusTotal')
				#logging.warning('Hash: ' + i + ' is in medPercentageRiskHashes.txt and will not be submitted to VirusTotal')
				continue

		if alreadyChecked == True:
			alreadyChecked = False
			continue			



		threatAgentUserDescriptionList = getThreatAgentUserDescription(s, idList[loopCount])
		threatDescription = str(threatAgentUserDescriptionList.pop())
		threatAgentID = str(threatAgentUserDescriptionList.pop())
		threatAgent = getComputerNameFromAgentID(s,threatAgentID)
		threatUser = str(threatAgentUserDescriptionList.pop())


		if agentIsDecommissioned(s, threatAgentID):
			printWarning('Threat ID:' + idList[loopCount] + ' is on decommissioned agent ID:' + threatAgentID + ', ignoring for now...')
			logging.warning('Hash: ' + i + ' on decommissioned agent(action:ignored) -- User:' + threatUser + ' -- Machine:' + threatAgent + ' -- Description:' + threatDescription)
			continue

		for k in benignResolvedHashList:
			if i == k:
				printLog('Hash already resolved - marking threat ID: ' + idList[loopCount] + ' as benign')
				sentinelAllowThreat(s, idList[loopCount])


				logging.warning('Hash: ' + i + ' marked as CLEAN(action:marked as benign) -- User:' + threatUser + ' -- Machine:' + threatAgent + ' -- Description:' + threatDescription)

				cleanTypeCount = cleanTypeCount + 1
				alreadyChecked = True
				continue

		if alreadyChecked == True:
			alreadyChecked = False
			continue




		for k in killResolvedHashList:
			if i == k:
				printLog('Hash already resolved - marking threat ID: ' + idList[loopCount] + ' as resolved and killing/quarantining threat')
				sentinelKillThreat(s,idList[loopCount])
				sentinelQuarantineThreat(s,idList[loopCount])
				sentinelMarkThreatAsResolved(s,idList[loopCount])

				logging.warning('Hash: ' + i + ' marked as HIGH (action:killed/quarentined/resolved/blacklisted) -- User:' + threatUser + ' -- Machine:' + threatAgent + ' -- Description:' + threatDescription)




				if not sentinelIsBlackHash(s, i):
					sentinelBlacklistHash(s, i)
				alreadyChecked = True
				highTypeCount = highTypeCount + 1
				continue

		if alreadyChecked == True:
			alreadyChecked = False
			continue



		#Here we do the same thing but it just handles unknowns/other things we don't actually resolve
		#but we don't need to send it through VT again
		for j in checkedHashList:
			if i == j:
				printLog('Hash: ' + i + ' already checked - skipping...')
				alreadyChecked = True
				continue

		if alreadyChecked == True:
			alreadyChecked = False
			continue

		try:
			#Read id
			report = v.get(i) 
			
			#wait for report to finish
			report.join()
			assert report.done == True
		except:
			totalCount = 0
			malwareCount = 0
			printWarning('VirusTotal cannot find file hash: ' + i + ' is UNKNOWN risk' + " for " + idList[loopCount])
			logging.warning('Hash: ' + i + ' marked as UNKNOWN(action:ignored/added to list) -- User:' + threatUser + ' -- Machine:' + threatAgent + ' -- Description:' + threatDescription)

			unknownCount = unknownCount + 1
			unknownTextFile = open("unknownlist.txt", "a")
			unknownTextFile.write(i + '\n')
			unknownTextFile.close()
			checkedHashList.append(i)
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
			sentinelAllowThreat(s,idList[loopCount])
			logging.warning('Hash: ' + i + ' marked as CLEAN(action:marked as benign) -- User:' + threatUser + ' -- Machine:' + threatAgent + ' -- Description:' + threatDescription)


			#turns out marking as benign automatically marks it as resolved
			#sentinelMarkThreatAsResolved(s,idList[loopCount])
			benignResolvedHashList.append(i)
			cleanTypeCount = cleanTypeCount + 1
			checkedHashList.append(i)

		elif (malwareCount/totalCount) < LOWPERCENTAGERISK:
			printWarning("Hash:" + i + " is LOW risk "+ str(malwareCount) + "/" + str(totalCount) + " for id:" + idList[loopCount])
			lowTypeCount = lowTypeCount + 1
			checkedHashList.append(i)
			logging.warning('Hash: ' + i + ' marked as LOW(action:ignored/added to list) -- User:' + threatUser + ' -- Machine:' + threatAgent + ' -- Description:' + threatDescription)

			lowExists = False
			for m in theLowList:
				if m == i:
					lowExists = True
					continue

			if not lowExists:
				lowText = open("lowPercentageRiskHashes.txt", "a")
				lowText.write(i + '\n')
				lowText.close()



		elif (malwareCount/totalCount) < MEDPERCENTAGERISK:
			printWarning("Hash:" + i + " is MEDIUM risk " + str(malwareCount) + "/" + str(totalCount) + " for id:" + idList[loopCount])
			medTypeCount = medTypeCount + 1
			checkedHashList.append(i)

			logging.warning('Hash: ' + i + ' marked as MEDIUM(action:ignored/added to list) -- User:' + threatUser + ' -- Machine:' + threatAgent + ' -- Description:' + threatDescription)

			medExists = False
			for n in theMediumList:
				if n == i:
					medExists = True
					continue

			if not medExists:
				medText = open("medPercentageRiskHashes.txt", "a")
				medText.write(i + '\n')
				medText.close()

		else:
			printError("Hash:" + i + " is HIGH risk " + str(malwareCount) + "/" + str(totalCount) + " for id:" + idList[loopCount])
			highTypeCount = highTypeCount + 1
			sentinelKillThreat(s,idList[loopCount])
			sentinelQuarantineThreat(s,idList[loopCount])
			sentinelMarkThreatAsResolved(s,idList[loopCount])
			killResolvedHashList.append(i)
			checkedHashList.append(i)
			if not sentinelIsBlackHash(s, i):
				sentinelBlacklistHash(s, i)

			logging.warning('Hash: ' + i + ' marked as HIGH (action:killed/quarentined/resolved/blacklisted) -- User:' + threatUser + ' -- Machine:' + threatAgent + ' -- Description:' + threatDescription)



		#reset counters for next iteration of checking file hash
		totalCount = 0
		malwareCount = 0



def agentIsDecommissioned(s, agentID):
	printLog('Checking if agent is decommissioned for agent ID:' + str(agentID))
	r = s.get(baseurl + '/web/api/v1.6/agents/'+ str(agentID))
	if printAndCheckStatusCode(r):
		is_decommissioned = get_all(r.json(), 'is_decommissioned').pop()
		if is_decommissioned == 'True':
			return True
		else:
			return False
	else:
		printError("Failed to check if agent is decommissioned for agent ID:" + str(agentID))
		if r.json() is not None:
			print 'raw json data:' + str(r.json())



def getThreatAgentUserDescription(s, threatID):
	printLog('Getting threat details for treat ID:' + str(threatID))
	r = s.get(baseurl + '/web/api/v1.6/threats/'+ str(threatID))
	if printAndCheckStatusCode(r):


		agentUserDescpriontList = list()

		tUsername = get_all(r.json(), 'username').pop()
		agentUserDescpriontList.append(tUsername)


		tAgent = get_all(r.json(), 'agent').pop()
		agentUserDescpriontList.append(tAgent)

		tDescription = get_all(r.json(), 'description').pop()
		agentUserDescpriontList.append(tDescription)


		return agentUserDescpriontList
	else:
		printError("failed to get details for threat id:" + str(threatID))
		if r.json() is not None:
			print 'raw json data:' + str(r.json())


def getComputerNameFromAgentID(s, agentID):
	printLog('Getting computer name for agent ID:' + str(agentID))
	r = s.get(baseurl + '/web/api/v1.6/agents/'+ str(agentID))
	if printAndCheckStatusCode(r):
		computerName = get_all(r.json(), 'computer_name')
		return computerName.pop()
	else:
		printError("failed to get computer name for agent ID:" + str(agentID))
		if r.json() is not None:
			print 'raw json data:' + str(r.json())


# This method attempts to allow and mark a threat as benign based on threatID
def sentinelAllowThreat(s, threatID):
	printLog('Marking threat as benign id:' + str(threatID))
	r = s.post(baseurl + '/web/api/v1.6/threats/'+ str(threatID) + '/mark-as-benign')
	if printAndCheckStatusCode(r):
		return None
	else:
		printError("failed to mark id:" + str(threatID) + " as benign")
		if r.json() is not None:
			print 'raw json data:' + str(r.json())

# This method attempts to quarantine (either machine or process) responsible based on the threatID
def sentinelQuarantineThreat(s, threatID):
	printLog('Quarantining threat id:' + str(threatID))
	r = s.post(baseurl + '/web/api/v1.6/threats/'+ str(threatID) +'/mitigate/quarantine')
	if printAndCheckStatusCode(r):
		
		return None
	else:
		printError("failed to quarantine id:" + str(threatID))
		if r.json() is not None:
			print 'raw json data:' + r.json()

def sentinelKillThreat(s, threatID):
	printLog('Killing threat id:' + str(threatID))
	r = s.post(baseurl + '/web/api/v1.6/threats/'+ str(threatID) +'/mitigate/kill')
	if printAndCheckStatusCode(r):

		return True
	else:
		printError("failed to kill id:" + str(threatID))
		if r.json() is not None:
			print 'raw json data:' + r.json()


def sentinelMarkThreatAsResolved(s, threatID):
	printLog('Marking threat id:' + str(threatID) + ' as resolved')
	r = s.post(baseurl + '/web/api/v1.6/threats/'+ str(threatID) +'/resolve')
	if printAndCheckStatusCode(r):
		global resolvedCount
		resolvedCount = resolvedCount + 1
		return None
	else:
		printError('Failed to mark threat id:' + str(threatID) + ' as resolved')
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
		printError("failed to delete hash id:" + hashID)
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
		printError("failed to get hash id:" + hashID)
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
		raise Exception('405\'d')
	else:
		printError(str(r))
		printError("You need an adult, something bad happened")
		raise Exception('Something bad happened...')
	return False

# put these here from utilities file so we don't need 
# to instatiate every single time we need to print
# basically just makes your log pretty and easier to read
def printSuccess(msg):
	print(Utilities.OKGREEN + "[OK]" + msg + Utilities.ENDC)
def printError(msg):
	print(Utilities.FAIL + "[ERROR]" + msg + Utilities.ENDC)
def printException(msg):
	print(Utilities.FAIL + "[EXCEPTION]" + msg + Utilities.ENDC + str(sys.exc_info()[0]))
def printLog(msg):
	print(Utilities.OKBLUE + "[LOG]" + msg + Utilities.ENDC)
def printWarning(msg):
	print(Utilities.WARNING + "[ATTENTION]" + msg + Utilities.ENDC)


# launch main()
if __name__ == "__main__": main()