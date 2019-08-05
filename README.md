# CEF
### CF Exploitation Framework

* A framework for exploiting windows machines on your local network
* Uses Default credentials and planted backdoors to traverse the network
* Uses P2P sharing of information between users of the program
   * Credentials are encrypted over the network using AES 128
* Payloads written in C# can be remotely deployed with PSexec

## Program Dependencies
* PSexec
    * https://docs.microsoft.com/en-us/sysinternals/downloads/psexec
    * `C:\Users\Admin\pstools\psexec.exe`
* NBTScan
    * http://www.unixwiz.net/tools/nbtscan.html
    * `C:\Users\Admin\nbtscan.exe`
* .NET Framework
    * https://go.microsoft.com/fwlink/?linkid=2088517
    * `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe`
    * Necessary for deploying c# payloads
    
Can be manually placed in the above locations or downloaded automatically upon running the program

## Python Dependencies
* Python 3
* PyCryptoDome
* Requests

Get these with `pip install`

## Upcoming features
* Scalability
  * Detect the user's root path for dependency installation
* NetBIOS
  * Scan outside of the user's home group with nbtscan
