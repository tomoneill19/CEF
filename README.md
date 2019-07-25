# CFEF
### CF Exploitation Framework

* A framework for exploiting windows machines on your local network
* Uses Default credentials and planted backdoors to traverse the network
* Uses P2P sharing of information between users of the program
   * Credentials are encrypted over the network using AES 128

## Program Dependencies
* PSexec
    * https://docs.microsoft.com/en-us/sysinternals/downloads/psexec
    * `C:\Users\Admin\pstools\psexec.exe`
* NBTScan
    * http://www.unixwiz.net/tools/nbtscan.html
    * `C:\Users\Admin\nbtscan.exe`
    
Can be manually placed in the above locations or downloaded automatically upon running the program

## Python Dependencies
* Python 3
* PyCryptoDome
* Requests

Get these with `pip install`

## Upcoming features
* Malware deployment
  * Sourcecode supplied with the project
  * Compiles with CSC at deployment time
* Scalability
  * Detect the user's root path for dependency installation
* NetBIOS
  * Scan outside of the user's home group with nbtscan
