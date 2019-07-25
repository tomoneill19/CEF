# CFEF
### CF Exploitation Framework

* A framework for exploiting windows machines on your local network
* Uses Default credentials and planted backdoors to traverse the network
* Uses P2P sharing of information between users of the program
   * Credentials are encrypted over the network using AES 128

## Program Dependencies
* PSexec
    * https://docs.microsoft.com/en-us/sysinternals/downloads/psexec
    * `C:\Users\Admin\pstools\psexec`
* NBTScan
    * http://www.unixwiz.net/tools/nbtscan.html
    * `C:\Users\Admin\nbtscan`
    
Can be manually placed in the above locations or downloaded automatically upon running the program

## Python Dependencies
* Python 3
* PyCryptoDome
* Requests

Get these with `pip install`
