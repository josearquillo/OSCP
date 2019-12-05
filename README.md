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

#### 3- VISUAL

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
{LINUX}
{WINDOWS}
{METASPLOIT: SUGGESTER}

### FILE TRANSFER

{FILE TRANSFER}

### REVERSE SHELL

{REVERSE SHELL}

#### UPGRADE SHELL

{UPGRADE SHELL}

## 7) POST EXPLOTATION / PRIVILEGE ESCALATION (USER 2)

{SEARCHSPLOIT / EXPLOIT-DB}
{METASPLOIT}

[REPEAT UNTIL...]

## N) POST EXPLOTATION / PRIVILEGE ESCALATION (USER ROOT/ADMIN)


## N+1) REPORT


--------------------------------------------------------------
