<!-- TOC -->
* [Nmap](#nmap)
  * [Ping Scan (a.k.a. Host Discovery)](#ping-scan-aka-host-discovery)
  * [Connect Scan](#connect-scan)
  * [SYN (Stealth) Scan](#syn-stealth-scan)
  * [Idle (Zombie) Scan](#idle-zombie-scan)
  * [UDP Scan](#udp-scan)
  * [ACK Scan](#ack-scan)
  * [Null Scan](#null-scan)
  * [Nmap Scripting Engine (NSE)](#nmap-scripting-engine-nse)
    * [A Note On NSE Stealth](#a-note-on-nse-stealth)
    * [Default Scripts](#default-scripts)
    * [Discovery Scripts](#discovery-scripts)
    * [Vuln Scripts](#vuln-scripts)
    * [Vulscan](#vulscan)
  * [Optimisations](#optimisations)
    * [Useful Options for Optimising Stealth](#useful-options-for-optimising-stealth)
      * [Timings](#timings)
      * [Fragmentation](#fragmentation)
      * [Decoys](#decoys)
      * [Avoiding XMAS and FIN Scans](#avoiding-xmas-and-fin-scans)
    * [Useful Options for Getting More Information](#useful-options-for-getting-more-information)
      * [OS Detection](#os-detection)
      * [Version Probing](#version-probing)
    * [Useful Options for Optimising Time Consumption](#useful-options-for-optimising-time-consumption)
      * [Scanning only common ports](#scanning-only-common-ports)
      * [Scanning only known-open ports](#scanning-only-known-open-ports)
      * [Version Intensity](#version-intensity)
* [Application Reconnaissance](#application-reconnaissance)
  * [Automated Web Application Scanners](#automated-web-application-scanners)
    * [WhatWeb](#whatweb)
    * [Retire.js](#retirejs)
    * [is-website-vulnerable](#is-website-vulnerable)
    * [Wapiti](#wapiti)
  * [Path Enumeration](#path-enumeration)
    * [Katana](#katana)
    * [GoSpider](#gospider)
    * [DirBuster](#dirbuster)
    * [GoBuster](#gobuster)
    * [Arjun](#arjun)
  * [SMB Enumeration](#smb-enumeration)
    * [Nmap Port Scanning](#nmap-port-scanning)
    * [NSE Scripts](#nse-scripts)
    * [smbclient](#smbclient)
    * [SMBMap](#smbmap)
  * [NFS Enumeration](#nfs-enumeration)
    * [RPC](#rpc)
    * [Scanning NFS with Nmap](#scanning-nfs-with-nmap)
    * [Mounting The Export](#mounting-the-export)
    * [NfSpy](#nfspy)
  * [FTP Enumeration](#ftp-enumeration)
    * [Scanning FTP with Nmap](#scanning-ftp-with-nmap)
    * [FTP Bounce Attacks](#ftp-bounce-attacks)
    * [Access](#access)
  * [SMTP Enumeration](#smtp-enumeration)
    * [Scanning SMTP with Nmap](#scanning-smtp-with-nmap)
    * [smtp-user-enum](#smtp-user-enum)
    * [Metasploit SMTP Module](#metasploit-smtp-module)
  * [SNMP Enumeration](#snmp-enumeration)
    * [How SNMP Works](#how-snmp-works)
    * [Protocol Versions](#protocol-versions)
    * [Brute-Forcing Community Strings](#brute-forcing-community-strings)
    * [Scanning SNMP with Nmap](#scanning-snmp-with-nmap)
    * [Hydra](#hydra)
    * [onesixtyone](#onesixtyone)
    * [SNMPWalk](#snmpwalk)
    * [SNMP-Check](#snmp-check)
    * [Braa](#braa)
  * [WebDAV Enumeration](#webdav-enumeration)
    * [Finding WebDAV Paths](#finding-webdav-paths)
    * [Brute-Forcing WebDAV Credentials](#brute-forcing-webdav-credentials)
    * [Checking if WebDAV is enabled](#checking-if-webdav-is-enabled)
      * [Nmap](#nmap-1)
      * [Metasploit](#metasploit)
    * [DAVTest](#davtest)
    * [Cadavar](#cadavar)
      * [A Note on Stealth](#a-note-on-stealth)
<!-- TOC -->


# Nmap

Nmap offers a variety of scans designed to discover the services that are running on a particular machine,
as well as any firewall rules that may be filtering incoming traffic.

The default behaviour of running `nmap <target_ip>` depends on if the user is privileged or not.
For a privileged user, the default option is the [TCP SYN scan](#syn-stealth-scan), whereas for a non-privileged user is the normal [TCP connect() scan](#connect-scan).

**IMPORTANT - Before running any of these scans, make sure to also read the [optimisations section](#optimisations) for how to reduce your chances of detection during a scan,
as well as changes to increase the amount of information discovered**


## Ping Scan (a.k.a. Host Discovery)

Nmap will conduct a "Host Discovery" phase before scanning each target provided, in order to ensure the host is actually up and avoid wasting time scanning IP addresses that are inactive.
You can see this behaviour for yourself by enabling verbose logs with the `-v` flag.
The default host discovery involves sending an ICMP echo request, a TCP SYN packet to port 443, a TCP ACK packet to port 80, and an ICMP timestamp request.

To do *only* host discovery without a port scan, you can run the following command:

```
# nmap -sn <target>
```

Constrastingly, you can also instruct Nmap to skip the discovery phase altogether.
This is useful when you want to scan the target(s) even if it they have a strict firewall that doesn't respond to any of your ping scans:

```
# nmap -Pn <target>
```

Alternatively, if you find your target is unresponsive to the default host discovery, you can create a custom scan of your own with the following options:

| Nmap Option          | Description                                                                                                                                                                                                                               |
|----------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `-PS<port list>`     | TCP SYN Ping                                                                                                                                                                                                                              |
| `-PA<port list>`     | TCP ACK Ping                                                                                                                                                                                                                              |
| `-PU<port list>`     | TCP UDP Ping - Where the port is in the `nmap-service-probes` file, known probes are used to increase the chances of a response.                                                                                                          |
| `-PE; -PP; -PM`      | ICMP echo, timestamp, and netmask request discovery probes - Typically not very reliable for scanning unknown targets over the internet due to being commonly blocked by firewalls, but they can be quite effective on internal networks. |
| `-PO<protocol list>` | IP Protocol Ping                                                                                                                                                                                                                          |


## Connect Scan

The TCP Connect() scan is the most basic port scan offered by Nmap.
It works by attempting the regular 3-way TCP handshake with every port specified on the target host, or all ports if none are specified like so:

```
$ nmap -sT <target>
```

The main advantage of the Connect() scan is that you don't require elevated privileges on the machine you're using to conduct the scan.
However, by actually forming a TCP connection with each port in an attempt to connect to the running service, you're much more likely to be logged than with a SYN scan.

```
nmap -sT 192.168.56.127
Starting Nmap 7.80 ( https://nmap.org ) at 2023-11-20 23:52 GMT
Nmap scan report for 192.168.56.127
Host is up (0.00028s latency).
Not shown: 981 filtered ports
PORT     STATE  SERVICE
21/tcp   open   ftp
22/tcp   open   ssh
23/tcp   open   telnet
25/tcp   open   smtp
80/tcp   closed http
111/tcp  open   rpcbind
139/tcp  open   netbios-ssn
161/tcp  closed snmp
445/tcp  open   microsoft-ds
512/tcp  open   exec
513/tcp  open   login
514/tcp  open   shell
631/tcp  closed ipp
1099/tcp open   rmiregistry
1524/tcp open   ingreslock
2121/tcp open   ccproxy-ftp
3306/tcp open   mysql
5432/tcp open   postgresql
6667/tcp open   irc
```


## SYN (Stealth) Scan

The TCP SYN scan is an improved version of the TCP Connect() scan that only conducts partial handshake before prematurely terminating the connection.
The scanner sends a SYN packet, and if server responds with a SYN/ACK the scanner sends a RST, ending the handshake before it completes successfully.
If the server responds with a RST instead the port will be identified as closed, otherwise if there's no response or we receive an ICMP unreachable error then we'll know it's being filtered.
To run a SYN scan, do:

```
# nmap -sS <target>
```

The same services that would be detected by Nmap during a Connect() scan are also found with the SYN scan.
The advantage of the SYN scan over the typical TCP Connect() scan is that we never form a connection with the service attached to the port, which means we're less likely to get logged.
However, we're still likely to be detected by any NIDS software if we blast the target with a rapid flood of SYN requests, so you can apply some the stealth tricks [discussed further down](#useful-options-for-optimising-stealth)


## Idle (Zombie) Scan

The Idle Scan, also known as the Zombie Scan, allows the attacker to perform reconnaissance on a target without ever sending a packet from their IP address.
Instead, a clever side-channel attack allows for the scan to be bounced off a dumb “zombie host”, which will be framed as the attacker.
By exploiting zombie machines that have predictable IP ID generation, we spoof the source address of our scans to be that of the zombie machine, 
and we can probe the current IP ID of the zombie before and after each port scanned to see if it received any response from the target.

**Finding a Suitable Zombie:**

While most modern Linux, Solaris, and OpenBSD machines have patched this vulnerability, printers, Windows boxes, older Linux hosts, FreeBSD, and Mac OS machines generally make for good zombie candidates.
To discover a candidate zombie, there are two methods that come with Nmap.

The first (and easiest) is using the IPIDSEQ script that comes with Nmap Scripting Engine.

```
# nmap --script ipidseq <targets>
```

The second way is by using a verbose OS detection scan and checking the IP ID Generation algorithm detected:

```
# nmap -O -v <targets>
```

For the targets, we can either specify a known network (e.g. `192.168.0.0/16`), or we test random machines on the internet until we encounter one that's suitable (e.g. with `-iR 100`).
We're looking for machines where the IP ID generation sequence is either `Incremental` or Broken `little-endian incremental`.
However, this is no guarantee that it will be a suitable zombie as some machines such as modern Solaris boxes will have per-host IP ID sequences.
The lower the latency between the attacker and zombie as well as between the zombie and target, the faster the scan can be done.

**Running the Zombie Scan:**

Once we have the IP address of a suitable zombie, we can scan all ports on the target like so:

```
# nmap -Pn -p- -sI <zombie-address> <target>
```

Make sure to disable host discovery with `-Pn` so that we don't send any pings directly from the attacker to the target.

You'll notice that unlike with a SYN or Connect() scan, the IDLE scan can't differentiate between a `filtered` port and a `closed` port.
This is because unless the target port is `open`, the target machine won't send a SYN/ACK to the zombie machine,
and therefore the zombie machine won't respond with a RST (which is what increments the zombie's IP ID counter).

```
# nmap -Pn -p- -sI 192.168.56.107 192.168.56.128

Starting Nmap 7.93 ( https://nmap.org ) at 2023-11-22 01:55 GMT
Idle scan using zombie 192.168.56.107 (192.168.56.107:80); Class: Incremental
Nmap scan report for 192.168.56.128
Host is up (0.060s latency).
Not shown: 65513 closed|filtered tcp ports (no-ipid-change)
PORT      STATE SERVICE
21/tcp    open  ftp
22/tcp    open  ssh
23/tcp    open  telnet
25/tcp    open  smtp
111/tcp   open  rpcbind
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
512/tcp   open  exec
513/tcp   open  login
514/tcp   open  shell
1099/tcp  open  rmiregistry
1524/tcp  open  ingreslock
2121/tcp  open  ccproxy-ftp
3306/tcp  open  mysql
3632/tcp  open  distccd
5432/tcp  open  postgresql
6667/tcp  open  irc
6697/tcp  open  ircs-u
8009/tcp  open  ajp13
8180/tcp  open  unknown
8787/tcp  open  msgsrvr
40177/tcp open  unknown
MAC Address: 08:00:27:AD:A8:9A (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 285.21 seconds
```


## UDP Scan

UDP scans typically offer less concrete information than a TCP scan, but allow us to guess if UDP services such as SNMP, DHCP or DNS are potentially running on a given port.
It's very rare to receive a UDP response from a port unless the packet sent is well crafted for the running service,
and since there's no handshakes or acknowledgements like with TCP, we won't be able to tell if a port is open or filtered if we don't receive any response.
To remedy this and distinguish between more open and filtered ports, we can use Nmap's Version Detection ([described in more detail further down](#version-probing)):

```
# nmap -sUV <target>
```

UDP scanning can be even slower than TCP scanning due to ICMP rate limiting and the need for version detection.
To help speed up this process, consider using `--version-intensity 0`.


## ACK Scan

The ACK scan can determine if there is a firewall between ourselves and the target by sending ACK probes to each target port.
If the probe solicits a RST response from the target, we can know that the target is reachable and that our packets aren't getting filtered.
On the other hand, if the never hear back from the target or receive an ICMP unreachable error, we know our packets are being dropped by a firewall.
The ACK scan never determines what ports are open and therefore doesn't directly detect any services, but it does tell us if there are any firewalls present.

For example, here is the output when scanning a machine with a firewall enabled:

```
$ sudo nmap -sA 192.168.56.127

Starting Nmap 7.80 ( https://nmap.org ) at 2023-11-21 23:17 GMT
Nmap scan report for 192.168.56.127
Host is up (0.00066s latency).
Not shown: 981 filtered ports
PORT     STATE      SERVICE
21/tcp   unfiltered ftp
22/tcp   unfiltered ssh
23/tcp   unfiltered telnet
25/tcp   unfiltered smtp
80/tcp   unfiltered http
111/tcp  unfiltered rpcbind
139/tcp  unfiltered netbios-ssn
161/tcp  unfiltered snmp
445/tcp  unfiltered microsoft-ds
512/tcp  unfiltered exec
513/tcp  unfiltered login
514/tcp  unfiltered shell
631/tcp  unfiltered ipp
1099/tcp unfiltered rmiregistry
1524/tcp unfiltered ingreslock
2121/tcp unfiltered ccproxy-ftp
3306/tcp unfiltered mysql
5432/tcp unfiltered postgresql
6667/tcp unfiltered irc
MAC Address: 08:00:27:6B:43:18 (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 3.00 seconds
```

When there is no firewall on the target machine, the output is much shorter:

```
# nmap -sA 192.168.56.127

Starting Nmap 7.80 ( https://nmap.org ) at 2023-11-21 23:13 GMT
Nmap scan report for 192.168.56.127
Host is up (0.00022s latency).
All 1000 scanned ports on 192.168.56.127 are unfiltered
MAC Address: 08:00:27:6B:43:18 (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 0.23 seconds
```


## Null Scan

The Null scan exploits a loophole in the TCP RFC to differentiate between open or filtered ports, and closed ports.
The RFC states that if the destination port is closed, then any incoming packet without the RST bit set should be replied to with a RST packet.
However, if there is no response at all then the port is either open or filtered, and if we recieve an ICMP unreachable error then the port is definitely filtered.

With no firewall on the target machine, we can see the 984 ports that are closed, as well as the 16 that are open:

```
# nmap -sN -T5 192.168.56.128

Starting Nmap 7.93 ( https://nmap.org ) at 2023-11-22 02:38 GMT
Nmap scan report for 192.168.56.128
Host is up (0.0010s latency).
Not shown: 982 closed tcp ports (reset)
PORT     STATE         SERVICE
21/tcp   open|filtered ftp
22/tcp   open|filtered ssh
23/tcp   open|filtered telnet
25/tcp   open|filtered smtp
111/tcp  open|filtered rpcbind
139/tcp  open|filtered netbios-ssn
445/tcp  open|filtered microsoft-ds
512/tcp  open|filtered exec
513/tcp  open|filtered login
514/tcp  open|filtered shell
1099/tcp open|filtered rmiregistry
1524/tcp open|filtered ingreslock
2121/tcp open|filtered ccproxy-ftp
3306/tcp open|filtered mysql
5432/tcp open|filtered postgresql
6667/tcp open|filtered irc
8009/tcp open|filtered ajp13
8180/tcp open|filtered unknown
MAC Address: 08:00:27:AD:A8:9A (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 1.74 seconds

```

However, when the target is running a firewall with "deny by default" ruleset, we can see that all ports are classified as open or filtered:

```
# nmap -sN 192.168.56.127

Starting Nmap 7.80 ( https://nmap.org ) at 2023-11-21 23:35 GMT
Nmap scan report for 192.168.56.127
Host is up (0.00049s latency).
All 1000 scanned ports on 192.168.56.127 are open|filtered
MAC Address: 08:00:27:6B:43:18 (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 11.29 seconds
```

The Null scan becomes even more useful when used in conjunction with the ACK scan.
If the Null scan tells us that a given port is `open|filtered`, and the ACK scan tells us that the port is `unfiltered` (i.e. either `open` or `closed`),
we can deduce that the given port is in fact `open`.


## Nmap Scripting Engine (NSE)

Nmap's functionality can be extended through the Nmap Scripting Engine, which allows for more advanced network discovery, version detection and vulnerability detection.
Included with Nmap is 604 scripts, which are split up into many (not mutually exclusive) categories such as `intrusive`, `safe`, `exploit`, `discovery`, etc.
To use the NSE, add the `--script` flag like so:

```
# nmap --script <filename>|<category>|<directory>/ <target>
```

You can run entire categories of scripts or single individual scripts.
You can also combine multiple categories in one scan, like so:

- `--script "not intrusive"` - Will run every script except for those labelled as `intrusive`
- `--script "default and discovery"` - Will run every script that is both in the `default` category and the `discovery` category
- `--script "default or discovery"` - Will run every script from both categories

For a full list and description of each available category, check [the NSE documentation](https://nmap.org/book/nse-usage.html#nse-category-default).
Some of the best scripts for reconnaissance are in the `discovery` and `vuln` categories, so the following scan can be quite fruitful:

`# nmap -sSV -sUV --script "default,discovery,vuln" <target>`


### A Note On NSE Stealth

**IMPORTANT - Note that some of these scripts are not very stealthy.**
While some scripts are purely for pre-processing or post-processing of scans, many will also send new traffic directly to the host or running services.
Not much can be done to reduce the speed at which scripts run, most [stealth optimisations](#useful-options-for-optimising-stealth) have no effect,
and timing options do not have an impact on scripts as [this feature was never added](https://github.com/nmap/nmap/issues/547).
Furthermore, some HTTP requests may be sent where the user agent will disclose that Nmap is being used or that the host OS is Kali (where applicable),
which may raise suspicion on any running NIDS. However, some of these scripts, such as `vulners`, use the data acquired from the initial port scan, which is still affected by the aforementioned stealth options.


### Default Scripts

A subset of the NSE scripts are included in the `default` category if they are fast, reliable, concise, and not very instrusive or privacy invasive.
This includes a variety of HTTP, NTLM and SNMP enumeration scripts, FTP security checks, and more.
For the full list see [the NSE default category docs](https://nmap.org/nsedoc/categories/default.html).


### Discovery Scripts

The scripts in the `discovery` category try to actively discover more about the network by querying public registries, SNMP-enabled devices, directory services, and the like.
Some notable scripts in this category include:

- `firewalk` - Tries to discover firewall rules using an IP TTL expiration technique known as firewalking. 
- `smb-enum-shares` - Attempts to list SMB shares and retrieve more information about them 
- `smb-os-discovery` - Attempts to determine the operating system, computer name, domain, workgroup, and current time over the SMB protocol. Also in the default category
- `dns-brute` - Attempts to enumerate DNS hostnames by brute force guessing of common subdomains.
- `dns-zone-transfer` - Requests a zone transfer (AXFR) from a DNS server.
- `http-waf-fingerprint` - Tries to detect the presence of a web application firewall and its type and version.
- `traceroute-geolocation` - Lists the geographic locations of each hop in a traceroute
- `http-wordpress-enum` - Enumerates themes and plugins of WordPress installations, with support for around 32,000 themes and 14,000 plugins.
- `ipidseq` - Classifies a host's IP ID sequence (test for susceptibility to idle scan).


### Vuln Scripts

The scripts in the `vuln` category check for specific known vulnerabilities and generally only report results if they are found.

The most notable script in the `vuln` category is `vulners`, which for every service with a version detection will provide links to available CVEs that can be used to exploit the service.
For example, running against the Metasploitable 2 target shows the following CVEs for the SSH server

```
$ sudo nmap -sSV --script vulners 192.168.56.127

Starting Nmap 7.80 ( https://nmap.org ) at 2023-11-20 20:31 GMT
Nmap scan report for 192.168.56.127
Host is up (0.00079s latency).
Not shown: 981 filtered ports
PORT     STATE  SERVICE     VERSION
21/tcp   open   ftp         vsftpd 2.3.4
22/tcp   open   ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| vulners: 
|   cpe:/a:openbsd:openssh:4.7p1: 
|     	SECURITYVULNS:VULN:8166	7.5	https://vulners.com/securityvulns/SECURITYVULNS:VULN:8166
|     	CVE-2008-1657	6.5	https://vulners.com/cve/CVE-2008-1657
|     	SSV:60656	5.0	https://vulners.com/seebug/SSV:60656	*EXPLOIT*
|     	CVE-2010-5107	5.0	https://vulners.com/cve/CVE-2010-5107
|     	CVE-2011-5000	3.5	https://vulners.com/cve/CVE-2011-5000
|     	CVE-2008-5161	2.6	https://vulners.com/cve/CVE-2008-5161
|     	CVE-2011-4327	2.1	https://vulners.com/cve/CVE-2011-4327
|     	CVE-2008-3259	1.2	https://vulners.com/cve/CVE-2008-3259
|_    	SECURITYVULNS:VULN:9455	0.0	https://vulners.com/securityvulns/SECURITYVULNS:VULN:9455
[... rest of output omitted for brevity ...]
```

Vulners draws security intelligence from over 200 different sources, granting it one of the most comprehensive sets of vulnerabilities and exploits.
This also includes Tenable Nessus and OpenVAS.

For the full list see [the NSE discovery category docs](https://nmap.org/nsedoc/categories/vuln.html)


### Vulscan

As well as the scripts that come included with nmap in `/usr/share/nmap/scripts/`, you can also use Nmap to run scripts of your own.
One such script is [Vulscan](https://github.com/scipag/vulscan), which is an alternative to the `vulners` script that comes with Nmap.

To install Vulscan, clone their git repository and symlink the new script into your existing Nmap scripts folder (the link step is **not** optional):

```bash
git clone https://github.com/scipag/vulscan scipag_vulscan
ln -s `pwd`/scipag_vulscan /usr/share/nmap/scripts/vulscan
```

You can then run the `vulscan` script like any other script:

```
nmap -sV --script=vulscan/vulscan.nse <target>
```

`vulscan` will look up the CPE for a detected service in multiple databases as well, including:

- [scipvuldb.csv](https://vuldb.com)
- [cve.csv](https://cve.mitre.org)
- [securityfocus.csv](https://www.securityfocus.com/bid/)
- [xforce.csv](https://exchange.xforce.ibmcloud.com/)
- [expliotdb.csv](https://www.exploit-db.com)
- [openvas.csv](http://www.openvas.org)
- [securitytracker.csv](https://www.securitytracker.com) (end-of-life)
- [osvdb.csv](http://www.osvdb.org) (end-of-life)


## Optimisations

### Useful Options for Optimising Stealth

#### Timings

The default timing for `nmap` is T3, but if we want to avoid detection by any running NIDS we should explicitly choose `-T1` or `-T0`.
The disadvantage is that this takes much longer to run than a normal or aggressive scan:

![timing_policies.gif](https://kb.parallels.com/Attachments/kcs-38903/timing_policies.gif)

For example, the Emerging Threats ruleset (which is often used with NIDS such as Snort and Suricata),
will raise an alert for possibly malicious probing of a MySQL port if it sees more that 4 probes within 60 seconds.
Using `-T1` or manually setting `--scan_delay` to 15 seconds can avoid this (and similar) detections.


#### Fragmentation

By using the `-f` option, Nmap will split TCP headers over several packets to make it harder for NIDS/NIPS and firewalls/filters to detect scans.
For example, Windows Defender's builtin firewall will block a normal Nmap scan, but can easily be circumvented with fragmentation.

The only disadvantage other than potentially breaking very old applications is that scans can take several times longer.
Many modern NIDS solutions also have preprocessors to defragment traffic before analysis.

Fragmentation is supported for Nmap's raw packet features, which includes the following scans:

- SYN scans
- UDP scans
- OS Detection scans

However, it isn't supported on the following scans:

- TCP Connect() scans
- FTP bounce scans
- Any scans that use version probing/detection
- Scans included in the Nmap Scripting Engine


#### Decoys

You can obfuscate your IP address by sending a flurry of port scans with spoofed source IP addresses at the same time as your legitimate scan, using the `-D` flag. 
This makes it so that it appears as though many targets are simultaneously scanning the target, only 1 of which is the true attacker's IP address.

For example, `nmap -D RND:9 <target>` will add 9 extra decoys with random IP addresses, or you can add specific machines using `nmap -D <decoy-1>,<decoy-2>,<etc.> <target>`.

This can be effective against basic IDS systems, and can make logs harder to manually inspect, however there are at least three ways the target can deobfuscate the attacker:

1. If the attacker uses decoy IP addresses that are not up, the target will respond with a SYN/ACK to the attacker's ACK on any open ports, but will not receive further communications.
The real attacker will be the only machine to respond to the SYN/ACK with a RST, giving away their true IP address.


2. The target machine, seeing they're being scanned from multiple IP addresses, can try blocking them one at a time.
When the real attacker IP gets blocked, it'll result in retransmissions and slowdowns as nmap stops receiving communications from the target.


3. If the target machine is logging the TTL on received packets, they can try running a traceroute to each of the source IP addresses so see roughly how many hops it takes.
If the change in TTL on incoming packets doesn't line up with a genuine connection that would typically start with a TTL of 64, we can identify which connections are likely decoys.
Furthermore, if only one of the connections has a realistic TTL, it may suggest that connection belongs to the true attacker.
Note that this technique isn't particularly accurate as routes can change often, and the attacker can set any starting TTL they'd like, such as `-ttl 255`

Decoys are also used during the host discovery phase, so you don't need to use `-Pn` like you would with an IDLE scan.
Decoys also work with the OS detection scan, however, they don't work with version detection or with the TCP Connect() scan 

#### Avoiding XMAS and FIN Scans

Nmap provides alternatives to the Null scan such as the FIN scan and the XMAS scan.
The issue with the XMAS scan is that the same way it sets the FIN, PSH, and URG flags, lighting the packet up like a Christmas tree.
These packets are very irregular compared to benign traffic, so they're very easy to detect and they light up the NIDS like a Christmas tree too:

```
11/22-02:43:17.785606  [**] [1:1228:7] SCAN nmap XMAS [**] [Classification: Attempted Information Leak] [Priority: 2] {TCP} 192.168.56.103:53093 -> 192.168.56.128:5802
```

The FIN scan is not as noisy, but they're also easily detected by the `sfportscan` module of the Snort NIDS:

```
11/22-02:38:22.795064  [**] [1:621:7] SCAN FIN [**] [Classification: Attempted Information Leak] [Priority: 2] {TCP} 192.168.56.103:61420 -> 192.168.56.128:8009
```

The best solution for maintaining a stealthy footprint during your firewall reconnaissance is to stick to the Null scan.


### Useful Options for Getting More Information

#### OS Detection

Lot's of precious information can be gleamed from the TCP/IP stack of a host, which can give   away the identity of the Operating System underneath.
Nmap includes a scan called the OS Detection Scan which can be enabled with `-O` that'll send a variety of TCP and UDP probes to a given target:

```
# nmap -O <target>
```

The [variety of probes](https://nmap.org/book/osdetect.html) used to test the target system include, but aren't limited to:

- FIN probes
- TCP ISN sampling
- IP ID sampling
- TCP timestamp
- Don't Fragment bits
- And more...

An example output may look like this:

```
$ sudo nmap -O 192.168.56.127

Starting Nmap 7.80 ( https://nmap.org ) at 2023-11-21 23:06 GMT
Nmap scan report for 192.168.56.127
Host is up (0.00074s latency).
Not shown: 984 closed ports
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
[... rest of services omitted for brevity ...]

MAC Address: 08:00:27:6B:43:18 (Oracle VirtualBox virtual NIC)
Aggressive OS guesses: Linux 2.6.32 (96%), Linux 3.2 - 4.9 (96%), Linux 2.6.32 - 3.10 (95%), Linux 3.4 - 3.10 (94%), Linux 3.1 (93%), Linux 3.2 (93%), Synology DiskStation Manager 5.2-5644 (93%), Netgear RAIDiator 4.2.28 (92%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (92%), Linux 2.6.32 - 2.6.35 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 3.81 seconds
```


#### Version Probing

While it's interesting to know what ports are open for TCP and UDP, it can be extremely valuable to discover the specific software that is bound to that port.
The `nmap-service-probes` database contains probes for querying various services and match expressions to recognize and parse responses.
This is particularly useful for UDP scans as many UDP services won't respond to empty or invalid packets (as there's no handshakes or acknowledgements).

To carry out a UDP and SYN scan with version detection:

```
# nmap -sUV -sSV --allports <target>
```

By default, only the first 9100 ports are scanned when we don't pass the `--allports` or `-p-` option.

Version scans can take substantially longer than a typical port scan, as we're now potentially probing each port many times.
To reduce the time consumption of the scans, consider using a lower version intensity or by changing the number of ports scanned as described below.

There is also a stealth disadvantage to using scans that use 

```
11/03-19:04:18.647414  [**] [1:2010937:3] ET SCAN Suspicious inbound to mySQL port 3306 [**] [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 192.168.56.1:58987 -> 192.168.56.128:3306
```


### Useful Options for Optimising Time Consumption

Some scans, such as `nmap -f -T1 -sUV <target>`, can take many hours if not days to finish executing, so there are some tricks to speed up our scans while maintaining stealth:


#### Scanning only common ports

Included with Nmap is a list of commonly used ports sorted in order of how often they are typically found open in the wild.
By passing the option `--top-ports <number>`, we can instruct Nmap to only scan the `<number>` most likely to be open ports.
For example, `nmap -f -T1 -sUV --top-ports 10000 <target>'` may finish executing 6x faster than every port was scanned.

The risk of this approach is that ports that are usually less likely to be open will be missed completely, but given a time constraint this option is very useful.


#### Scanning only known-open ports

Instead of running a time-consuming scan such as version detection against a bunch of ports that may or may not have any services running,
an alternative strategy would be to first run a basic SYN or FIN scan first to find our which ports are potentially open,
and only run the more time-consuming scan on those ports:

`nmap -sSV -p <port1>,<port2>,<etc.>`


#### Version Intensity

Depending on how often the version probes usually hit, they are assigned a rarity (or intensity) from 0 to 9.
The higher number probes are the least likely to hit but are more likely to correctly identify the service.
By default, only probes of up to rarity 7 are used, but this can be adjusted with `--version-intensity <rarity>`.


# Application Reconnaissance

## Automated Web Application Scanners

Web vulnerability scanners exist to aid penetration testers in finding common vulnerabilities in web applications quickly.
They can often detect many of the OWASP Top 10 vulnerabilities such as SQL injections, Cross-Site Scripting (XSS), and more.

However it is important to keep in mind that there are some vulnerabilities that these automated tools won't be able to identify effectively.
This includes application logics flaws, authentication vulnerabilities like enumerable usernames, session management flaws like session hijacking, etc.


The tools in this chapter are tested against several websites deployed using [PentestLab](https://github.com/eystsen/pentestlab).


### WhatWeb

A good starting point for performing reconnaissance on a web application is using [WhatWeb](https://www.kali.org/tools/whatweb/).
WhatWeb identifies websites and their underlying technologies such as Javascript libraries, analytics packages, content management systems (CMS), etc.
WhatWeb comes included with Kali Linux, but can be [built from source](https://github.com/urbanadventurer/WhatWeb/wiki/Installation) on any other Linux distribution.

WhatWeb has multiple "aggression" levels with its scans, where less aggressive scans are stealthier but less fruitful.
There are 4 levels of aggression available:

- 1 - Stealthy - Makes one HTTP request per target. Also follows redirects.
- 2 - Unused
- 3 - Aggressive - Can make a handful of HTTP requests per target.
This triggers aggressive plugins for targets only when those plugins are identified with a level 1 request first.
- 4 - Heavy - Makes a lot of HTTP requests per target.
Aggressive tests from all plugins are used for all URLs.

For example, a scan performed with the default aggression level of 1 ascertains the following information about [WPScan Vulnerable Wordpress](https://github.com/wpscanteam/VulnerableWordpress)
```
$ whatweb http://127.12.0.1

http://127.12.0.1 [200 OK] Apache[2.4.7],
Country[RESERVED][ZZ],
HTML5,
HTTPServer[Ubuntu Linux][Apache/2.4.7 (Ubuntu)],
IP[127.12.0.1],
JQuery[1.11.2],
MetaGenerator[WordPress 4.2.1],
PHP[5.5.9-1ubuntu4.29],
PoweredBy[WordPress,WordPress,],
Script[text/javascript],
Title[Vulnerable WordPress | Just another WordPress site],
UncommonHeaders[secretheader],
Via-Proxy[Squid 1.0.0],
WordPress[4.2.1],
X-Powered-By[PHP/5.5.9-1ubuntu4.29],
x-pingback[http://vulnerablewordpress/xmlrpc.php]
```

With just 1 request, we've identified the versions of Wordpress, JQuery, PHP and Apache in use by the web application.
We can use this information to check if there are any existing n-day vulnerabilities for the detected technologies, which could be exploited for initial access.

For this particular site, the output of running WhatWeb at aggression level 1 and 3 were the same.
The only extra information from running it at aggression level 4 was that we found out the `Matomo` analytics platform was being used as well.


### Retire.js

[Retire.js](https://github.com/RetireJS/retire.js) is a tool to identify JavaScript libraries with known vulnerabilities in web applications.
This can allow us to detect outdated versions of libraries such as React and jQuery which we could exploit for initial access.
Retire.js includes an actively maintained list of over 800 vulnerabilities that it can detect, which you can see for yourself [here](https://retirejs.github.io/retire.js/).

It can be installed using NPM (tested and working with NodeJS v21.5.0 and NPM 10.2.4), but it is also available as a Chrome and Firefox (deprecated) extension, as well as Burp and ZAP plugins:
For the best experience while pen-testing, the Chrome extension is our recommendation.

For example, when we navigate to the [Mutillidae II](https://github.com/webpwnized/mutillidae) website deployed through [PentestLab](https://github.com/eystsen/pentestlab),
we can see that 7 different CVEs are shown relating to the outdated version of jquery in use on the app:

![img.png](assets/RetireJS.png)

You should note that the extension only displays the javascript libraries that are currently active, and won't spider to other pages that may have other Javascript files.


### is-website-vulnerable

Similar to Retire.js, [is-website-vulnerable](https://github.com/lirantal/is-website-vulnerable) is another tool for finding publicly known security vulnerabilities in a website's frontend JavaScript libraries.
It has a better CLI than Retire.js, which can be deployed using Docker or installed with NPM (tested and working with NodeJS v21.5.0 and NPM 10.2.4):

```
npm install -g is-website-vulnerable
```

Rather than using its own vulnerability database, `is-website-vulnerable` will query the databases maintained by [snyk.io](https://security.snyk.io/vuln).
As you can see, the output is much shorter, and just includes the number of vulnerabilities per detected library, and a link for further details:

```
$ is-website-vulnerable http://192.168.56.106/mutillidae/

✔ Set up completed in 0.55 seconds!
✔ Auditing completed in 2.03 seconds!

  Website: http://192.168.56.106/mutillidae/
  
    ⎡ ✖ jQuery@1.3.2
    ⎜ ■■■  5  vulnerabilities
    ⎣ ▶ https://snyk.io/vuln/npm:jquery?lh=1.3.2
  
  [5] Total vulnerabilities
  [1894.03ms] execution time
```

Just like Retire.js, this will only analyse the Javascript files on the specific page that you specified, and won't automatically crawl to discover others.
Consider using this in conjunction with one of the spiders / crawlers discussed in [Path Enumeration](#path-enumeration) to increase the output.


### Wapiti

[Wapiti](https://github.com/wapiti-scanner/wapiti) is a web vulnerability scanner written in Python.
It has a CLI interface but is packed with features and supports a variety of attacks and detections such as:

- SQL Injections (Error based, boolean based, time based) and XPath Injections
- Reflected and Permanent Cross Site Scripting (XSS)
- File disclosure detection (local and remote include, require, fopen, readfile...)
- Command Execution detection (eval(), system(), passtru()...)
- XXE (Xml eXternal Entity) injection
- CRLF Injection
- Folder and file enumeration (DirBuster like)
- Server Side Request Forgery (through use of an external Wapiti website)
- Checking cookie security flags (secure and httponly flags) and basic Cross Site Request Forgery (CSRF) detection
- Log4Shell, Spring4Shell and ShellShock detection
- And more...

**Installation:**

To install the latest version of Wapiti, simply clone the git repository and then install with `pip`:

```bash
$ git clone https://github.com/wapiti-scanner/wapiti
$ sudo pip3 install .
```

**Usage:**

By default, not every check is carried out on the target host.
Each of the detections is supported by a particular module, and only the "common" modules are executed by default, which include:

- blindsql - Detect SQL injection vulnerabilities using blind time-based technique.
- cookieflags - Evaluate the security of cookies on the website.
- csp - Evaluate the security level of Content Security Policies of the web server.
- exec - Detect scripts vulnerable to command and/or code execution.
- file - Detect file-related vulnerabilities such as directory traversal and include() vulnerabilities.
- http_headers - Evaluate the security of HTTP headers.
- permanentxss - Detect stored (aka permanent) Cross-Site Scripting vulnerabilities on the web server.
- redirect - Detect Open Redirect vulnerabilities.
- sql - Detect SQL (but also LDAP and XPath) injection vulnerabilities by triggering errors (error-based technique).
- ssrf - Detect Server-Side Request Forgery vulnerabilities.
- xss - Detects stored (aka permanent) Cross-Site Scripting vulnerabilities on the web server.

There are some more modules that are of use to us which we can optionally enable as well:

- backup - Uncover backup files on the web server.
- brute_login_form - Attempt to login on authentication forms using known weak credentials (like admin/admin).
- buster - Brute force paths on the web-server to discover hidden files and directories.
- crlf - Detect Carriage Return Line Feed (CRLF) injection vulnerabilities.
- csrf - Detect forms missing Cross-Site Request Forgery protections (CSRF tokens).
- htaccess - Attempt to bypass access controls to a resource by using a custom HTTP method.
- methods - Detect uncommon HTTP methods (like PUT) that may be allowed by a script.
- nikto - Perform a brute-force attack to uncover known and potentially dangerous scripts on the web server.
- shellshock - Detects scripts vulnerable to the infamous ShellShock vulnerability.
- wapp - Identify web technologies used by the web server using Wappalyzer database.
- xxe - Detect scripts vulnerable to XML external entity injection (also known as XXE).

To enter your cookies, you can add the HTTP header yourself or use a JSON formatted cookie file:

```
$ wapiti --url http://127.14.0.1/ --module common,crlf,csrf,htaccess,methods,nikto,shellshock,wapp,xxe --depth 7 --color --header \
"Cookie: JSESSIONID=38B837D07BF4FAF2D4446D81BAEE4DC2; AltoroAccounts=ODAwMDAyflNhdmluZ3N+MTAwMDAuNDJ8ODAwMDAzfkNoZWNraW5nfjE1MDAwLjM5fDQ1MzkwODIwMzkzOTYyODh+Q3JlZGl0IENhcmR+MTAwLjQyfA=="
```

Using this to scan [Altoro Mutual](https://altoromutual.com/feedback.jsp), it successfully detects multiple isues, including:

```
Lack of anti CSRF token                                                                                                                                                                                                                     
    POST /doLogin HTTP/1.1                                                                                                                                                                                                                  
    Host: 127.14.0.1                                                                                                                                                                                                                        
    Referer: http://127.14.0.1/login.jsp                                                                                                                                                                                                    
    Content-Type: application/x-www-form-urlencoded                                                                                                                                                                                         
                                                                                                                                                                                                                                            
    uid=&passw=Letm3in_&btnSubmit=Login                                                                                                                                                                                                     
```

```
Received a HTTP 500 error in http://127.14.0.1/index.jsp                                                                                                                                                                                    
Evil request:                                                                                                                                                                                                                               
    GET /index.jsp?content=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fusr%2Fbin%2Fenv%7C HTTP/1.1                                                                                                           
    Host: 127.14.0.1
```

```
XSS vulnerability in http://127.14.0.1/index.jsp via injection in the parameter content                                                                                                                                                     
Evil request:                                                                                                                                                                                                                               
    GET /index.jsp?content=%3CSvG%0AoNloAd%3Dalert%28%27wtevtoj9uj%27%29%3E HTTP/1.1                                                                                                                                                        
    Host: 127.14.0.1
```


## Path Enumeration

When pentesting a web application, it can be very useful to discover the different pages and forms available on the site.
It's important to start by manually browsing the site to ascertain the kind of application it is.
However, it can be quite time-consuming and tedious to manually discover every available page or path that the site provides.

To aid this process, a variety of path enumeration, web crawling and spidering tools exist to aid penetration testers.
Web crawlers, sometimes called spiders, work by visiting a list of initial URLs, discovering new hyperlinks, and recursively crawling those newly discovered pages.
These allow us to quickly discover pages that have existing references, but sometimes we're looking for hidden pages.
For this, we can enumerate a list of common paths using a tool such as Dirbuster.

To test the techniques in this chapter, I deployed vulnerable-by-design web apps such as [OWASP Mutillidae II](https://owasp.org/www-project-mutillidae-ii/) and [Altoro Mutual](https://altoromutual.com/feedback.jsp).


### Katana

[Katana](https://github.com/projectdiscovery/katana) is a popular web crawling and spidering framework with features such as automatic form filling.
It can be deployed using Docker, or can be installed locally using Go:

```bash
$ go install github.com/projectdiscovery/katana/cmd/katana@latest
```


**Usage:**

Katana is highly customisable and packed with useful features, but a few of the most important options include:

- `-d, -depth <int>` - Maximum depth to crawl (default 3)
- `-jsl, -jsluice` - Enable jsluice parsing in javascript file (memory intensive)
- `-kf, -known-files <string>` - Enable crawling of known files (all,robotstxt,sitemapxml)
- `-aff, -automatic-form-fill` - Enable automatic form filling
- `-H, -headers <string[]>` - Custom header/cookie to include in all http requests (useful for PHPSESSIONID cookies, spoofed user-agents, etc.)
- `-iqp, -ignore-query-params` - Ignore crawling same path with different query-param values
- `-rlm, -rate-limit-minute <int>` -  Maximum number of requests to send per minute
- `-proxy string` - HTTP/SOCKS5 proxy to use (Useful for forwarding through Tor using localhost:9050)

By default the crawler won't crawl out to URLs on different hosts, restricting the scope to the initial hosts.
Here is an example using [Altoro Mutual](https://altoromutual.com/) deployed locally (to 127.14.0.1):

```
$ ./katana -u http://127.14.0.1/ -depth 3 -jsluice -automatic-form-fill -known-files all

   __        __                
  / /_____ _/ /____ ____  ___ _
 /  '_/ _  / __/ _  / _ \/ _  /
/_/\_\\_,_/\__/\_,_/_//_/\_,_/                                                   

                projectdiscovery.io

[INF] Current katana version v1.0.4 (latest)
[INF] Started standard crawling for => http://127.14.0.1/
http://127.14.0.1/
http://127.14.0.1/style.css
http://127.14.0.1/swagger/index.html
http://127.14.0.1/index.jsp?content=privacy.htm
http://127.14.0.1/default.jsp?content=security.htm

[... omitted for brevity ...]

http://127.14.0.1/sameDomain
http://127.14.0.1/sendFeedback
http://127.14.0.1/high
http://127.14.0.1/disclaimer.htm?url=http://www.netscape.com
```


### GoSpider

A great alternative to Katana is [GoSpider](https://github.com/jaeles-project/gospider), a simpler crawling tool also written in Go.
It has very good features for clearnet sites such as discovering URLs using the Wayback Machine and Common Crawl, and finding AWS-S3 buckets from responses.

GoSpider can be deployed with docker using the Dockerfile in the repository, but is easier installed using Go:

```bash
$ GO111MODULE=on go install github.com/jaeles-project/gospider@latest
```


**Usage:**

Some of GoSpider's most useful options include:

- `-u, --user-agent <string>` - User Agent to use
- `--cookie <string>` - Cookie(s) to use
- `-d, --depth <int>` - Limit the recursion depth of visited URLs (Default is 1, set to 0 for infinite recursion)
- `-k, --delay <int>` - Duration to wait before sending another request to the same host (in seconds)
- `-K, --random-delay <int>` - Extra randomised delay between creating new requests (in seconds)
- `--js` - Enable linkfinder in javascript file (default true)
- `-a, --other-source` - Find URLs from 3rd party sources (Archive.org, CommonCrawl.org, VirusTotal.com, AlienVault.com)
- `-p, --proxy <string>` - Proxy (Ex: http://127.0.0.1:9050)

Here's an example of it being run on a locally deployed [Altoro Mutual](https://altoromutual.com/) application:

```
$ ./gospider -s http://127.14.0.1/ --depth 3 --js --delay 15
                                  
[url] - [code-200] - http://127.14.0.1/
[href] - http://127.14.0.1/style.css
[href] - http://127.14.0.1/index.jsp
[href] - http://127.14.0.1/login.jsp
[href] - http://127.14.0.1/index.jsp?content=inside_contact.htm
[form] - http://127.14.0.1/
[url] - [code-200] - http://127.14.0.1/index.jsp?content=personal.htm
[url] - [code-200] - http://127.14.0.1/index.jsp?content=business.htm
[url] - [code-200] - http://127.14.0.1/index.jsp?content=inside_about.htm

[... omitted for brevity ...]

[linkfinder] - [from: http://127.14.0.1/swagger/swagger-ui-bundle.js] - ./view/root-injects.js
[linkfinder] - http://127.14.0.1/swagger/view/root-injects.js
[linkfinder] - http://127.14.0.1/view/root-injects.js
[url] - [code-200] - https://petstore.swagger.io/v2/swagger.json
```


### DirBuster

DirBuster is a very popular multi-threaded java application designed to brute force directories and files names on web/application servers.
This is in contrast to crawlers that discover new paths by searching for hyperlinks and other references.
Despite this, it also has basic functionality for enumerating any hyperlinks it discovers recursively, but DirBuster's functionality as a crawler pales in comparison to Katana or GoSpider.

DirBuster comes included with Kali Linux, and one of it's great features is the wordlists that are bundled.
The included wordlists are generated from real-world data, and so represent typically available endpoints.


**Usage:**

DirBuster can be used from the command line in a headless mode, but also comes with a basic GUI/
To start a scan, choose one of the included wordlists (typically in /usr/share/wordlists/dirbuster/), or use a custom wordlist.
`directory-list-2.3-medium.txt` (220546 words) and `directory-list-2.3-small.txt` (87650 words) both have good results.
For more options, you can press the `List info` button:

![img.png](assets/Path%20Enumeration%201.png)

You can also add extra file extensions such as `htm`, `txt`, etc., and add the blank extension as well.
By browsing the site manually or using one of the aforementioned crawlers, you can find out what file extensions are typically found on the target site and use those.

Once configured, you can start the brute-force and view the results as it is still going.
Even with one thread the request speed is quite high, so you can expect this brute-force attack to produce some unusual network traffic.
This may be detected by a NIDS or application firewall, which would quickly get you detected and/or blacklisted.

![img.png](assets/Path%20Enumeration%202.png)

DirBuster was successful in finding over 26,000 unique pages and directories, whereas Katana found only 150 and GoSpider around 600 for the same web application.
This shows that despite it's rudimentary brute-force approach, DirBuster can achieve better results when the initial URL seed is minimal.

However, there is 2 very large issues with DirBuster:
1. The default user agent used in HTTP requests sent by Dirbuster contains the word `dirbuster`, and there is no way to change the user agent through the utility itself.
This makes it very easy to detect with a WAF or NIDS, no matter the thread count used.
2. While you can increase the number of threads used to achieve extremely fast request rates, there's no way to add delays or limit the request rate.
The minimum request rate with 1 thread is still much higher than a typical user would browse the site, so it may raise some alerts.

To remedy this, consider using a modern alternative such as GoBuster:


### GoBuster

[GoBuster](https://github.com/OJ/gobuster) is a brute-force tool similar to DirBuster, but as well as brute forcing and fuzzing URL paths just like DirBuster it also supports DNS subdomain and vhost brute-forcing.

GoBuster can be deployed using Docker, but is easiest used by installing using Go:

```bash
$ go install github.com/OJ/gobuster/v3@latest
```


**Usage:**

To use in place of DirBuster, run it directory brute-frocing mode by calling `gobuster dir [options]`
GoBuster has several useful features that DirBuster is lacking, including:

- `-c, --cookies <string>` - Cookies to use for the requests (useful for `PHPSESSIONID`, etc.)
- `-x, --extensions <string>` - File extension(s) to search for (such as `.php`, `.txt`, etc.)
- `--random-agent` - Use a random real-world user agent (default user agent is "gobuster/3.6.0")
- `--delay <duration>` - Time each thread waits between requests (e.g. 1500ms)
- `--proxy <string>` - Proxy to use for requests ([http(s)://host:port] or [socks5://host:port])


A full example of how one might use gobuster looks like this:

```
./gobuster dir -u http://127.14.0.1/ --discover-backup --extensions .txt,.php,.htm,.html --follow-redirect --random-agent \
--threads 2  --delay 5000ms --wordlist /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt --output gobuster-altoro.log \
 --cookies "JSESSIONID=A4D581C1E715CC3DFDE4FA261FD7F7ED; AltoroAccounts=ODAwMDAyflNhdmluZ3N+MTAwMDAuNDJ8ODAwMDAzfkNoZWNraW5nfjE1MDAwLjM5fDQ1MzkwODIwMzkzOTYyODh+Q3JlZGl0IENhcmR+MTAwLjQyfA==" 

===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://127.14.0.1/
[+] Method:                  GET
[+] Threads:                 2
[+] Delay:                   5s
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] Cookies:                 JSESSIONID=A4D581C1E715CC3DFDE4FA261FD7F7ED; AltoroAccounts=ODAwMDAyflNhdmluZ3N+MTAwMDAuNDJ8ODAwMDAzfkNoZWNraW5nfjE1MDAwLjM5fDQ1MzkwODIwMzkzOTYyODh+Q3JlZGl0IENhcmR+MTAwLjQyfA==
[+] User Agent:              Mozilla/4.0 (compatible; MSIE 6.0; Windows 98) Opera 7.23  [en]
[+] Extensions:              txt,php,htm,html
[+] Follow Redirect:         true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/docs                 (Status: 200) [Size: 17145]
/disclaimer.htm       (Status: 200) [Size: 2010]
/admin                (Status: 200) [Size: 8325]
/examples             (Status: 200) [Size: 1126]
/bank                 (Status: 200) [Size: 8325]
/retirement.htm       (Status: 200) [Size: 1081]
/manager              (Status: 403) [Size: 3446]

[... omitted for brevity ...]
```

This was successful in finding around ~260 unique paths, and including our authentication cookies allows us to discover pages that would only be visible if logged in.


### Arjun

[Arjun](https://github.com/s0md3v/Arjun) is a Python tool that can find query parameters for URL endpoints.
It includes a huge list of 25,980 common parameter names, which it can work through in as little as 50 requests.
This wordlist was created by merging the best words from Seclists and [PortSwigger's param-miner](https://github.com/PortSwigger/param-miner)
with the top parameter names from the [CommonCrawl](http://commoncrawl.org/) dataset.

Arjun is available from PyPI, and can be installed with:

```
$ pip3 install arjun
```


**Usage:**

Arjun has a few useful options, including:

- `-d <delay>` - Add a delay between requests (in seconds)
- `--passive <source>` - Collect parameter names from passive sources like wayback, commoncrawl and otx. (Great for clearnet sites)

For example, we can run it on our self-hosted Altoro instance like so:

```
$ arjun -u http://127.14.0.1/index.jsp                                         
    _
   /_| _ '                                                                                                                                                  
  (  |/ /(//) v2.2.2                                                                                                                                        
      _/                                                                                                                                                    

[*] Probing the target for stability
[*] Analysing HTTP response for anomalies
[*] Analysing HTTP response for potential parameter names
[+] Heuristic scanner found 1 parameter: query
[*] Logicforcing the URL endpoint
[✓] parameter detected: content, based on: http headers
[+] Parameters found: content
```

As we can see, it detects the only query parameter on the `/index.jsp` endpoint, which is `?content=<page-name>`.
This scan also impressively runs in just under 10 seconds, thanks to a [binary search style optimisation](https://github.com/s0md3v/Arjun/wiki/How-Arjun-works%3F) 


## SMB Enumeration

Server Message Block (SMB) is a client-server protocol that regulates access to files and entire directories and other network resources such as printers, routers, or interfaces released for the network.
The SMB protocol has been developed by Microsoft since 1983 with SMB1, and has iterated through 3 major versions since.
SMB1 was only discontinued in 2013, 30 years after it's initial launch, in favour of SMB2 which was released in 2013, added 32-bit and 64-bit support, and opened up the specification to allow for UNIX ports such as Samba.
SMB3 (the current version) was introduced alongside Windows 8 in 2013 and added support for end-to-end encryption. 
Microsoft attempted to rename SMB to CIFS (Common Internet File System) as it continued to develop features for it, but both terms are still in use interchangeably.

The demos in this chapter are conducted on the Metasploitable 2 and Metasploitable 3 training targets.


### Nmap Port Scanning

We can use nmap's version probing to detect the version of the SMB services that are running.
If we only care about SMB, we can save time by scanning only ports 139 and 445, which should take around a minute even with the `-T1` preset:

```bash
$ sudo nmap -sSV -T1 -p 139,445 <target>
```


Here example of scanning a target for SMB with Nmap:
```
$ sudo nmap -sSV -T1 -p 139,445 192.168.56.127

Starting Nmap 7.93 ( https://nmap.org ) at 2023-12-02 15:28 GMT
Nmap scan report for 192.168.56.127
Host is up (0.0014s latency).

PORT    STATE SERVICE     VERSION
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
MAC Address: 08:00:27:6B:43:18 (Oracle VirtualBox virtual NIC)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 62.46 second
```


### NSE Scripts

Nmap also comes with several SMB-related scripts such as:

- `smb-enum-shares` – Enumerates SMB shares in an SMB server.
Example output:

    ```
      Host script results:
    | smb-enum-shares: 
    |   account_used: guest
    |   \\192.168.56.102\IPC$: 
    |     Type: STYPE_IPC_HIDDEN
    |     Comment: IPC Service (ubuntu server (Samba, Ubuntu))
    |     Users: 2
    |     Max Users: <unlimited>
    |     Path: C:\tmp
    |     Anonymous access: READ/WRITE
    |     Current user access: READ/WRITE
    |   \\192.168.56.102\print$: 
    |     Type: STYPE_DISKTREE
    |     Comment: Printer Drivers
    |     Users: 0
    |     Max Users: <unlimited>
    |     Path: C:\var\lib\samba\printers
    |     Anonymous access: <none>
    |     Current user access: <none>
    |   \\192.168.56.102\public: 
    |     Type: STYPE_DISKTREE
    |     Comment: WWW
    |     Users: 0
    |     Max Users: <unlimited>
    |     Path: C:\var\www\html\
    |     Anonymous access: <none>
    |_    Current user access: <none>
    ```
- `smb-brute` – Performs brute-force password auditing against SMB servers. Example Output:
  ```
  Host script results:
  | smb-brute: 
  |   msfadmin:msfadmin => Valid credentials
  |_  user:user => Valid credentials
  ```
- `smb-protocols` - Attempts to list the supported protocols and dialects of a SMB server. Example Output:
  ```
  Host script results:
  | smb-protocols: 
  |   dialects: 
  |     NT LM 0.12 (SMBv1) [dangerous, but default]
  |     202
  |     210
  |     300
  |     302
  |_    311
  ```
- `smb-security-mode` and `smb2-security-mode` - Returns information about the SMB security level determined by SMB. Example Output:
  ```
  Host script results:
  | smb-security-mode: 
  |   account_used: guest
  |   authentication_level: user
  |   challenge_response: supported
  |_  message_signing: disabled (dangerous, but default)
  | smb2-security-mode: 
  |   311: 
  |_    Message signing enabled but not required
  ```
- `smb-vuln-*` – Identifies whether the SMB server is vulnerable to any known exploits. Example output:
  ```
  Host script results:
  |_smb-vuln-ms10-061: false
  |_smb-vuln-ms10-054: false
  | smb-vuln-regsvc-dos: 
  |   VULNERABLE:
  |   Service regsvc in Microsoft Windows systems vulnerable to denial of service
  |     State: VULNERABLE
  |       The service regsvc in Microsoft Windows 2000 systems is vulnerable to denial of service caused by a null deference
  |       pointer. This script will crash the service if it is vulnerable. This vulnerability was discovered by Ron Bowes
  |       while working on smb-enum-sessions.
  |_
  ```

While it is convenient that Nmap includes so many of these features in it's NSE, it may be more beneficial to brute-force passwords using Hydra and to enumerate shares using one of the tools below.
Running a brute-force attack to authenticate can be quite noisy in terms of stealth, so try some known credentials first if you have any.


### smbclient

`smbclient` is a part of the Samba suite, and can be used to communicate with SMB shares with an FTP-like interface.
It comes included with Kali and Parrot OS, but some users may experience an issue with the out-of-the-box configuration that causes errors trying to connect to some SMB servers.
You may need to add the following lines to your Samba configuration (ususally at /etc/samba/smb.conf) [like described here](https://unix.stackexchange.com/questions/562550/smbclient-protocol-negotiation-failed)

```
client min protocol = CORE
client max protocol = SMB3
```

Usage for connecting to an anonymously accessible share looks like this:

  ```
  $ smbclient -N -L \\192.168.56.128
  
  Anonymous login successful
  
      Sharename       Type      Comment
      ---------       ----      -------
      print$          Disk      Printer Drivers
      tmp             Disk      oh noes!
      opt             Disk      
      IPC$            IPC       IPC Service (ubuntu2004 server (Samba 3.0.20-Debian))
      ADMIN$          IPC       IPC Service (ubuntu2004 server (Samba 3.0.20-Debian))
  Reconnecting with SMB1 for workgroup listing.
  Anonymous login successful
  
      Server               Comment
      ---------            -------
  
      Workgroup            Master
      ---------            -------
      WORKGROUP            UBUNTU2004
  ```

You can then use `smbclient` to login and establish an interactive smbshell on any of the detected shares, or pass one or more pre-determined commands:

```
$ smbclient -N \\\\192.168.56.128\\tmp -c "recurse;ls"
Anonymous login successful
  .                                   D        0  Tue Dec 19 01:52:05 2023
  ..                                 DR        0  Fri Nov  3 03:13:38 2023
  .X0-lock                           HR       11  Fri Nov  3 03:13:44 2023
  .ICE-unix                          DH        0  Sun Jan 28 03:08:08 2018
  .X11-unix                          DH        0  Fri Nov  3 03:13:44 2023
  814.jsvc_up                         R        0  Fri Nov  3 03:13:48 2023
  810.jsvc_up                         R        0  Sun Jan 28 03:54:31 2018
  820.jsvc_up                         R        0  Tue Dec 19 00:23:22 2023
  826.jsvc_up                         R        0  Sun Jan 28 07:08:40 2018
  1582.jsvc_up                        R        0  Sun Jan 28 04:01:49 2018
  1823.jsvc_up                        R        0  Sun Jan 28 02:57:44 2018

\.ICE-unix
  .                                   D        0  Sun Jan 28 03:08:08 2018
  ..                                  D        0  Tue Dec 19 01:52:05 2023

\.X11-unix
  .                                   D        0  Fri Nov  3 03:13:44 2023
  ..                                  D        0  Tue Dec 19 01:52:05 2023
  X0                                  A        0  Fri Nov  3 03:13:44 2023

		65221196 blocks of size 1024. 37317284 blocks available
```


### SMBMap

Alternatively you can use SMBMap, an SMB enumeration tool designed with penetration testing in mind.
The `smbmap` tool comes included with Kali and Parrot OS, but can easily be installed using Python 3:

```
sudo pip3 install smbmap
```

Unlike `smbclient`, you can also show permissions for each share, upload/download functionality, and more.

```
$ smbmap -H 192.168.56.128

[+] IP: 192.168.56.128:445	Name: 192.168.56.128                                    
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	print$                                            	NO ACCESS	Printer Drivers
	tmp                                               	READ, WRITE	oh noes!
	opt                                               	NO ACCESS	
	IPC$                                              	NO ACCESS	IPC Service (ubuntu2004 server (Samba 3.0.20-Debian))
	ADMIN$                                            	NO ACCESS	IPC Service (ubuntu2004 server (Samba 3.0.20-Debian))
```

It also makes it easier to list the files on a given share, either recursively (with `-R`) or non-recursively (with `-r`):

```
smbmap -r tmp -H 192.168.56.128
[+] IP: 192.168.56.128:445	Name: 192.168.56.128                                    
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	tmp                                               	READ, WRITE	
	.\tmp\*
	dr--r--r--                0 Tue Dec 19 01:45:36 2023	.
	dw--w--w--                0 Fri Nov  3 03:13:37 2023	..
	fw--w--w--               11 Fri Nov  3 03:13:43 2023	.X0-lock
	dr--r--r--                0 Sun Jan 28 03:08:07 2018	.ICE-unix
	dr--r--r--                0 Fri Nov  3 03:13:43 2023	.X11-unix
	fw--w--w--                0 Fri Nov  3 03:13:47 2023	814.jsvc_up
	fw--w--w--                0 Sun Jan 28 03:54:30 2018	810.jsvc_up
	fw--w--w--                0 Tue Dec 19 00:23:21 2023	820.jsvc_up
	fw--w--w--                0 Sun Jan 28 07:08:39 2018	826.jsvc_up
	fw--w--w--                0 Sun Jan 28 04:01:48 2018	1582.jsvc_up
	fw--w--w--                0 Sun Jan 28 02:57:43 2018	1823.jsvc_up
```


## NFS Enumeration

NFS (Network File System) is a client-server model file sharing protocol created by Sun Microsystems in 1984.
It has since however seen many updates since NFSv1, with the most recent being NFS version 4.2 which was published in November 2016.
The previous versions NFSv2 and NFSv3 supported both TCP and UDP, in fact UDP was preferred due to its lower overheads translating to higher theoretical throughputs.
NFSv4 now requires TCP instead though, and will operate over port 2049 by default.
NFSv3 also requires Portmap, which requires port 111 (by default) on the server to be open.

To test the techniques in this chapter, the [HackLAB: Vulnix](https://www.vulnhub.com/entry/hacklab-vulnix,48/) VM from Vulnhub is used.


### RPC

When using NFS, the communication between clients and server takes place by way of Remote Procedure Call (RPC) services.
The NFS client makes procedure calls based on the file system operations that are done by the client process, and the procedures run on the server transparently as if the client process had run the calls in its own address space.

The RPC Portmapper (also called portmap or rpcbind) is a service which makes sure that the client ends up at the right port.
RPC processes notify rpcbind when they start, registering the ports they are listening on and the RPC program numbers they expect to serve.
The `rpcbind` utility then maps RPC services to the ports on which they listen, and publishes the mapping on the `rpcbind` port, which you can see with `rpcinfo`.
You can view the assigned RPC program numbers on the Internet Assigned Numbers Authority (IANA) page on [RPC Program Numbers](https://www.iana.org/assignments/rpc-program-numbers/rpc-program-numbers.xhtml).
The client can then query `rpcbind` on the server with a particular program number (for example 100003 for NFS) and receive the port number on which NFS is listening on.

![img.png](assets/RPC.png)

You can see this for yourself using the `rpcinfo` utility, which will expose the RPC services running on the target machine:

```
$ rpcinfo -p 192.168.56.108   
   program vers proto   port  service
    100000    4   tcp    111  portmapper
    100000    3   tcp    111  portmapper
    100000    2   tcp    111  portmapper
    100000    4   udp    111  portmapper
    100000    3   udp    111  portmapper
    100000    2   udp    111  portmapper
    100024    1   udp  43932  status
    100024    1   tcp  56810  status
    100003    2   tcp   2049  nfs
    100003    3   tcp   2049  nfs
    100003    4   tcp   2049  nfs
    100227    2   tcp   2049
    100227    3   tcp   2049
    100003    2   udp   2049  nfs
    100003    3   udp   2049  nfs
    100003    4   udp   2049  nfs
    100227    2   udp   2049
    100227    3   udp   2049
    100021    1   udp  57382  nlockmgr
    100021    3   udp  57382  nlockmgr
    100021    4   udp  57382  nlockmgr
    100021    1   tcp  60258  nlockmgr
    100021    3   tcp  60258  nlockmgr
    100021    4   tcp  60258  nlockmgr
    100005    1   udp  56007  mountd
    100005    1   tcp  49087  mountd
    100005    2   udp  41956  mountd
    100005    2   tcp  35651  mountd
    100005    3   udp  39174  mountd
    100005    3   tcp  42018  mountd
```

The dump shows that NFS is running with various versions and that it can be reached at TCP or UDP port 2049.
For each version of NFS on TCP or UDP there is also an `nlockmgr` and `mountd` instance.

### Scanning NFS with Nmap

We can first check if a web server is exposing NFS by using Nmap to run a port scan.
An NFS server expose at least the following services:

- `nfs` itself (on port 2049 by default)
- `rpcbind` or `sunrpc` (on port 111 by default)
- `nlockmgr` (portmapper will assign to a non-privileged port >1024)
- `mountd` (portmapper will assign to a non-privileged port >1024)


Nmap also has some useful scripts for showing information about NFS exports from targets, such as:

- `nfs-ls` - Attempts to get useful information about files from NFS exports. The output is intended to resemble the output of ls.
- `nfs-showmount` - Shows NFS exports, like the `showmount -e` command.
- `nfs-statfs` - Retrieves disk space statistics and information from a remote NFS share. The output is intended to resemble the output of df.

You can run all these checks together at the same time as an RPC scan with the following command:

```
$ sudo nmap -sR 192.168.56.108 -p 1-65535 --script nfs*

Starting Nmap 7.80 ( https://nmap.org ) at 2023-12-26 18:42 GMT
Nmap scan report for 192.168.56.108
Host is up (0.000084s latency).
Not shown: 65518 closed ports
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 5.9p1 Debian 5ubuntu1 (Ubuntu Linux; protocol 2.0)
25/tcp    open  smtp       Postfix smtpd
79/tcp    open  finger     Linux fingerd
110/tcp   open  pop3       Dovecot pop3d
111/tcp   open  rpcbind    2-4 (RPC #100000)
| nfs-ls: Volume /home/vulnix
|_  access: NoRead NoLookup NoModify NoExtend NoDelete NoExecute
| nfs-showmount: 
|_  /home/vulnix *
| nfs-statfs: 
|   Filesystem    1K-blocks  Used      Available  Use%  Maxfilesize  Maxlink
|_  /home/vulnix  792040.0   715272.0  37040.0    96%   8.0T         32000
| rpcinfo: 
[... omitted for brevity - same as rpcinfo output above ...]
2049/tcp  open  nfs_acl    2-3 (RPC #100227)
35651/tcp open  mountd     1-3 (RPC #100005)
| nfs-showmount: 
|_  /home/vulnix *
42018/tcp open  mountd     1-3 (RPC #100005)
| nfs-showmount: 
|_  /home/vulnix *
49087/tcp open  mountd     1-3 (RPC #100005)
| nfs-showmount: 
|_  /home/vulnix *
56810/tcp open  status     1 (RPC #100024)
60258/tcp open  nlockmgr   1-4 (RPC #100021)
MAC Address: 08:00:27:2C:2E:6A (Oracle VirtualBox virtual NIC)
Service Info: Host:  vulnix; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 35.45 seconds
```

### Mounting The Export

You can manually mount an NFS share using the `mount` command, but you won't be able to access the directory unless the UID and GID of your user matches those of the shared directory on the server:

```bash
$ mkdir ~/nfs-mount
$ sudo mount -t nfs -o vers=3 192.168.56.108:/home/vulnix ~/nfs-mount/
$ ls -ld nfs-mount/

drwxr-x--- 2 2008 2008 4096 Sep  2  2012 nfs-mount/
```
You will need to create a new user and group with matching UIDs and GIDs and run all your commands as that user.

```bash
$ sudo groupadd -g 2008 vulnix
$ sudo adduser vulnix -uid 2008 -gid 2008
$ su vulnix
```

Now you can access the directory normally:

```bash
$ ls -a ~/nfs-mount

. .. .bash_logout .bashrc .profile
```

From here you now have a read/write access which you can use to escalate privileges, for example by uploading your own SSH keys.


### NfSpy

The process of mounting an NFS share can be simplified with NfSpy.
NfSpy works by using FUSE to mount the NFS share in userspace, and spoofs the UID and GID instead of actually creating a new user.

NfSpy used to come with Kali OS, but was removed from `kali-rolling` in 2019 as the source code was no longer maintained and archived.
To install NfSpy simply clone [the git repository](https://github.com/bonsaiviking/NfSpy/) and then run `sudo python2 setup.py install`.

```bash
$ nfspy -o server=192.168.2.4:/home/vulnix,nfsport=2049/tcp,rw vulnix-mount
$ ls -a vulnix

.  ..  .bash_logout  .bashrc  .profile
```

Alternatively, you can get an FTP-like shell using `nfspysh`, which doesn't require FUSE and therefore is much more convenient to deploy for Windows and other OS users:

```
nfspysh -o server=192.168.56.108:/home/vulnix

nfspy@192.168.56.108:/home/vulnix:/> ls
/:
040750   2008   2008        4096 2012-09-02 19:25:02 .
100644   2008   2008         220 2012-04-03 16:58:14 .bash_logout
100644   2008   2008         675 2012-04-03 16:58:14 .profile
040750   2008   2008        4096 2012-09-02 19:25:02 ..
100644   2008   2008        3486 2012-04-03 16:58:14 .bashrc
```


## FTP Enumeration

File Transfer Protocol (FTP) is a client-server model communication protocol used to transfer files between devices on a network.
It is a plain-text protocol (which means no encryption), but it does support authentication for clients using a username and password.

In order to add encryption, there are alternatives such as:

- FTPS - An extension to FTP that adds support for TLS (formerly SSL)
- SFTP - SSH File Transfer Protocol - A secure file transfer subsystem for the Secure Shell (SSH) protocol
- FTP over SSH - The practice of using standard FTP over an SSH tunnel


### Scanning FTP with Nmap

By default, FTP runs on port 21, and sometimes SFTP or FTPS can be found on port 2121.
We can use Nmap to detect what FTP servers (if any) are running on these ports:

```
$ sudo nmap -sV -p 21,2121 --script ftp* 192.168.56.106

[... omitted for brevity ...]

PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-brute: 
|   Accounts: 
|     user:user - Valid credentials
|_  Statistics: Performed 661 guesses in 183 seconds, average tps: 2.8
| ftp-vsftpd-backdoor: 
|   VULNERABLE:
|   vsFTPd version 2.3.4 backdoor
|     State: VULNERABLE (Exploitable)
|     IDs:  BID:48539  CVE:CVE-2011-2523
|       vsFTPd version 2.3.4 backdoor, this was reported on 2011-07-04.
|     Disclosure date: 2011-07-03
|     Exploit results:
|       Shell command: id
|       Results: uid=0(root) gid=0(root)
|     References:
|       https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/unix/ftp/vsftpd_234_backdoor.rb
|       https://www.securityfocus.com/bid/48539
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-2523
|_      http://scarybeastsecurity.blogspot.com/2011/07/alert-vsftpd-download-backdoored.html
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.56.1
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
2121/tcp open  ftp     ProFTPD 1.3.1

[... omitted for brevity ...]
```

### FTP Bounce Attacks

One of Nmap's useful scripts for FTP is the `ftp-bounce` script, which checks to see if an FTP server allows port scanning using the FTP bounce method.
FTP Bounce attacks are an exploit of the FTP protocol, whereby an attacker is able to use the PORT command to request access to ports indirectly through the use of the victim machine, which serves as a proxy for the request.
This technique can be used to port scan hosts discreetly by redirecting attribution of the scans to the victim FTP bounce target, similar to the Zombie / IDLE scan.

Unfortunately most modern FTP server programs are configured by default to refuse PORT commands that would connect to any host but the originating host, thwarting FTP bounce attacks.
If we were able to find a vulnerable host however, we could use it to bounce our Nmap scans using the `-b` flag:

```bash
$ nmap -b <name>:<pass>@<ftp_server> <victim>
```

### Access

You used to be able to browse FTP servers using your browser, but that feature has been disabled since 2021.

An alternative is to use `wget`.
You can download all available files by not specifying a path other than the root:

```bash
$ wget -m ftp://<name>:<pass>@<ftp_server>
```

There is of course the regular `ftp` client that ships with most linux distributions as well.
Even Windows 11 now includes an `ftp` client in the default Powershell, but for FTPS and SFTP support consider [FileZilla](https://filezilla-project.org/).


## SMTP Enumeration

The Simple Mail Transfer Protocol (SMTP) is a TCP/IP protocol used in sending emails over a network.
SMTP is a push protocol and is used to send the mail whereas POP (post office protocol) or IMAP (internet message access protocol) is used to retrieve those emails at the receiver’s side. 

SMTP has 3 commands in particular that are useful for enumerating available users:

- `VRFY`: It is used to validate the user on the server.
- `EXPN`: It is used to find the delivery address of mail aliases
- `RCPT` TO: It points to the recipient’s address.

To test the following techniques, the SMTP server of the [Metasploitable 2](https://docs.rapid7.com/metasploit/metasploitable-2/) virtual machine was used.


### Scanning SMTP with Nmap

As always, one of the first tools we should use to analyse a given target is Nmap.
SMTP typically runs on ports 25, 465 or 587, with 465 typically being used for Authenticated SMTP over TLS/SSL (SMTPS).
Nmap also includes some useful NSE scripts for SMTP reconnaissance, such as:

- `smtp-commands` -  Attempts to use EHLO and HELP to gather the Extended commands supported by an SMTP server.
- `smtp-enum-users` - Attempts to enumerate the users on an SMTP server by issuing the VRFY, EXPN or RCPT TO commands.
- `smtp-open-relay` - Checks if an SMTP server is vulnerable to mail relaying (i.e. does not verify if the user is authorised to send email from the specified email address)
- `smtp-ntlm-info` -  Enumerates information from remote SMTP services with NTLM authentication enabled. 
- `smtp-brute` - Performs brute force password auditing against SMTP servers using either LOGIN, PLAIN, CRAM-MD5, DIGEST-MD5 or NTLM authentication.

If you're confident about the port which your target's SMTP service is running on (perhaps from an earlier scan), you can save time by only scanning those ports:

```
$ sudo nmap -sSV -p 25,465,587 --script smtp* --script-args "smtp-enum-users.methods={VRFY}" 192.168.56.106

Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-27 17:11 EST
Nmap scan report for 192.168.56.106
Host is up (0.00097s latency).

PORT    STATE  SERVICE    VERSION
25/tcp  open   smtp       Postfix smtpd
| smtp-enum-users: 
|_  Couldn't find any accounts
|_smtp-commands: metasploitable.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN
|_smtp-open-relay: Server doesn't seem to be an open relay, all tests failed
| smtp-vuln-cve2010-4344: 
|_  The SMTP server is not Exim: NOT VULNERABLE
465/tcp closed smtps
587/tcp closed submission
Service Info: Host:  metasploitable.localdomain

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.68 seconds
```

Sometimes the `smtp-enum-users` script will be unsuccessful in finding any accounts (like shown above), in which case you could try a different tool such as `smtp-user-enum` instead.

However, if you find that the script returns `Method RCPT returned a unhandled status code` instead, that may be because the server doesn't support the `RCPT` method.
As we can see from the output of the `smtp-commands` script, of the three commands we mentioned earlier (`VRFY`, `EXPN`, and `RCPT`), the server only supports `VRFY`.
To remedy this we can set the method(s) that the script tries to use (and their order), using the `--script-args "smtp-enum-users.methods={VRFY,EXPN,RCPT}"` flags.


### smtp-user-enum

[smtp-user-enum](https://www.kali.org/tools/smtp-user-enum/) is a username guessing tool primarily for use against the default Solaris SMTP service.
It performs a similar role to Nmap's `smtp-enum-users` script, but allows you to use a custom wordlist for usernames tested, or just test a single username.
Kali Linux and Metasploit users will have access to some useful wordlists out of the box, such as the one at `/usr/share/wordlists/metasploit/unix_users.txt`.

You can pick a single user to test with `-u`, or feed in a user list file with `-U` and the default mode is `VRFY` (but that can be changed with the `-M` flag):

```
``smtp-user-enum -M VRFY -U `/usr/share/wordlists/metasploit/unix_users.txt -t``` 192.168.56.106

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

######## Scan started at Wed Dec 27 16:18:12 2023 #########
192.168.56.106: backup exists
192.168.56.106: bin exists
192.168.56.106: daemon exists
[... omitted for brevity ...]
192.168.56.106: user exists
192.168.56.106: uucp exists
192.168.56.106: www-data exists
######## Scan completed at Wed Dec 27 16:18:13 2023 #########
30 results.

168 queries in 1 seconds (168.0 queries / sec)
```

This script was successful in finding 30 different users on the target machine.


### Metasploit SMTP Module

Metasploit also has a user enumeration script just as both Nmap and `smtp-user-enum` do, thanks to the `scanner/smtp/smtp_enum` auxilliary module.
But there is a key advantage in using Metasploit's alternative implementation instead: this module also has a supports some defense evasion features to help us avoid detection:

```
msf6 auxiliary(scanner/smtp/smtp_enum) > show evasion

Module evasion options:

   Name                Current Setting  Required  Description
   ----                ---------------  --------  -----------
   TCP::max_send_size  0                no        Maxiumum tcp segment size.  (0 = disable)
   TCP::send_delay     0                no        Delays inserted before every send.  (0 = disable)
```

By setting `TCP::max_send_size`, we can fragment our packets to help avoid NIDS detections.
I found that a value of 4 bytes worked well to reduce detections on Snort when the defragmentation preprocessor was not enabled.

The `TCP::send_delay` option can also be used to reduce the rate at which requests are sent, using a value in milliseconds.
You may see diminishing returns at values above 20000, but depending on your patience and the size of your wordlist this can further reduce your chance of detection.

Bringing all these together, here is a demo of how to enumerate the SMTP service users using `msfconsole`:

```
msf6 > use auxiliary/scanner/smtp/smtp_enum 
msf6 auxiliary(scanner/smtp/smtp_enum) > set RHOSTS 192.168.56.106
RHOSTS => 192.168.56.106
msf6 auxiliary(scanner/smtp/smtp_enum) > set TCP::max_send_size 4
TCP::max_send_size => 4
msf6 auxiliary(scanner/smtp/smtp_enum) > set TCP::send_delay 15000
TCP::send_delay => 15000
msf6 auxiliary(scanner/smtp/smtp_enum) > exploit

[*] 192.168.56.106:25     - 192.168.56.106:25 Banner: 220 metasploitable.localdomain ESMTP Postfix (Ubuntu)
[+] 192.168.56.106:25     - 192.168.56.106:25 Users found: , backup, bin, daemon, distccd, ftp, games, gnats, irc, libuuid, list, lp, mail, man, mysql, news, nobody, postfix, postgres, postmaster, proxy, service, sshd, sync, sys, syslog, user, uucp, www-data
[*] 192.168.56.106:25     - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

Interestingly, this finds only 25 of the 30 users that we found using `smtp-user-enum`, even though the wordlists used were identical.
In particular, the `root` and `ROOT` users weren't detected by Metasploit.


## SNMP Enumeration

Simple Network Management Protocol (SNMP) is a protocol to facilitate the sharing of information among various devices on a network.
It can be used to monitor routers, switches, printers, IoT devices, etc. in a way that is agnostic to their hardware or software.

The tools in this chapter are tested against the [Analoguepond: 1](https://www.vulnhub.com/entry/analougepond-1,185/) virtual machine from Vulnhub


### How SNMP Works

SNMP has a simple architecture based on a client-server model:

- The servers, called managers, collect and process information about devices on the network.
- The clients, called agents, are any type of device or device component connected to the network. 

At the centre of SNMP is the Management Information Base (MIB), a tree structure hierarchy containing all queryable SNMP objects of a device, and each object has an Object Identifier (OID) (such as `1.3.6.1.2.1.1`):

![img.png](assets/SNMP.png)

Each digit of the OID has significance and maps to a particular resource: for example `1.3.6.1` is `iso.org.dod.internet`.

There are only 7 commands, or Protocol Data Units (PDUs) as known in SNMP, that are allowed by the protocol:

| PDU Type   | Purpose                                                                                                                                                   |
|------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------|
| `Get`      | Sent by a manager to an agent to request the value of a specific OID.                                                                                     |
| `GetNext`  | Allows a manager to request the next sequential object in the MIB.                                                                                        |
| `Set`      | Sent by a manager to an agent in order to change the value held by a variable on the agent.                                                               |
| `GetBulk`  | This manager to agent request functions as if multiple GetNext requests were made.                                                                        |
| `Response` | An agent-to-manager message used to send any requested information back to the manager, acting as both a response with content and as an acknowledgement. |
| `Trap`     | Traps are asynchronous notifications in that they are unsolicited by the manager receiving them. They are typically triggered by events on the agents.    |
| `Inform`   | To confirm the receipt of a trap, a manager sends an Inform message back to the agent.                                                                    |


### Protocol Versions

SNMPv1 had its first RFC in 1988, and was incrementally standardised with 6 more RFCs, until 1991 when the RFC for version 2 of management information base (MIB-2) was published.
SNMPv1 is still widely used and is the de facto network management protocol in the Internet community.

Work on SNMPv2, a revision to SNMPv1 promising substantial improvements to security, began in 1993 but was not very well adopted.
The community took issue with its controversial party-based security model, which was then omitted again to make SNMPv2c.

SNMPv2c formed the backbone of SNMPv3 which superseded it in 1998, and added support for data encryption and different authentication requirements on a granular basis for managers and agents.
SNMPv3 is the current version of SNMP, addressing privacy and authentication concerns from previous versions.

All versions of SNMP communicate using UDP over a default port of 161.


### Brute-Forcing Community Strings

In order to access the information saved on the MIB you need to know the community string on versions 1 and 2/2c and the credentials on version 3.
Unless we're privy to these values already thanks to some clever social engineering, we're going to need to brute force this before we can begin our enumeration.

For a good list of usernames, consider using /`usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt`.
This comes with the `seclists` package, which if you don't already have can be installed with:

```
$ sudo apt install seclists
```


### Scanning SNMP with Nmap

Fortunately, our trusty swiss army knife `nmap` includes several useful scripts for SNMP penetration testing, including:

- `snmp-brute` -  Attempts to find an SNMP community string by brute force guessing. The default wordlist is `nselib/data/snmpcommunities.lst`

For a brute-force, specify only the `snmp-brute` script when scanning like so:

```
$ sudo nmap -sUV -p 161 192.168.56.111 --script snmp-brute
            
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-26 20:45 EST
Nmap scan report for 192.168.56.111
Host is up (0.00053s latency).

PORT    STATE SERVICE VERSION
161/udp open  snmp    SNMPv1 server; net-snmp SNMPv3 server (public)
| snmp-info: 
|   enterprise: net-snmp
|   engineIDFormat: unknown
|   engineIDData: 096a5051642b555800000000
|   snmpEngineBoots: 18
|_  snmpEngineTime: 1h40m33s
| snmp-brute: 
|_  public - Valid credentials
Service Info: Host: analoguepond

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.27 seconds
```

The string `public` which Nmap found here is a commonly used community string, so consider trying it first before carrying out brute-forcing.

Nmap also includes some more scripts which are handy for SNMP enumeration, including:

- `snmp-info` -  Extracts basic information from an SNMPv3 GET request. The same probe is used here as in the service version detection scan.
- `snmp-interfaces` - Attempts to enumerate network interfaces through SNMP.
- `snmp-processes` - Attempts to enumerate running processes through SNMP.
- `snmp-netstat` - Attempts to query SNMP for a netstat like output. 
- `snmp-sysdescr` -  Attempts to extract system information from an SNMP service.

Since we already have the community string, the `snmp-brute` script is the only one we don't need:

```
$ sudo nmap -sUV -p 161 192.168.56.111 --script "snmp* and not snmp-brute"

Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-26 22:47 EST
Nmap scan report for 192.168.56.111
Host is up (0.00065s latency).

PORT    STATE SERVICE VERSION
161/udp open  snmp    SNMPv1 server; net-snmp SNMPv3 server (public)
| snmp-sysdescr: Linux analoguepond 3.19.0-25-generic #26~14.04.1-Ubuntu SMP Fri Jul 24 21:16:20 UTC 2015 x86_64
|_  System uptime: 3h42m28.76s (1334876 timeticks)
| snmp-info: 
|   enterprise: net-snmp
|   engineIDFormat: unknown
|   engineIDData: 096a5051642b555800000000
|   snmpEngineBoots: 18
|_  snmpEngineTime: 3h42m29s
Service Info: Host: analoguepond

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.46 seconds
```

### Hydra

If that doesn't work, or you wish to have more control over the execution of the brute-force attack, you can consider using Hydra instead:

```
$ hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt 192.168.56.111 snmp
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-12-26 20:57:21
[DATA] max 16 tasks per 1 server, overall 16 tasks, 118 login tries (l:1/p:118), ~8 tries per task
[DATA] attacking snmp://192.168.56.111:161/
[161][snmp] host: 192.168.56.111   password: public
[STATUS] attack finished for 192.168.56.111 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-12-26 20:57:21
```

To improve your stealth with `hydra` while using the SNMP module, consider passing the `-c <time>` flag to add a delay between each request.


### onesixtyone

[onesixtyone](https://github.com/trailofbits/onesixtyone) is a dedicated SNMP scanner, i.e. a program that sends SNMP requests to multiple IP addresses with different community strings and waits for a reply.
It takes advantage of the connectionless nature of a UDP protocol such as SNMP by spraying out SNMP requests without waiting for responses.
This makes it very quick for those less concerned about their digitial footprint on the network, and can very quickly scan multiple devices.

`onesixtyone` comes pre-installed with Kali Linux, but can otherwise be built from source like so:

```
git clone https://github.com/trailofbits/onesixtyone
cd onesixtyone
gcc -o onesixtyone onesixtyone.c
```

Usage is simple, just pass the wordlist of community strings with the `-c` flag, and if you have more than one target you can create a line-seperated list file to pass with `-i`:

```
$ onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt 192.168.56.111

Scanning 1 hosts, 120 communities
192.168.56.111 [public] Linux analoguepond 3.19.0-25-generic #26~14.04.1-Ubuntu SMP Fri Jul 24 21:16:20 UTC 2015 x86_64
```

To improve your stealth, you can specify the amount of time to wait between sending packets using the `-w <time>` flag (the default is 10ms).


### SNMPWalk

Once we have a valid community string to work with, we can begin enumerating the SNMP service.
We have a few tools we can use for this apart from Nmap, including SNMPWalk, SNMP-Check and Braa.
The `snmpwalk` utility comes installed with Kali Linux, but can be installed from your package manager otherwise:

```
$ sudo apt install snmp                 # On Debian distros, or
$ sudo dnf install net-snmp-utils       # On RHEL 8
```

`snmpwalk` can be used to retrieve a subtree of management values using SNMP GETNEXT requests.
It will issue multiple GETNEXT requests until all the data in an agent's implemented MIB tree has been traversed:

```
$ snmpwalk -v1 -c public 192.168.56.111

SNMPv2-MIB::sysDescr.0 = STRING: Linux analoguepond 3.19.0-25-generic #26~14.04.1-Ubuntu SMP Fri Jul 24 21:16:20 UTC 2015 x86_64
SNMPv2-MIB::sysObjectID.0 = OID: NET-SNMP-MIB::netSnmpAgentOIDs.10
DISMAN-EVENT-MIB::sysUpTimeInstance = Timeticks: (1176601) 3:16:06.01
SNMPv2-MIB::sysContact.0 = STRING: Eric Burdon <eric@example.com>
SNMPv2-MIB::sysName.0 = STRING: analoguepond
SNMPv2-MIB::sysLocation.0 = STRING: There is a house in New Orleans they call it...
SNMPv2-MIB::sysServices.0 = INTEGER: 72
[... omitted for brevity ...]
```

Alternatively, you can use SNMPBulkWalk, which achieves the same thing but by using SNMP GETBULK requests instead:

```
$ snmpbulkwalk -v2c -c public 192.168.56.111

SNMPv2-MIB::sysDescr.0 = STRING: Linux analoguepond 3.19.0-25-generic #26~14.04.1-Ubuntu SMP Fri Jul 24 21:16:20 UTC 2015 x86_64
SNMPv2-MIB::sysObjectID.0 = OID: NET-SNMP-MIB::netSnmpAgentOIDs.10
DISMAN-EVENT-MIB::sysUpTimeInstance = Timeticks: (1240429) 3:26:44.29
SNMPv2-MIB::sysContact.0 = STRING: Eric Burdon <eric@example.com>
SNMPv2-MIB::sysName.0 = STRING: analoguepond
SNMPv2-MIB::sysLocation.0 = STRING: There is a house in New Orleans they call it...
SNMPv2-MIB::sysServices.0 = INTEGER: 72
[... omitted for brevity ...]
```


### SNMP-Check

For a better formatted output, maybe consider using [snmpcheck](https://gitlab.com/kalilinux/packages/snmpcheck) instead.
It also comes included with Kali Linux, but the output is more human-readable:

```
$ `snmp-check 192.168.56.111 -c public -p 161`
snmp-check v1.9 - SNMP enumerator
Copyright (c) 2005-2015 by Matteo Cantoni (www.nothink.org)

[+] Try to connect to 192.168.56.111:161 using SNMPv1 and community 'public'

[*] System information:

  Host IP address               : 192.168.56.111
  Hostname                      : analoguepond
  Description                   : Linux analoguepond 3.19.0-25-generic #26~14.04.1-Ubuntu SMP Fri Jul 24 21:16:20 UTC 2015 x86_64
  Contact                       : Eric Burdon <eric@example.com>
  Location                      : There is a house in New Orleans they call it...
  Uptime snmp                   : 03:56:30.35
  Uptime system                 : 03:56:22.13
  System date                   : 2023-12-27 04:01:31.0
```

As well as system information, `snmpcheck` also supports the following enumerations:

- Hardware and storage information
- IIS statistics
- IP forwarding
- Listening UDP ports
- Mountpoints
- Network interfaces
- Network services
- Processes (and their parameters, you may see interesting values being passed here)
- User accounts
- And more...

This is the same formatting used by the metasploit framework, should you choose to use the `auxiliary/scanner/snmp/snmp_enum` module instead.
However, SNMP-Check does also include a basic GUI, which can be launched by running `snmpcheck` without any parameters.


### Braa

[Braa](https://github.com/mteg/braa) is a mass SNMP scanner, but unlike `snmpwalk` from net-snmp, it is able to query dozens or hundreds of hosts simultaneously.
It uses the GETNEXT PDU, and similar to `onesixtyone`, these two tools go hand-in-hand if you're looking to quickly enumerate a large network of SNMP devices:

```
$ braa public@192.168.56.111:.* -d 1000000

192.168.56.111:131ms:.0:Linux analoguepond 3.19.0-25-generic #26~14.04.1-Ubuntu SMP Fri Jul 24 21:16:20 UTC 2015 x86_64
192.168.56.111:143ms:.0:.10
192.168.56.111:137ms:.0:1516621
192.168.56.111:124ms:.0:Eric Burdon <eric@example.com>
192.168.56.111:140ms:.0:analoguepond
192.168.56.111:142ms:.0:There is a house in New Orleans they call it...
[... omitted for brevity ...]
```

Using the `-d <time>` flag, we can specify an amount of time to wait between each packet (in microseconds).
This can us avoid flooding the network and improve our stealth.


## WebDAV Enumeration

WebDAV (Web Distributed Authoring and Versioning) is an extension to the HTTP protocol that allows a web server to act as a file server, letting clients modify its contents.
WebDAV is rarely used alone, usually in conjunction with CalDAV (remote-access calendar) and CardDAV (remote-access address book).

Aside from the HTTP methods defined in the HTTP/1.0 and HTTP/1.1 specifications (`GET`, `HEAD`, `POST`, `PUT`, `DELETE`, `CONNECT`, `OPTIONS`, `TRACE`), WebDAV introduces 7 new verbs:

| Verb        | Action                                                                                                                                                                                   |
|-------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `COPY`      | Copy a resource from one uniform resource identifier (URI) to another                                                                                                                    |
| `LOCK`      | Put a lock on a resource. WebDAV supports both shared and exclusive locks.                                                                                                               |
| `MKCOL`     | Create collections (also known as a directory)                                                                                                                                           |
| `MOVE`      | Move a resource from one URI to another                                                                                                                                                  |
| `PROPFIND`  | Retrieve properties, stored as XML, from a web resource. It is also overloaded to allow one to retrieve the collection structure (also known as directory hierarchy) of a remote system. |
| `PROPPATCH` | Change and delete multiple properties on a resource in a single atomic act                                                                                                               |
| `UNLOCK`    | Remove a lock from a resource                                                                                                                                                            |


To test the following techniques, the WebDAV server of the [Metasploitable 2](https://docs.rapid7.com/metasploit/metasploitable-2/) VM is used.

![img.png](assets/WebDAV.png)


### Finding WebDAV Paths

We'll need to find out if the targeted web server supports WebDAV.
For this we can use either Nmap or Metasploit, but first we need to know which path to test.
Some web servers only have WebDAV and will have it enabled on the root path (`\`), whereas others will mount a DAV-enabled directory somewhere such as `\webdav\`.

To find this, we can use one of our path enumeration tools, such as [Katana](/reconnaissance/path-enumeration/playbook.md#katana):

```
$ ./katana -u http://192.168.56.106/ --depth 3

   __        __                
  / /_____ _/ /____ ____  ___ _
 /  '_/ _  / __/ _  / _ \/ _  /
/_/\_\\_,_/\__/\_,_/_//_/\_,_/                                                   

                projectdiscovery.io

[INF] Current katana version v1.0.4 (latest)
[INF] Started standard crawling for => http://192.168.56.106/
http://192.168.56.106/
http://192.168.56.106/dav/
http://192.168.56.106/twiki/
http://192.168.56.106/dvwa/
http://192.168.56.106/phpMyAdmin/
http://192.168.56.106/mutillidae/
[... omitted for brevity ...]
```

As you can see, we quickly discover `http://192.168.56.106/dav/`, which seems like a good path to test.


### Brute-Forcing WebDAV Credentials

Metasploitable 2 unauthenticated WebDAV target, if you need valid credentials you can use Hydra to try brute-force them.
WebDAV uses HTTP basic authentication, with the `Authorization` HTTP header used to pass credentials.
For example, the username/password combination `tomcat:s3cret` would get Base64 encoded and sent as `Authorization: Basic dG9tY2F0OnMzY3JldA==`.

We can use Hydra's HTTP-GET mode to attack this authentication scheme:

```bash
hydra -L <username-list> -P <password-list> <target-ip> http-get <url-path-to-webdav>
```


### Checking if WebDAV is enabled

#### Nmap

Since WebDAV is an HTTP service, it will typically be running on port 80 or 443, or the alternate non-privileged ports 8080 and 8443.
One of Nmap's NSE scripts is `http-webdav-scan`, a script to detect WebDAV installations using the OPTIONS and PROPFIND methods.
We can pass the path we found earlier to the script using the `--script-args http-webdav-scan.path=/<path>/` options (the trailing slash is essential):

```
$ nmap -sSV --script http-webdav-scan -p 80,8080,443,8443 192.168.56.106 --script-args http-webdav-scan.path=/dav/

Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-29 10:35 EST
Nmap scan report for 192.168.56.106
Host is up (0.0012s latency).

PORT     STATE  SERVICE    VERSION
80/tcp   open   http       Apache httpd 2.2.8 ((Ubuntu) DAV/2)
| http-webdav-scan: 
|   Server Type: Apache/2.2.8 (Ubuntu) DAV/2
|   Allowed Methods: OPTIONS,GET,HEAD,POST,DELETE,TRACE,PROPFIND,PROPPATCH,COPY,MOVE,LOCK,UNLOCK
|   WebDAV type: Apache DAV
|   Server Date: Fri, 29 Dec 2023 16:14:48 GMT
|   Directory Listing: 
|     /dav/
|_    /dav/DavTestDir_bw6m7rTuBg/
|_http-server-header: Apache/2.2.8 (Ubuntu) DAV/2
443/tcp  closed https
8080/tcp closed http-proxy
8443/tcp closed https-alt

Nmap done: 1 IP address (1 host up) scanned in 4.13 seconds
```

This gives us some valuable information, such the server and WebDAV type, the supported HTTP methods, and a recursive directory listing.


#### Metasploit

We can also use one of Metasploit's auxilliary modules to check if a given path has WebDAV enabled.
The `auxiliary/scanner/http/webdav_scanner` will output less useful information than the `http-webdav-scan` NSE script,
but it has the advantage that it supports HTTP basic authentication should your target requires it.

```
msf6 > use auxiliary/scanner/http/webdav_scanner
msf6 auxiliary(scanner/http/webdav_scanner) > set PATH /dav/
PATH => /dav/
msf6 auxiliary(scanner/http/webdav_scanner) > set RHOSTS 192.168.56.106
RHOSTS => 192.168.56.106
msf6 auxiliary(scanner/http/webdav_scanner) > set HttpUsername tomcat
HttpUsername => tomcat
msf6 auxiliary(scanner/http/webdav_scanner) > set HttpUsername s3cret
HttpUsername => s3cret
msf6 auxiliary(scanner/http/webdav_scanner) > run

[+] 192.168.56.106 (Apache/2.2.8 (Ubuntu) DAV/2) has WEBDAV ENABLED
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

The default user agent is quite inconspicuous, but can be changed with `set UserAgent <agent-string>`.


### DAVTest

[DAVTest](https://github.com/sullo/davtest) is a tool to test WebDAV enabled servers by uploading test executable files,
and then (optionally) uploading files which allow for command execution or other actions directly on the target.
The tool is written in Perl, and comes included with Kali Linux.

```
$ davtest --url http://192.168.56.106/dav/ -cleanup 
********************************************************
 Testing DAV connection
OPEN            SUCCEED:                http://192.168.56.106/dav
********************************************************
NOTE    Random string for this session: yjp5CO2s
********************************************************
 Creating directory
MKCOL           SUCCEED:                Created http://192.168.56.106/dav/DavTestDir_yjp5CO2s
********************************************************
 Sending test files
PUT     txt     SUCCEED:        http://192.168.56.106/dav/DavTestDir_yjp5CO2s/davtest_yjp5CO2s.txt
PUT     cgi     SUCCEED:        http://192.168.56.106/dav/DavTestDir_yjp5CO2s/davtest_yjp5CO2s.cgi
PUT     php     SUCCEED:        http://192.168.56.106/dav/DavTestDir_yjp5CO2s/davtest_yjp5CO2s.php
PUT     html    SUCCEED:        http://192.168.56.106/dav/DavTestDir_yjp5CO2s/davtest_yjp5CO2s.html
PUT     pl      SUCCEED:        http://192.168.56.106/dav/DavTestDir_yjp5CO2s/davtest_yjp5CO2s.pl
PUT     asp     SUCCEED:        http://192.168.56.106/dav/DavTestDir_yjp5CO2s/davtest_yjp5CO2s.asp
PUT     aspx    SUCCEED:        http://192.168.56.106/dav/DavTestDir_yjp5CO2s/davtest_yjp5CO2s.aspx
PUT     jhtml   SUCCEED:        http://192.168.56.106/dav/DavTestDir_yjp5CO2s/davtest_yjp5CO2s.jhtml
PUT     cfm     SUCCEED:        http://192.168.56.106/dav/DavTestDir_yjp5CO2s/davtest_yjp5CO2s.cfm
PUT     shtml   SUCCEED:        http://192.168.56.106/dav/DavTestDir_yjp5CO2s/davtest_yjp5CO2s.shtml
PUT     jsp     SUCCEED:        http://192.168.56.106/dav/DavTestDir_yjp5CO2s/davtest_yjp5CO2s.jsp
********************************************************
 Checking for test file execution
EXEC    txt     SUCCEED:        http://192.168.56.106/dav/DavTestDir_yjp5CO2s/davtest_yjp5CO2s.txt
EXEC    txt     FAIL
EXEC    cgi     FAIL
EXEC    php     SUCCEED:        http://192.168.56.106/dav/DavTestDir_yjp5CO2s/davtest_yjp5CO2s.php
EXEC    php     FAIL
EXEC    html    SUCCEED:        http://192.168.56.106/dav/DavTestDir_yjp5CO2s/davtest_yjp5CO2s.html
EXEC    html    FAIL
[... omitted for brevity ...]
```

The `-cleanup` option tells DAVTest to clean up the created files after the tests have finished running by sending HTTP DELETE requests.
This can be useful if you want to avoid leaving a trace on machines you're testing.

Another feature of DAVTest is the `-sendbd auto` option, which when enabled will upload executable backdoors in place of standard placeholder files.
However, you can make a better and more functionality-rich backdoor yourself using Metasploit, which you can upload yourself using Cadavar:


### Cadavar

[Cadaver](https://github.com/notroj/cadaver) is a command line WebDAV tool that comes pre-installed in Kali Linux.
It allows you to interact with WebDAV servers and perform tasks such as uploading and downloading files.
Once you've determined what files are uploaded and executable using DAVTest, you can use Cadavar to `PUT` them on the server:

```
$ cadaver http://192.168.56.106/dav/

dav:/dav/> put my-reverse-shell.php
Uploading my-reverse-shell.php to `/dav/my-reverse-shell.php': succeeded.
```

The payload itself and setting up a listener is out of the scope of the reconnaissance chapter, but they are both done within `msfconsole` as well.


#### A Note on Stealth

While testing DAVTest, I found that it raised detections with common IDS software such as Snort, as well as WAF solutions such as Naxsi.
In particular, the Emerging Threats ruleset contains the following rules:

```
ET SCAN DavTest WebDav Vulnerability Scanner Default User Agent Detected
ET SCAN Possible DavTest WebDav Vulnerability Scanner Initial Check Detected
```

The DAVTest tool (and all the active forks) don't currently have any way to change the user agent to anything other than the default.
For this reason, if avoiding detection is essential I'd recommend either avoiding the use of this tool, or passing through Burp proxy or similar to modify the outbound HTTP request header.

Furthermore, you may also find yourself getting blacklisted if you try to brute-force the WebDAV password using Hydra.
There are also several detection rules for popular n-day vulnerabilities that use WebDAV,
although it's unlikely that an adversary is running the most recent NIDS and WAF solutions as well as heavily outdated WebDAV software (unless you're in a honeypot).



