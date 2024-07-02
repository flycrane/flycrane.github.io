# 目标扫描

## 一、主机发现
```**$ sudo nmap -sn 10.129.96.0/24 -oA nmapscan/hosts**```

```
$ sudo nmap -sn 10.129.96.0/24 -oA nmapscan/hosts
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-31 05:59 EDT
Nmap scan report for 10.129.96.149
Host is up (0.29s latency).
Nmap scan report for 10.129.96.168
Host is up (0.29s latency).
Nmap scan report for 10.129.96.173
Host is up (0.29s latency).

Nmap done: 256 IP addresses (3 hosts up) scanned in 35.50 seconds                                 
```

## 二、扫描TCP端口
```**$ sudo nmap --min-rate 10000 -p- 10.129.96.149 -oA nmapscan/tcp**```

```
$ sudo nmap --min-rate 10000 -p- 10.129.96.149 -oA nmapscan/tcp
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-31 05:41 EDT
Stats: 0:00:19 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 46.25% done; ETC: 05:42 (0:00:05 remaining)
Nmap scan report for 10.129.96.149
Host is up (0.37s latency).
Not shown: 65529 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
6789/tcp open  ibm-db2-admin
8080/tcp open  http-proxy
8443/tcp open  https-alt
8843/tcp open  unknown
8880/tcp open  cddbp-alt

Nmap done: 1 IP address (1 host up) scanned in 28.04 seconds
```

## 三、扫描UDP端口
```**$ sudo nmap -sU --min-rate 10000 -p- 10.129.96.149 -oA nmapscan/udp**```

```
$ sudo nmap -sU --min-rate 10000 -p- 10.129.96.149 -oA nmapscan/udp
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-31 05:42 EDT
Warning: 10.129.96.149 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.129.96.149
Host is up (0.92s latency).
All 65535 scanned ports on 10.129.96.149 are in ignored states.
Not shown: 65458 open|filtered udp ports (no-response), 77 closed udp ports (port-unreach)

Nmap done: 1 IP address (1 host up) scanned in 97.57 seconds    

# 当扫描结果基本为空时，可以考虑扫描最常见的端口，如20个
$ sudo nmap -sU --min-rate 10000 --top-ports 20 10.129.96.149 -oA nmapscan/udp                                           
```

## 四、扫描系统服务(包含全部TCP和UDP端口)
```**$ sudo nmap -sT -sV -sC -O -p22,6789,8080,8443,8843,8880 10.129.96.149 -oA nmapscan/detail**```

```                                                        
$ sudo nmap -sT -sV -sC -O -p22,6789,8080,8443,8843,8880 10.129.96.149 -oA nmapscan/detail
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-31 05:45 EDT
Nmap scan report for 10.129.96.149
Host is up (0.37s latency).

PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
6789/tcp open  ibm-db2-admin?
8080/tcp open  http-proxy
|_http-title: Did not follow redirect to https://10.129.96.149:8443/manage
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 431
|     Date: Fri, 31 May 2024 09:45:26 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 404 
|     Found</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 404 
|     Found</h1></body></html>
|   GetRequest, HTTPOptions: 
|     HTTP/1.1 302 
|     Location: http://localhost:8080/manage
|     Content-Length: 0
|     Date: Fri, 31 May 2024 09:45:25 GMT
|     Connection: close
|   RTSPRequest: 
|     HTTP/1.1 400 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 435
|     Date: Fri, 31 May 2024 09:45:26 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400 
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400 
|     Request</h1></body></html>
|   Socks5: 
|     HTTP/1.1 400 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 435
|     Date: Fri, 31 May 2024 09:45:27 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400 
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400 
|_    Request</h1></body></html>
|_http-open-proxy: Proxy might be redirecting requests
8443/tcp open  ssl/nagios-nsca Nagios NSCA
| http-title: UniFi Network
|_Requested resource was /manage/account/login?redirect=%2Fmanage
| ssl-cert: Subject: commonName=UniFi/organizationName=Ubiquiti Inc./stateOrProvinceName=New York/countryName=US
| Subject Alternative Name: DNS:UniFi
| Not valid before: 2021-12-30T21:37:24
|_Not valid after:  2024-04-03T21:37:24
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.94SVN%I=7%D=5/31%Time=66599C34%P=x86_64-pc-linux-gnu%r
SF:x20Request</h1></body></html>");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.8 (95%), Linux 5.0 - 5.4 (95%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 (95%), Linux 5.0 - 5.5 (95%), Linux 3.1 (94%), Linux 3.2 (94%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), HP P2000 G3 NAS device (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 171.96 seconds
```

## 五、漏洞扫描
```**$ sudo nmap --script=vuln -p22,6789,8080,8443,8843,8880 10.129.96.149 -oA nmapscan/vulns**```

```
$ sudo nmap --script=vuln -p22,6789,8080,8443,8843,8880 10.129.96.149 -oA nmapscan/vulns # vuln可以改成其它参数
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-31 10:55 EDT
Stats: 0:51:35 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.82% done; ETC: 11:47 (0:00:06 remaining)
Nmap scan report for 10.129.187.144
Host is up (0.68s latency).

PORT     STATE SERVICE
22/tcp   open  ssh
6789/tcp open  ibm-db2-admin
8080/tcp open  http-proxy
|_http-aspnet-debug: ERROR: Script execution failed (use -d to debug)
|_http-vuln-cve2014-3704: ERROR: Script execution failed (use -d to debug)
8443/tcp open  https-alt
8843/tcp open  unknown
8880/tcp open  cddbp-alt

Nmap done: 1 IP address (1 host up) scanned in 3272.23 seconds
```

## 六、安全扫描

```
# HOST DISCOVERY:
  -sn: Ping Scan - disable port scan
  -PS/PA/PU/PY[portlist]: TCP SYN/ACK, UDP or SCTP discovery to given ports
  -PE/PP/PM: ICMP echo, timestamp, and netmask request discovery probes
  -PO[protocol list]: IP Protocol Ping
  
# SCAN TECHNIQUES:
  -sS/sT/sA/sW/sM: TCP SYN/Connect()/ACK/Window/Maimon scans
  -sN/sF/sX: TCP Null, FIN, and Xmas scans
  --scanflags <flags>: Customize TCP scan flags
  -sI <zombie host[:probeport]>: Idle scan
  -sY/sZ: SCTP INIT/COOKIE-ECHO scans
  -sO: IP protocol scan
  -b <FTP relay host>: FTP bounce scan
  
# PORT SPECIFICATION AND SCAN ORDER:
  -r: Scan ports sequentially - don't randomize

# TIMING AND PERFORMANCE:
  Options which take <time> are in seconds, or append 'ms' (milliseconds),
  's' (seconds), 'm' (minutes), or 'h' (hours) to the value (e.g. 30m).
  -T<0-5>: Set timing template (higher is faster)
  --min-hostgroup/max-hostgroup <size>: Parallel host scan group sizes
  --min-parallelism/max-parallelism <numprobes>: Probe parallelization
  --min-rtt-timeout/max-rtt-timeout/initial-rtt-timeout <time>: Specifies
      probe round trip time.
  --max-retries <tries>: Caps number of port scan probe retransmissions.
  --host-timeout <time>: Give up on target after this long
  --scan-delay/--max-scan-delay <time>: Adjust delay between probes
  --min-rate <number>: Send packets no slower than <number> per second
  --max-rate <number>: Send packets no faster than <number> per second

# FIREWALL/IDS EVASION AND SPOOFING:
  -f; --mtu <val>: fragment packets (optionally w/given MTU)
  -D <decoy1,decoy2[,ME],...>: Cloak a scan with decoys
  
  -S <IP_Address>: Spoof source address
  -g/--source-port <portnum>: Use given port number
  
  --proxies <url1,[url2],...>: Relay connections through HTTP/SOCKS4 proxies
  --data <hex string>: Append a custom payload to sent packets
  --data-string <string>: Append a custom ASCII string to sent packets
  --data-length <num>: Append random data to sent packets
  --ip-options <options>: Send packets with specified ip options
  --ttl <val>: Set IP time-to-live field
  --spoof-mac <mac address/prefix/vendor name>: Spoof your MAC address
  --badsum: Send packets with a bogus TCP/UDP/SCTP checksum

# MISC:
  --send-eth/--send-ip: Send using raw ethernet frames or IP packets
```