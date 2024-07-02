# 信息收集

## 准备阶段
```
1、使用隧道代理：123proxy
2、清除个人信息
3、浏览器隐私模式
4、不登录任何个人账号，防止溯源
```

## 被动收集
```
# Passive Recon：利用公开信息，whois，OSINT，DNS，Search engine dorks

# whois to query WHOIS servers: 43端口
#Registrar: Via which registrar was the domain name registered?
#Contact info of registrant: Name, organization, address, phone, among other things. (unless made hidden via a privacy service)
#Creation, update, and expiration dates: When was the domain name first registered? When was it last updated? And when does it need to be renewed?
#Name Server: Which server to ask to resolve the domain name?
$ whois hackerone.org

# nslookup to query DNS servers
$ nslookup OPTIONS DOMAIN_NAME SERVER
- OPTIONS contains the query type as shown in the table below. For instance, you can use A for IPv4 addresses and AAAA for IPv6 addresses.
- DOMAIN_NAME is the domain name you are looking up.
- SERVER is the DNS server that you want to query. You can choose any local or public DNS server to query. Cloudflare offers 1.1.1.1 and 1.0.0.1, Google offers 8.8.8.8 and 8.8.4.4, and Quad9 offers 9.9.9.9 and 149.112.112.112. There are many more public DNS servers that you can choose from if you want alternatives to your ISP’s DNS servers.

Query type	Result
A	IPv4 Addresses
AAAA	IPv6 Addresses
CNAME	Canonical Name
MX	Mail Servers
SOA	Start of Authority
TXT	TXT Records

$ nslookup -type=A tryhackme.com 1.1.1.1
$ nslookup -type=a tryhackme.com 1.1.1.1 a

user@TryHackMe$ nslookup -type=A tryhackme.com 1.1.1.1
Server:		1.1.1.1
Address:	1.1.1.1#53
Non-authoritative answer:
Name:	tryhackme.com
Address: 172.67.69.208
Name:	tryhackme.com
Address: 104.26.11.229
Name:	tryhackme.com
Address: 104.26.10.229

user@TryHackMe$ nslookup -type=MX tryhackme.com
Server:		127.0.0.53
Address:	127.0.0.53#53
Non-authoritative answer:
tryhackme.com	mail exchanger = 5 alt1.aspmx.l.google.com.
tryhackme.com	mail exchanger = 1 aspmx.l.google.com.
tryhackme.com	mail exchanger = 10 alt4.aspmx.l.google.com.
tryhackme.com	mail exchanger = 10 alt3.aspmx.l.google.com.
tryhackme.com	mail exchanger = 5 alt2.aspmx.l.google.com.

We can see that tryhackme.com’s current email configuration uses Google. Since MX is looking up the Mail Exchange servers, we notice that when a mail server tries to deliver email @tryhackme.com, it will try to connect to the aspmx.l.google.com, which has order 1. If it is busy or unavailable, the mail server will attempt to connect to the next in order mail exchange servers, alt1.aspmx.l.google.com or alt2.aspmx.l.google.com.

Google provides the listed mail servers; therefore, we should not expect the mail servers to be running a vulnerable server version. However, in other cases, we might find mail servers that are not adequately secured or patched.

# dns查询
$ host [domain]
$ host -t [field] [domain]
$ host [ip_address]
$ host [domain] [8.8.8.8]

# dig to query DNS servers, Domain Information Groper, dig @SERVER DOMAIN_NAME TYPE
$ dig thmlabs.com TXT
$ nslookup -type=TXT thmlabs.com
# A quick comparison between the output of nslookup and dig shows that dig returned more information, such as the TTL (Time To Live) by default

$ dig @1.1.1.1 hackerone.org
$ dig hackerone.org NS
$ dig hackerone.org ANY
$ dig @8.8.8.8 hackerone.org ANY

Lookup the IP(s) associated with a hostname (A records)
$ dig +short [example.com]

Get a detailed answer for a given domain (A records)
$ dig +noall +answer [example.com]

Query a specific DNS record type associated with a given domain name
$ dig +short [example.com] [A|MX|TXT|CNAME|NS]

Get all types of records for a given domain name
$ dig [example.com] ANY

Specify an alternate DNS server to query
$ dig @[8.8.8.8] [example.com]

Perform a reverse DNS lookup on an IP address (PTR record)
$ dig -x [8.8.8.8]

Find authoritative name servers for the zone and display SOA records
$ dig +nssearch [example.com]

Perform iterative queries and display the entire trace path to resolve a domain name
$ dig +trace [example.com]

# DNSDumpster, DNS Servers, MX Records, TXT Records, Host (A) Records, Domain Map
https://dnsdumpster.com/

# Shodan.io
https://www.shodan.io/

#filters: https://www.shodan.io/search/filters
ssh port:22,3333
ssh -port:22 # SSH on non-standard ports
http.title:"hacked by"
hostname:google.com,facebook.com

# Google dorks
google: site:*.bbc.com -site:www.bbc.com
google: site:*.bbc.com inurl:login
google: site:*.bbc.com filetype:pdf
google: inurl:wp-admin.php

$ dnsrecon

$ wafw00f hackerone.org

$ https://sitereport.netcraft.com/

$ https://www.whatismyip.com/ip-whois-lookup/

$ theHarvester -D Digininja -b linkedin,bing,google,sublist3r,twitter,yahoo

# subdomain enumeration
$ sublis3r

### /etc/hosts 指定域名/IP解析
### /etc/services 服务和端口
### /etc/resolv.conf 设置DNS服务器
nameserver 192.168.37.2 

# 境内公共DNS
114.114.114.114
114.114.115.115
阿里DNS: 223.5.5.5, 223.6.6.6
百度DNS: 180.76.76.76
腾讯DNS: 119.29.29.29, 182.254.116.116

# 境外公共DNS
Cloudflare & APNIC: 1.1.1.1, 1.0.0.1
谷歌DNS: 8.8.8.8, 8.8.4.4
OpenDNS: 208.67.222.222, 208.67.220.220
微软DNS: 4.2.2.1, 4.2.2.2
```

## 主动收集
```
# Active Recon：和目标主动接触，端口扫描，漏洞扫描，Web扫描

# Generally speaking, when we don’t get a ping reply back, there are a few explanations that would explain why we didn’t get a ping reply, for example:
# 1、The destination computer is not responsive; possibly still booting up or turned off, or the OS has crashed.
# 2、It is unplugged from the network, or there is a faulty network device across the path.
# 3、A firewall is configured to block such packets. The firewall might be a piece of software running on the system itself or a separate network appliance. Note that MS Windows firewall blocks ping by default.
# 4、Your system is unplugged from the network.

$ ping [options] <destination>
Options:
  <destination>      DNS name or IP address
  -a                 use audible ping
  -A                 use adaptive ping
  -B                 sticky source address
  -c <count>         stop after <count> replies
  -C                 call connect() syscall on socket creation
  -D                 print timestamps
  -d                 use SO_DEBUG socket option
  -e <identifier>    define identifier for ping session, default is random for
                     SOCK_RAW and kernel defined for SOCK_DGRAM
                     Imply using SOCK_RAW (for IPv4 only for identifier 0)
  -f                 flood ping
  -h                 print help and exit
  -H                 force reverse DNS name resolution (useful for numeric
                     destinations or for -f), override -n
  -I <interface>     either interface name or address
  -i <interval>      seconds between sending each packet
  -L                 suppress loopback of multicast packets
  -l <preload>       send <preload> number of packages while waiting replies
  -m <mark>          tag the packets going out
  -M <pmtud opt>     define path MTU discovery, can be one of <do|dont|want|probe>
  -n                 no reverse DNS name resolution, override -H
  -O                 report outstanding replies
  -p <pattern>       contents of padding byte
  -q                 quiet output
  -Q <tclass>        use quality of service <tclass> bits
  -s <size>          use <size> as number of data bytes to be sent
  -S <size>          use <size> as SO_SNDBUF socket option value
  -t <ttl>           define time to live
  -U                 print user-to-user latency
  -v                 verbose output
  -V                 print version and exit
  -w <deadline>      reply wait <deadline> in seconds
  -W <timeout>       time to wait for response
IPv4 options:
  -4                 use IPv4
  -b                 allow pinging broadcast
  -R                 record route
  -T <timestamp>     define timestamp, can be one of <tsonly|tsandaddr|tsprespec>
IPv6 options:
  -6                 use IPv6
  -F <flowlabel>     define flow label, default is random
  -N <nodeinfo opt>  use IPv6 node info query, try <help> as argument

$ telnet
Usage: telnet [OPTION...] [HOST [PORT]]
Login to remote system HOST (optionally, on service port PORT)

 General options:

  -4, --ipv4                 use only IPv4
  -6, --ipv6                 use only IPv6
  -8, --binary               use an 8-bit data transmission
  -a, --login                attempt automatic login
  -b, --bind=ADDRESS         bind to specific local ADDRESS
  -c, --no-rc                do not read the user's .telnetrc file
  -d, --debug                turn on debugging
  -e, --escape=CHAR          use CHAR as an escape character
  -E, --no-escape            use no escape character
  -K, --no-login             do not automatically login to the remote system
  -l, --user=USER            attempt automatic login as USER
  -L, --binary-output        use an 8-bit data transmission for output only
  -n, --trace=FILE           record trace information into FILE
  -r, --rlogin               use a user-interface similar to rlogin

 Encryption control:

  -x, --encrypt              encrypt the data stream, if possible

 Authentication and Kerberos options:

  -k, --realm=REALM          obtain tickets for the remote host in REALM
                             instead of the remote host's realm
  -X, --disable-auth=ATYPE   disable type ATYPE authentication

  -?, --help                 give this help list
      --usage                give a short usage message
  -V, --version              print program version

Mandatory or optional arguments to long options are also mandatory or optional
for any corresponding short options.

$ nc 
connect to somewhere:   nc [-options] hostname port[s] [ports] ... 
listen for inbound:     nc -l -p port [-options] [hostname] [port]
options:
        -c shell commands       as `-e'; use /bin/sh to exec [dangerous!!]
        -e filename             program to exec after connect [dangerous!!]
        -b                      allow broadcasts
        -g gateway              source-routing hop point[s], up to 8
        -G num                  source-routing pointer: 4, 8, 12, ...
        -h                      this cruft
        -i secs                 delay interval for lines sent, ports scanned
        -k                      set keepalive option on socket
        -l                      listen mode, for inbound connects
        -n                      numeric-only IP addresses, no DNS
        -o file                 hex dump of traffic
        -p port                 local port number
        -r                      randomize local and remote ports
        -q secs                 quit after EOF on stdin and delay of secs
        -s addr                 local source address
        -T tos                  set Type Of Service
        -t                      answer TELNET negotiation
        -u                      UDP mode
        -v                      verbose [use twice to be more verbose]
        -w secs                 timeout for connects and final net reads
        -C                      Send CRLF as line-ending
        -z                      zero-I/O mode [used for scanning]
port numbers can be individual or ranges: lo-hi [inclusive];
hyphens in port names must be backslash escaped (e.g. 'ftp\-data').

# if the TTL reaches 0, it will be dropped, and an ICMP Time-to-Live exceeded would be sent to the original sender. Note that some routers are configured not to send such ICMP messages when discarding a packet.
$ traceroute/tracert
traceroute [ -46dFITnreAUDV ] [ -f first_ttl ] [ -g gate,... ] [ -i device ] [ -m max_ttl ] [ -N squeries ] [ -p port ] [ -t tos ] [ -l flow_label ] [ -w MAX,HERE,NEAR ] [ -q nqueries ] [ -s src_addr ] [ -z sendwait ] [ --fwmark=num ] host [ packetlen ]
Options:
  -4                          Use IPv4
  -6                          Use IPv6
  -d  --debug                 Enable socket level debugging
  -F  --dont-fragment         Do not fragment packets
  -f first_ttl  --first=first_ttl
                              Start from the first_ttl hop (instead from 1)
  -g gate,...  --gateway=gate,...
                              Route packets through the specified gateway
                              (maximum 8 for IPv4 and 127 for IPv6)
  -I  --icmp                  Use ICMP ECHO for tracerouting
  -T  --tcp                   Use TCP SYN for tracerouting (default port is 80)
  -i device  --interface=device
                              Specify a network interface to operate with
  -m max_ttl  --max-hops=max_ttl
                              Set the max number of hops (max TTL to be
                              reached). Default is 30
  -N squeries  --sim-queries=squeries
                              Set the number of probes to be tried
                              simultaneously (default is 16)
  -n                          Do not resolve IP addresses to their domain names
  -p port  --port=port        Set the destination port to use. It is either
                              initial udp port value for "default" method
                              (incremented by each probe, default is 33434), or
                              initial seq for "icmp" (incremented as well,
                              default from 1), or some constant destination
                              port for other methods (with default of 80 for
                              "tcp", 53 for "udp", etc.)
  -t tos  --tos=tos           Set the TOS (IPv4 type of service) or TC (IPv6
                              traffic class) value for outgoing packets
  -l flow_label  --flowlabel=flow_label
                              Use specified flow_label for IPv6 packets
  -w MAX,HERE,NEAR  --wait=MAX,HERE,NEAR
                              Wait for a probe no more than HERE (default 3)
                              times longer than a response from the same hop,
                              or no more than NEAR (default 10) times than some
                              next hop, or MAX (default 5.0) seconds (float
                              point values allowed too)
  -q nqueries  --queries=nqueries
                              Set the number of probes per each hop. Default is
                              3
  -r                          Bypass the normal routing and send directly to a
                              host on an attached network
  -s src_addr  --source=src_addr
                              Use source src_addr for outgoing packets
  -z sendwait  --sendwait=sendwait
                              Minimal time interval between probes (default 0).
                              If the value is more than 10, then it specifies a
                              number in milliseconds, else it is a number of
                              seconds (float point values allowed too)
  -e  --extensions            Show ICMP extensions (if present), including MPLS
  -A  --as-path-lookups       Perform AS path lookups in routing registries and
                              print results directly after the corresponding
                              addresses
  -M name  --module=name      Use specified module (either builtin or external)
                              for traceroute operations. Most methods have
                              their shortcuts (`-I' means `-M icmp' etc.)
  -O OPTS,...  --options=OPTS,...
                              Use module-specific option OPTS for the
                              traceroute module. Several OPTS allowed,
                              separated by comma. If OPTS is "help", print info
                              about available options
  --sport=num                 Use source port num for outgoing packets. Implies
                              `-N 1'
  --fwmark=num                Set firewall mark for outgoing packets
  -U  --udp                   Use UDP to particular port for tracerouting
                              (instead of increasing the port per each probe),
                              default port is 53
  -UL                         Use UDPLITE for tracerouting (default dest port
                              is 53)
  -D  --dccp                  Use DCCP Request for tracerouting (default port
                              is 33434)
  -P prot  --protocol=prot    Use raw packet of protocol prot for tracerouting
  --mtu                       Discover MTU along the path being traced. Implies
                              `-F -N 1'
  --back                      Guess the number of hops in the backward path and
                              print if it differs
  -V  --version               Print version info and exit
  --help                      Read this help and exit

Arguments:
+     host          The host to traceroute to
      packetlen     The full packet length (default is the length of an IP
                    header plus 40). Can be ignored or increased to a minimal
                    allowed value       
                    
user@AttackBox$ traceroute tryhackme.com
traceroute to tryhackme.com (172.67.69.208), 30 hops max, 60 byte packets
# traceroute 每次发3个包，TTL=1，2，3，4，5，6，7。。。 每行一个路由器
# 有一个路由器没有发回包ICMP Time-to-Live exceeded message
 1  ec2-3-248-240-5.eu-west-1.compute.amazonaws.com (3.248.240.5)  2.663 ms * ec2-3-248-240-13.eu-west-1.compute.amazonaws.com (3.248.240.13)  7.468 ms
 2  100.66.8.86 (100.66.8.86)  43.231 ms 100.65.21.64 (100.65.21.64)  18.886 ms 100.65.22.160 (100.65.22.160)  14.556 ms
 # *表示没有收到剩下的2个ICMP Time-to-Live exceeded message
 3  * 100.66.16.176 (100.66.16.176)  8.006 ms *
 4  100.66.11.34 (100.66.11.34)  17.401 ms 100.66.10.14 (100.66.10.14)  23.614 ms 100.66.19.236 (100.66.19.236)  17.524 ms
 5  100.66.7.35 (100.66.7.35)  12.808 ms 100.66.6.109 (100.66.6.109)  14.791 ms *
 6  100.65.14.131 (100.65.14.131)  1.026 ms 100.66.5.189 (100.66.5.189)  19.246 ms 100.66.5.243 (100.66.5.243)  19.805 ms
 7  100.65.13.143 (100.65.13.143)  14.254 ms 100.95.18.131 (100.95.18.131)  0.944 ms 100.95.18.129 (100.95.18.129)  0.778 ms
 8  100.95.2.143 (100.95.2.143)  0.680 ms 100.100.4.46 (100.100.4.46)  1.392 ms 100.95.18.143 (100.95.18.143)  0.878 ms
 9  100.100.20.76 (100.100.20.76)  7.819 ms 100.92.11.36 (100.92.11.36)  18.669 ms 100.100.20.26 (100.100.20.26)  0.842 ms
10  100.92.11.112 (100.92.11.112)  17.852 ms * 100.92.11.158 (100.92.11.158)  16.687 ms
11  100.92.211.82 (100.92.211.82)  19.713 ms 100.92.0.126 (100.92.0.126)  18.603 ms 52.93.112.182 (52.93.112.182)  17.738 ms
# 99.83.69.207路由器发回3个ICMP Time-to-Live exceeded message
12  99.83.69.207 (99.83.69.207)  17.603 ms  15.827 ms  17.351 ms
13  100.92.9.83 (100.92.9.83)  17.894 ms 100.92.79.136 (100.92.79.136)  21.250 ms 100.92.9.118 (100.92.9.118)  18.166 ms
# 172.67.69.208是最后一个路由器
14  172.67.69.208 (172.67.69.208)  17.976 ms  16.945 ms 100.92.9.3 (100.92.9.3)  17.709 ms

# To summarize, we can notice the following:
The number of hops/routers between your system and the target system depends on the time you are running traceroute. There is no guarantee that your packets will always follow the same route, even if you are on the same network or you repeat the traceroute command within a short time.
Some routers return a public IP address. You might examine a few of these routers based on the scope of the intended penetration testing.
Some routers don’t return a reply.
                                                                                                                                                                                                                                                                                                                                       
$ nmap

$ browser
- FoxyProxy：切换代理，https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/
- User-Agent Switcher：伪造User Agent，https://addons.mozilla.org/en-US/firefox/addon/user-agent-string-switcher/
- Wappalyzer：检查建站技术，https://addons.mozilla.org/en-US/firefox/addon/wappalyzer/
```

## DNS
```
# TLD (Top-Level Domain)
A TLD is the most righthand part of a domain name. So, for example, the tryhackme.com TLD is .com. There are two types of TLD, gTLD (Generic Top Level) and ccTLD (Country Code Top Level Domain). Historically a gTLD was meant to tell the user the domain name's purpose; for example, a .com would be for commercial purposes, .org for an organisation, .edu for education and .gov for government. And a ccTLD was used for geographical purposes, for example, .ca for sites based in Canada, .co.uk for sites based in the United Kingdom and so on. Due to such demand, there is an influx of new gTLDs ranging from .online , .club , .website , .biz and so many more. For a full list of over 2000 TLDs click here.
https://data.iana.org/TLD/tlds-alpha-by-domain.txt

# Second-Level Domain
Taking tryhackme.com as an example, the .com part is the TLD, and tryhackme is the Second Level Domain. When registering a domain name, the second-level domain is limited to 63 characters + the TLD and can only use a-z 0-9 and hyphens (cannot start or end with hyphens or have consecutive hyphens).

# Subdomain
A subdomain sits on the left-hand side of the Second-Level Domain using a period to separate it; for example, in the name admin.tryhackme.com the admin part is the subdomain. A subdomain name has the same creation restrictions as a Second-Level Domain, being limited to 63 characters and can only use a-z 0-9 and hyphens (cannot start or end with hyphens or have consecutive hyphens). You can use multiple subdomains split with periods to create longer names, such as jupiter.servers.tryhackme.com. But the length must be kept to 253 characters or less. There is no limit to the number of subdomains you can create for your domain name.

# 整个域名最长253个字符，Second-Level Domain 和 每个subdomain都小于63个字符

# DNS Record Types
DNS isn't just for websites though, and multiple types of DNS record exist. We'll go over some of the most common ones that you're likely to come across.

# A Record
These records resolve to IPv4 addresses, for example 104.26.10.229

# AAAA Record
These records resolve to IPv6 addresses, for example 2606:4700:20::681a:be5

# CNAME Record
These records resolve to another domain name, for example, TryHackMe's online shop has the subdomain name store.tryhackme.com which returns a CNAME record shops.shopify.com. Another DNS request would then be made to shops.shopify.com to work out the IP address.

# MX Record
These records resolve to the address of the servers that handle the email for the domain you are querying, for example an MX record response for tryhackme.com would look something like alt1.aspmx.l.google.com. These records also come with a priority flag. This tells the client in which order to try the servers, this is perfect for if the main server goes down and email needs to be sent to a backup server.

# TXT Record
TXT records are free text fields where any text-based data can be stored. TXT records have multiple uses, but some common ones can be to list servers that have the authority to send an email on behalf of the domain (this can help in the battle against spam and spoofed email). They can also be used to verify ownership of the domain name when signing up for third party services.

# What happens when you make a DNS request

### When you request a domain name, your computer first checks its local cache to see if you've previously looked up the address recently; if not, a request to your Recursive DNS Server will be made.

### A Recursive DNS Server is usually provided by your ISP, but you can also choose your own. This server also has a local cache of recently looked up domain names. If a result is found locally, this is sent back to your computer, and your request ends here (this is common for popular and heavily requested services such as Google, Facebook, Twitter). If the request cannot be found locally, a journey begins to find the correct answer, starting with the internet's root DNS servers.

### The root servers act as the DNS backbone of the internet; their job is to redirect you to the correct Top Level Domain Server, depending on your request. If, for example, you request www.tryhackme.com, the root server will recognise the Top Level Domain of .com and refer you to the correct TLD server that deals with .com addresses.

### The TLD server holds records for where to find the authoritative server to answer the DNS request. The authoritative server is often also known as the nameserver for the domain. For example, the name server for tryhackme.com is kip.ns.cloudflare.com and uma.ns.cloudflare.com. You'll often find multiple nameservers for a domain name to act as a backup in case one goes down.

### An authoritative DNS server is the server that is responsible for storing the DNS records for a particular domain name and where any updates to your domain name DNS records would be made. Depending on the record type, the DNS record is then sent back to the Recursive DNS Server, where a local copy will be cached for future requests and then relayed back to the original client that made the request. DNS records all come with a TTL (Time To Live) value. This value is a number represented in seconds that the response should be saved for locally until you have to look it up again. Caching saves on having to make a DNS request every time you communicate with a server.
```

## 方法
```
* 查IP
* 查域名
* 查证书
1、备案信息，天眼查，爱企查(社工)，
2、SEO综合查询：https://seo.chinaz.com/
3、whois信息：https://whois.chinaz.com/
4、IP反查：https://tool.chinaz.com/same，fofa，hunter
5、子域名：fofa，hunter，oneforall，LayerDomainFinder
6、CDN：多点ping，ping邮件服务器、分站域名，或从国外访问，查找域名解析记录如DNSdumpster；DoS耗光CDN流量会暴露真实IP
7、测绘引擎：IP，域名，title，图标，备案号
8、SSL证书：censys，cloudflair
9、信息泄露：phpinfo，test，压缩包，.hg，.svn，Web.xml，隐藏API如swagger
10、github搜索
11、加入目标公司的QQ，微信工作群收集信息
```

## 工具
```
灯塔：https://tophanttechnology.github.io/ARL-doc/
FOFA：https://fofa.info/
Hunter：https://hunter.qianxin.com/
水泽：https://github.com/0x727/ShuiZe_0x727
OneForAll：https://github.com/shmilylty/OneForAll
LayerDomainFinder：https://github.com/euphrat1ca/LayerDomainFinder
omnisci3nt：https://github.com/spyboy-productions/omnisci3nt.git
masscan：https://github.com/robertdavidgraham/masscan # 发包少，安全
数字观星：https://fp.shuziguanxing.com/ # 探测服务
API发现靶场：https://xz.aliyun.com/t/11734?time__1311=mqmx0DBDc7qiwq0vo4%2BxCqFxjEF5DuGW6oD
```

## 参考资料
```
https://blog.csdn.net/weixin_65527369/article/details/130661462?spm=1001.2014.3001.5502
https://xu-an.gitbook.io/sec/how/fofa
https://go.wgpsec.org/
```

## 实战

### 攻击面资产收集
```
使用网络空间测绘引擎，如 Fofa，Hunter，https://search.censys.io 对目标单位进行域名、IP、指纹信息获取等；
使用自动化漏洞工具对已有资产进行漏洞探测、漏洞利用等；
使用企业查询网站，对目标单位的上下级公司进行梳理，以获取更多的资产信息。
```

### 打点 GetShell
```
借助 Github 对目标单位进行信息收集，再结合中英文公司名称、简称、域名等以及收集到的信息，总结规律并组成字典，通过 Exchange 邮服接口爆破目标邮箱，进而获取弱口令邮箱用户；
尝试利用邮箱口令对 VPN 进行登录，发现存在动态令牌等双因素验证措施，但部分用户未绑定令牌（未使用过VPN），直接进行绑定使用，从而获得 VPN 入口权限。
```

### 内网探测渗透
```
基于 VPN 网络，针对内网进行信息收集、资产探测、口令猜解等；
通过常规设备通用口令获得华为 IBMC 设备权限；
通过弱口令猜解获得 Linux 服务器权限；
进一步基于已有服务器权限进行代理穿透与网络探测，尝试发现更多内网资产；
最终在一台 Linux 服务器上搭建代理，突破隔离进入下一层网络，可访问多个 B 段。
```

### 据点权限维持
```
通过系统信息、人员邮件、内部 Wiki 等方式，排摸内网存在的防护措施，发现内网及云上主机存在 EDR 等安全防护产品，敏感操作如：命令执行、爆破、隧道搭建等，会触发告警；
基于多种工具及协议，结合内网存在的防护措施进行针对性改造，如免杀、流量特征修改、云函数等，在内网不同环境绕过防护措施，建立据点并留存后门，加大防守方发现及处置难度。
```

### 内网横向移动
```
进一步利用口令爆破，获得数据库权限，在数据库中能够获得大量业务敏感信息；
通过数据库口令，获取 SQLSERVER 的服务器权限，之后利用土豆提权操作获取该服务器 Administrator 口令；
基于第二步获取到的 Administrator 口令以及之前的邮箱弱口令，组合形成新的字典，进一步爆破 RDP 口令，从而获得 Windows 服务器权限；
继续横向渗透，从 Windows 服务器中发现到域控凭证信息，经过 PTH 操作后取得域控权限（管理域内机器近万余台）。
```

### 获取重点目标
```
在域控上 Dump 所有密码，收集用户登录 IP 以及 Hash 、明文凭证，寻找重点用户，如运维、开发机器等，尝试以重点用户为基础进行横向，发现更多业务资产信息；
对终端机进行数据分析，获取口令等敏感信息，进而横向移动。
```

###  获取核心靶标
```
通过域用户凭证信息并结合先前收集的 Web 应用后台进一步尝试登录，获得各类 Web 应用系统权限，包括目标单位核心业务系统等；
通过登录重要人员的云盘，查阅资料，获取邮件服务器、邮件网关权限；
进一步对重要人员的 Wiki 信息收集，获取靶标服务器相关信息，通过口令成功获取靶标服务器权限。
```