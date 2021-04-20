# Port_Authority
Blocks websites from using javascript to port scan your computer/network and dynamically blocks all LexisNexis endpoints from running their invasive data collection scripts.

| | | |
|:-------------------------:|:-------------------------:|:-------------------------:|
|<img width="1604" alt="Ebay" src="https://user-images.githubusercontent.com/60232273/115321775-85da5280-a152-11eb-9ab3-8ce13e13a73a.png">  Ebay attempting to run ThreatMetrix scripts but being blocked by Port Authority. |  <img width="1604" alt="Chick Fil A" src="https://user-images.githubusercontent.com/60232273/115321756-7c50ea80-a152-11eb-9b11-107d08b20d6c.png"> If you go to the sign-in page on chick-fil-a.com and temporarily disable uBlockOrigin you will see chick fil a trying to port scan your computer through web sockets. |<img width="1604" alt="Discord" src="https://user-images.githubusercontent.com/60232273/115321767-7fe47180-a152-11eb-89d1-d3aaab669dfe.png"> Discord port scanning your computer trying to connect with the desktop Discord app.|

----
## What does this addon do?
1. Blocks all possible types of port scanning (HTTP/HTTPS/WS/WSS/FTP/FTPS)
2. Dynamically blocks the ThreatMetrix tracking scripts made by one of the largest and least ethical data brokers in the world (Lexis Nexis)
3. Gives a nice notification when one of the above scenerios are blocked :)
4. This addon doesn't store/transmit any data or metadata about you or your requests... because ya know privacy

## Regex Explination
- Explination of the regex used to determine local addresses: https://regex101.com/r/DOPCdB/15
- Explination of the regex which is used to match the protocol: https://regex101.com/r/f8LSTx/2

## Test HTTP / HTTPS Portscanning
- Site where you can test if HTTP port scanning works: https://defuse.ca/in-browser-port-scanning.htm
- Click CTRL + Shift + I to see the networking tab where the blocked port scans will be shown.

## Test Websocket Portscanning
- Site where you can test if WebSocket port scanning works: http://frontend-overflowstack.com/
- Click CTRL + Shift + I to see the networking tab where the blocked port scans will be shown.

## Test sites that port scan you or otherwise run ThreatMetrix scripts (Wall of Shame!)
- https://signin.ebay.com
- https://login.my.chick-fil-a.com
- https://bestbuy.com/identity/signin
- https://dazn.com/en-US/account/signin
- https://login.globalsources.com
- https://auth.bitbay.net/login
- https://login.mahix.org
- https://marcus.com/us/en/login
- The full list of endpoints can be found [HERE](https://gist.github.com/ACK-J/65dfe84fcf5a06c46364e5f2bd29c118).

## Permissions Needed
**Display notifications to you**
- This is needed so the addon can alert you when a malicious scripts is blocked or javascrpt port scanning is blocked.
**Access browser tabs**
- This is needed so the addon can display the proper number of blocked requests on a per-tab basis.
**Access your data for all websites**
- This is needed because the addon needs to check every request your browser makes to determine if it needs to be blocked.

## Why I wrote this addon?
I was intrigued back in May of 2020 when eBay got caught port scanning their customers. I noticed that all of the articles covering this topic mentioned that there was nothing you could do to prevent it... so I wanted to make one. After going down many rabbit holes, I found that this script which was port scanning everyone is, in my opinion, malware.

**Here's why I think that:**
- The data being exfiled from your computer is encrypted into an image with XOR.
- The domain it reaches out to is made to look legitimate, but redirects using a CNAME record to Lexis Nexis' servers.
- It can determine your real IP address even if you are using a VPN / Proxy [HERE](https://risk.lexisnexis.com/global/en/products/threatmetrix).
- The javascript is assembled via string.join (like malware often does) and then executed in a service worker.
- Each time you load the page the javascript is re-obfuscated.
- The script collects 416 pieces of personally identifiable information about you and your network. ( Shown [HERE](https://gist.github.com/ACK-J/aa8dceb072d31d97a4e7fe0ef389f370) )

So I developed multiple ways to stop this. The first being the existing functionality built into Port Authority. By default, Port Authority will check the sites that your browser reaches out to and if it redirects to Lexis Nexis' infrastructure, it will be blocked and you will receive a notification. The second is a Python script I wrote which uses Shodan to find all of Lexis Nexis' customer-specific domains on the internet [HERE](https://gist.github.com/ACK-J/7a2da401c732cbe58479d03acc4e4b43). You can add the output of the script to a blocker such as uBlockOrigin to prevent your computer from connecting to them.

**Note:** This second method will never include every customer-specific endpoint so you are better off using the dynamic blocking built into Port Authority which WILL block every single customer-specific endpoint Lexis Nexis uses.

Most of these sites are using Lexis Nexis's Threat Metrix scripts, Dan Nemec has a great blog post reverse engineering the script and showing all the invasive data collected https://blog.nem.ec/2020/05/24/ebay-port-scanning/
