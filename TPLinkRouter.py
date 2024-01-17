import hassapi as hass

import base64
import binascii
import hashlib
import json
import logging
import re
import requests
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA

# TP-Link Python API

# commands used 
EVENT = "TPlinkRouter"

_ON = "ON"
_OFF = "OFF"
RESET_ROUTER = "ResetRouter"

RESET_ROUTER_LINK = "/admin/system?form=reboot"
RESET_ROUTER_NOW = b"operation=write"

ACCESS_CONTROL = "AccessControl"
ACCESS_CONTROL_LINK = "/admin/access_control?form=enable"
ENABLE_ACCESS_CONTROL_ON = b"operation=write&enable=on"
ENABLE_ACCESS_CONTROL_OFF = b"operation=write&enable=off"

LOGOUT_LINK = "/admin/system?form=logout"
LOGOUT_COMMAND = b"operation=write"


class TPLinkRouterAPI(hass.Hass):
    def initialize(self):
        # get a requests session
        self.session = requests.Session()

        self.host = self.args["host"]
        self.password = self.args["password"]

        #create button for home assistant - when pressed, this will reset the router
        if not self.entity_exists("button.reset_TPLINK_router"):
            self.set_state("button.reset_TPLINK_router", state = "off", attributes = {"id": "reset_TPLINK_router"})
        
        self.listen_event(self._callback, EVENT)
        self.log ("TP-Link router Appdaemon running... Awaiting EVENT")
        
        self.listen_event(self._callbackResetRouter, event = "call_service")
        
        
    def _callback (self, event_name, data, kwargs):
        # Check if we need to login. Call read opereation, if successful, login not necessary.
        try:
            ep = "/admin/status?form=all"
            ret = self.send_encrypted_command(b"operation=read", ep)
        except:
            print("Need to log in first...")
            self.prelogin()
            ep = "/admin/status?form=all"
            ret = self.send_encrypted_command(b"operation=read", ep)
        
        # Check command and action
        self.action = data.get("action")
        command = data.get("command")
        
        if command == ACCESS_CONTROL:
            self.access_control ()
        
        print (switcher.get (command))
        
        self.log ("Logging out... ")
        print (self.send_encrypted_command(LOGOUT_COMMAND, LOGOUT_LINK))
        
        return

    def _callbackResetRouter (self, event_name, data, kwargs):
        # callback to reset router. First check if entity is button.reset router, then act
        entity_id = data.get("service_data").get("entity_id", None)
        self.log(entity_id)
        if entity_id != "button.reset_tplink_router":
            self.log("Not resetting router")
            return
        # now reset router
        self.log ("Router will be reset now")
        
        # Check if we need to login. Call read opereation, if successful, login not necessary.
        self.check_login_status()
        
        ret = self.send_encrypted_command(RESET_ROUTER_NOW, RESET_ROUTER_LINK)
        self.log("************************")
        return
    
    def default (self):
        return self.send_encrypted_command(b"operation=read", "/admin/status?form=all")
        
    def access_control (self):
        # now switch on access control
        self.log ("Access control will be set to: " + self.action)
        if self.action == _ON:
            ret = self.send_encrypted_command(ENABLE_ACCESS_CONTROL_ON, ACCESS_CONTROL_LINK)
        elif self.action == _OFF:
            ret = self.send_encrypted_command(ENABLE_ACCESS_CONTROL_OFF, ACCESS_CONTROL_LINK)
        self.log("************************")
        self.log(ret)
        self.log("************************")
        return ret


    def check_login_status (self):
        try:
            ep = "/admin/status?form=all"
            ret = self.send_encrypted_command(b"operation=read", ep)
        except:
            print("Need to log in first...")
            self.prelogin()
            ep = "/admin/status?form=all"
            ret = self.send_encrypted_command(b"operation=read", ep)
        
        return
        
        
    def prelogin (self):
        # setup crypto
        self.init_aes()
        
        # build the username/password hash
        h = hashlib.md5()
        h.update(b"admin%s" % self.password.encode())

        # build the signature string
        self.init_rsa()
        self.sig_base = b"k=%s&i=%s&h=%s&s=" % (self.aes_key, self.aes_iv, h.hexdigest().encode())

        # login
        self.stok = ""
        self.login()
        return

    def decrypt_aes(self, ciphertext):
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv=self.aes_iv)
        plaintext = cipher.decrypt(ciphertext)
        return plaintext

    def encrypt_aes(self, plaintext):
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv=self.aes_iv)
        ciphertext = cipher.encrypt(plaintext)
        return ciphertext

    def get_signature(self, datalen):
        # plaintext signature string
        ss = b"%s%d" % (self.sig_base, (self.seq+datalen))

        # encrypt using the 512-bit public key
        sig = b""
        for x in range(0, len(ss), 53):
            chunk = ss[x:x+53]
            sig += self.sig_cipher.encrypt(ss[x:x+53])
        sig = binascii.hexlify(sig)
        return sig

    def send_encrypted_command(self, cmd, url):
        # encrypt the command (AES) and then base64-encode
        pc = chr(16 - (len(cmd) % 16))
        while len(cmd) % 16 != 0:
            cmd += pc.encode()
        cmd = self.encrypt_aes(cmd)
        cmd = base64.b64encode(cmd)

        # get the signature for the current sequence number
        sig = self.get_signature(len(cmd))

        # build the POST data
        post_data = { "sign": sig, "data": cmd }
        
        # send the request
        res = self.session.post("http://%s/cgi-bin/luci/;stok=%s%s" % (self.host, self.stok, url), data=post_data)

        # parse and decrypt the response
        data = json.loads(res.content)
        #print (data)
        data_raw = base64.b64decode(data["data"])
        data = self.decrypt_aes(data_raw)
        print (data)
        if data[-1] < 16:
            data = data[:-data[-1]]
        data = json.loads(data)

        return data

    def login(self):
        # build the login command and encrypt with AES
        login_cmd = b"password=%s&operation=login" % binascii.hexlify(self.enc_cipher.encrypt(self.password.encode()))
        
        # send the command
        data = self.send_encrypted_command(login_cmd, "/login?form=login")

        # process the response
        if data["success"] != True:
            raise Exception("Login failure!")
        self.stok = data["data"]["stok"]
        logging.info("Logged in successfully!")

    def init_rsa(self, enc_priv=None, sig_priv=None):
        # request the signature public key and sequence number
        url = "http://%s/cgi-bin/luci/;stok=/login?form=auth" % self.host
        res = self.session.post(url, data={"operation":"read"})
        data = json.loads(res.content)
        self.sig_pub = int.from_bytes(binascii.unhexlify(data["data"]["key"][0]), "big")
        self.seq = data["data"]["seq"]
        
        # request the data public key
        url = "http://%s/cgi-bin/luci/;stok=/login?form=keys" % self.host
        res = self.session.post(url, data={"operation":"read"})
        data = json.loads(res.content)
        self.enc_pub = int.from_bytes(binascii.unhexlify(data["data"]["password"][0]), "big")
                
        # setup the data cipher
        self.enc_key = RSA.construct((self.enc_pub, 65537))
        if enc_priv is not None:
            self.enc_priv = enc_priv
            self.enc_key = RSA.construct((self.enc_pub, 65537, self.enc_priv))
        self.enc_cipher = PKCS1_v1_5.new(self.enc_key)        

        # setup the signature cipher
        self.sig_key = RSA.construct((self.sig_pub, 65537))
        #print (self.sig_key)
        if sig_priv is not None:
            self.sig_key = RSA.construct((self.sig_pub, 65537, sig_priv))
        self.sig_cipher = PKCS1_v1_5.new(self.sig_key)

    def init_aes(self):
        self.aes_key =  b'1640278231266107' 
        self.aes_iv = b'1640278231266253'

        # setup the cipher
        self.aes_cipher = AES.new(self.aes_key, AES.MODE_CBC, iv=self.aes_iv)

        
