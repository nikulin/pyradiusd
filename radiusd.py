#!/usr/bin/env python
#*- coding: utf-8 -*

import logging
import six
import sys
import SocketServer
from StringIO import StringIO
from pyrad import tools, dictionary
from pyrad.packet import AuthPacket, AccessRequest, AccessAccept, AccessReject

DICTIONARY = u'''
ATTRIBUTE User-Name 1 string
ATTRIBUTE User-Password 2 string encrypt=1
ATTRIBUTE NAS-Identifier 32 string
'''

NAS_SECRET = 'put CORRECT radius_secret from your config file here'
USERS = {
    'superuser': 'resurepus068',
    'admin': 'nimda955',
    'editor': 'rotide395',
    'guest': 'tseug164',
}


def getLogger(name, logfile, level=logging.INFO):
    formatter = logging.Formatter('%(name)-12s %(asctime)s %(levelname)-8s %(message)s', '%a, %d %b %Y %H:%M:%S',)
    logger = logging.getLogger(name)
    logger.setLevel(level)
    file_handler = logging.FileHandler(logfile)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    if level == logging.DEBUG:
        stream_handler = logging.StreamHandler(sys.stderr)
        logger.addHandler(stream_handler)
    return logger


radiuslog = getLogger("radius", "radius.log", level=logging.INFO)
class AuthPacket2(AuthPacket):
    def __init__(self, code=AccessRequest, id=None, secret=six.b(''), authenticator=None, **attributes):
        AuthPacket.__init__(self, code, id, secret, authenticator, **attributes)

    def CreateReply(self, msg=None, **attributes):
        reply = AuthPacket2(AccessAccept, self.id, self.secret, self.authenticator, dict=self.dict, **attributes)
        if msg:
            reply.set_reply_msg(tools.EncodeString(msg))
        return reply

    def set_reply_msg(self, msg):
        if msg:
            self.AddAttribute(18, msg)

    def get_username(self):
        try:
            return tools.DecodeString(self.get(1)[0])
        except:
            return None

    def get_passwd(self):
        try:
            return self.PwDecrypt(self.get(2)[0])
        except:
            return None

    def get_realm(self):
        try:
            return tools.DecodeString(self.get(32)[0])
        except:
            return None


class UDPHandler(SocketServer.DatagramRequestHandler):
    """
    This class works similar to the TCP handler class, except that
    self.request consists of a pair of data and client socket, and since
    there is no connection the client address must be given explicitly
    when sending data back via sendto().
    """

    def send_reject(self, req, socket, err):
        reply = req.CreateReply(msg=err)
        reply.code = AccessReject
        socket.sendto(reply.ReplyPacket(), self.client_address)
        radiuslog.error("[Auth]  send an authentication reject,err: %s" % err)

    def send_accept(self, req, socket, **args):
        reply = req.CreateReply()
        reply.code = AccessAccept
        socket.sendto(reply.ReplyPacket(), self.client_address)
        radiuslog.debug("[Auth] send an authentication accept,user[%s],nas[%s]" % (req.get_username(), req.get_realm()))

    def handle(self):
        try:
            data = self.request[0].strip()
            socket = self.request[1]
            dict = dictionary.Dictionary(StringIO(DICTIONARY))
            pkt = AuthPacket2(packet=data, dict=dict, secret=NAS_SECRET)
            username, password, realm = pkt.get_username(), pkt.get_passwd(), pkt.get_realm()
            if not (username in USERS and USERS[username] == password and realm.startswith("adm")):
                raise Exception('No user found or Login denied')
            self.send_accept(pkt, socket)
        except Exception, e:
            radiuslog.debug('ERROR: {0}'.format(e))
            radiuslog.debug("PACKET: {0}".format(pkt))
            self.send_reject(pkt, socket, str(e))


if __name__ == "__main__":
    HOST, PORT = "", 1812
    server = SocketServer.UDPServer((HOST, PORT), UDPHandler)

    print "serving at port", PORT
    server.serve_forever()

