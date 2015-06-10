#!/usr/bin/env python2.7
#*- coding: utf-8 -*

import os

assert "DJANGO_SETTINGS_MODULE" in os.environ, "Need DJANGO_SETTINGS_MODULE environment variable"

import argparse
import logging
import six
import sys
import SocketServer
from StringIO import StringIO
from pyrad import tools, dictionary
from pyrad.packet import AuthPacket, AccessRequest, AccessAccept, AccessReject
from django.conf import settings
from django.contrib.auth import authenticate

nas_secret, log_file, debug = None, 'radius.log', False

parser = argparse.ArgumentParser(description='Simple RADIUS server')
parser.add_argument( '-l', '--log', type=str, dest='log_file', help='log file')
parser.add_argument( '-s', '--secret', type=str, dest='nas_secret', help='RADIUS secret')
parser.add_argument( '--debug', action='store_true', dest='debug', help='run in debug mode')
args = vars(parser.parse_args())

if not nas_secret:
    assert settings.RADIUS_SECRET, "RADIUS_SECRET should be present in settings file or in args"
    nas_secret = settings.RADIUS_SECRET

INSTALLED_APPS = ('django.contrib.auth', ),
MIDDLEWARE_CLASSES = ('django.contrib.auth.middleware.AuthenticationMiddleware', ),
AUTHENTICATION_BACKENDS = ('django.contrib.auth.backends.ModelBackend', ),
DICTIONARY = u'''
ATTRIBUTE User-Name 1 string
ATTRIBUTE User-Password 2 string encrypt=1
ATTRIBUTE NAS-Identifier 32 string
'''


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


radiuslog = getLogger("radiusd", log_file, level=logging.DEBUG if debug else logging.INFO)


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


class RADIUSHandler(SocketServer.DatagramRequestHandler):
    """
    Very simply RADIUS packets handler
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
        pkt, socket = None, None
        try:
            data = self.request[0].strip()
            socket = self.request[1]
            dict = dictionary.Dictionary(StringIO(DICTIONARY))
            pkt = AuthPacket2(packet=data, dict=dict, secret=nas_secret)
            username, password, realm = pkt.get_username(), pkt.get_passwd(), pkt.get_realm()
            user = authenticate(username=username, password=password)
            if not (user and user.is_active and ("adm" not in realm or user.is_staff)):
                raise Exception('No user found or Login denied')
            self.send_accept(pkt, socket)
        except Exception, e:
            radiuslog.debug("[ERROR] {0}".format(e))
            self.send_reject(pkt, socket, str(e))


if __name__ == "__main__":
    HOST, PORT = "", 1812
    server = SocketServer.UDPServer((HOST, PORT), RADIUSHandler)

    print "serving at port", PORT
    server.serve_forever()
