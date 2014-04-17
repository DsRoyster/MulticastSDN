import socket as skt
from MCCommon import *
from MCPacket import *
import time
from pox.core import core

from MCController import *

log = core.getLogger()


def launch ():
	"""
	Starts the component
	"""
	mcctl = MCController()
	def addSwitch (event):
		log.debug("Controlling %s" % (event.connection,))
		mcctl.addConnection(event.connection)
	core.openflow.addListenerByName("ConnectionUp", addSwitch)