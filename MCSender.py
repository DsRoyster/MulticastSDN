import socket as skt
from MCCommon import *
from MCPacket import *
import time

class MCSender(MC):

	def init(self, dstaddrIn, dsrportIn, nTreeIn = 0, treelstIn = [], mngaddrConst = MC.mngaddrConst, mngportConst = MC.mngportConst):
		# Variables
		self.mngaddr = mngaddrConst
		self.mngport = mngportConst
		self.srcaddr = skt.gethostbyname(skt.gethostname())
		self.srcport = 0
		self.dstaddr = dstaddrIn
		self.dstport = dsrportIn
		self.nTree = nTreeIn
		self.treelst = treelstIn

		# Management Socket
		self.mngskt = skt.socket(skt.AF_INET, skt.SOCK_DGRAM, skt.IPPROTO_UDP)
		self.mngskt.bind(('', self.mngport))
		#self.sendskt = skt.socket(skt.AF_PACKET, skt.SOCK_RAW)
		self.sendskt = []
	def __init__(self, dstaddrIn = '', dsrportIn = 0, nTreeIn = 0, treelstIn = []):
		self.init(dstaddrIn, dsrportIn, nTreeIn, treelstIn)

	def initSendSock(self, treelst):
		for s in self.sendskt:
			s.close()
		self.sendskt = []
		self.nTree = len(treelst)
		self.treelst = treelst
		for i in xrange(self.nTree):
			s = skt.socket(skt.AF_INET, skt.SOCK_DGRAM, skt.IPPROTO_UDP)
			s.bind('', treelst[i])

	def init(self):
		# Define data for INIT packet
		data = {
		'type':MC.INIT,
		'srcaddr':self.srcaddr,
		'srcport':self.srcport,
		'dstaddr':self.dstaddr,
		'dstport':self.dstport,
		'nTree':self.nTree,
		'datalen':0
		}

		# Send management packet to controller
		msg = MCPacket.buildManagePacket(data)
		while True:
			self.mngskt.sendto(msg, (self.mngaddr, self.mngport))

			while True:
				recvdata, addr = self.mngskt.recvfrom(24) 	# Init and Init_Reply both have 24 bytes length
				if skt.inet_ntoa(addr) == self.srcaddr:
					break

			recvmsg = MCPacket(recvdata)
			if recvmsg.getDWord(0) != MC.INIT_REPLY:
				continue
			# Extract information from packet
			recvdata = MCPacket.extractManagePacket(recvmsg)
			self.nTree = recvdata['nTree']
			if self.nTree:
				break
			else:
				return False

		# Initialize send sockets
		self.initSendSock(recvdata['treelst'])

		# Begin transmission
		return True

	def send(self):
		data = {
		'type':MC.DATA_PACKET,
		'srcaddr':self.srcaddr,
		'srcport':self.srcport,
		'dstaddr':self.dstaddr,
		'dstport':self.dstport,
		'treeid':0,
		'datalen':0,
		'payload':None
		}

		treeIdx = 0
		datacnt = 0
		while datacnt < datalen:
			# Send random data of the same size, just for testing
			# Pkt content
			pkt = str(time.time())
			pkt += "".join(['aaabbbcccdddeeefffggg' for i in xrange((MC.FIX_DATA_SIZE - len(pkt)) / len('aaabbbcccdddeeefffggg'))])
			if datacnt + pkt > datalen:
				pkt = pkt[0:datalen-datacnt]

			# Pkt data
			data['treeid'] = treeIdx
			treeIdx = (treeIdx + 1) % nTree
			data['payload'] = pkt

			# Send out
			self.sendskt[data['treeid']].sendto(data['payload'], (self.dstaddr, self.dstport))
			datacnt += len(pkt)

		return datacnt

	def end(self):
		# Define data for END packet
		data = {
		'type':MC.END,
		'srcaddr':self.srcaddr,
		'srcport':self.srcport,
		'dstaddr':self.dstaddr,
		'dstport':self.dstport,
		}

		# Send management packet to controller
		msg = MCPacket.buildPacketContent(data)
		self.mngskt.sendto(msg, (self.mngaddr, self.mngport))

		# End all sockets
		for s in self.sendskt:
			s.close()

		# Begin transmission
		return True



