import socket as skt
from MCCommon import *
from MCPacket import *
import time

class MCSender(MC):

	def init(self, dstaddrIn, dsrportIn, mngaddrConst = MC.mngaddrConst, mngportConst = MC.mngportConst):
		# Variables
		self.mngaddr = mngaddrConst
		self.mngport = mngportConst
		self.srcaddr = skt.gethostbyname(skt.gethostname())
		self.dstaddr = dstaddrIn
		self.dstport = dsrportIn

		# Management Socket
		self.mngskt = skt.socket(skt.AF_INET, skt.SOCK_DGRAM, skt.IPPROTO_UDP)
		self.recvskt = None
	def __init__(self, dstaddrIn = '', dsrportIn = 0):
		self.init(dstaddrIn, dsrportIn)

	def join(self):
		# Define data for JOIN packet
		data = {
		'type':MC.JOIN,
		'srcaddr':self.srcaddr,
		'dstaddr':self.dstaddr,
		'dstport':self.dstport,
		}

		# Send management packet to controller
		msg = MCPacket.buildManagePacket(data)
		while True:
			self.mngskt.sendto(msg, (self.mngaddr, self.mngport))

			while True:
				recvdata, addr = sock.recvfrom(24) 	# Init and Init_Reply both have 24 bytes length
				if skt.inet_ntoa(addr) == self.srcaddr:
					break

			recvmsg = MCPacket(recvdata)
			if recvmsg.getDWord(0) != MC.JOIN_REPLY:
				continue
			# Extract information from packet
			recvdata = MCPacket.extractManagePacket(recvmsg)
			if recvdata['status']:
				break
			else:
				return False

		print 'Join group success.'

		# Begin transmission
		self.recvskt = skt.socket(skt.AF_INET, skt.SOCK_DGRAM, skt.IPPROTO_UDP)
		return True

	def recv(self):
		# Just count the amount of data received, regardless of the content
		data = {
		'type':MC.INIT,
		'srcaddr':self.srcaddr,
		'srcport':self.srcport,
		'dstaddr':self.dstaddr,
		'dstport':self.dstport,
		'treeid':0,
		'datalen':0,
		'payload':0
		}
		datacnt = 0

		start_time = time.time()
		last_timestamp = 0
		while True:
			recvmsg, addr = self.recvskt.recvfrom(65565)
			recvdata = MCPacket.extractDataPacket(recvmsg)
			if recvdata['dstaddr'] != self.dstaddr:
				continue
			datacnt += len(recvdata['payload'])
			elp_time = time.time() - start_time
			if elp_time >= last_timestamp:
				last_timestamp += 10
				print 'Time elapsed:', elp_time, 'Data received:', datacnt, 'Bytes'


		return datacnt

	def leave(self):
		# Define data for LEAVE packet
		data = {
		'type':MC.LEAVE,
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

		print 'Leave group.'

		# Begin transmission
		return True



