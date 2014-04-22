import socket as skt
from MCCommon import *
from MCPacket import *
import time

class MCReceiver(MC):

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
			print MCPacket(msg).getDWord(0), MC.JOIN
			self.mngskt.sendto(msg, (self.mngaddr, self.mngport))

			while True:
				recvdata, addr = self.mngskt.recvfrom(24) 	# Init and Init_Reply both have 24 bytes length
				if addr[0] == self.mngaddr and addr[1] == self.mngport:
					break

			recvmsg = MCPacket(recvdata)
			print 'Type:', recvmsg.getDWord(0)
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
		#self.recvskt = skt.socket(skt.AF_INET, skt.SOCK_RAW)
		#self.recvskt.setsockopt(skt.IPPROTO_IP, skt.IP_HDRINCL, 1)
		#self.recvskt.ioctl(skt.SIO_RCVALL, skt.RCVALL_ON)
		self.recvskt = skt.socket(skt.AF_INET, skt.SOCK_DGRAM)
		self.recvskt.bind(('', self.dstport))
		self.recvskt.setsockopt(skt.SOL_SOCKET, skt.SO_BROADCAST, 1)
		return True

	def recv(self, blocking = 1):
		# Just count the amount of data received, regardless of the content
		data = {
		'type':MC.INIT,
		'srcaddr':self.srcaddr,
		'dstaddr':self.dstaddr,
		'dstport':self.dstport,
		'treeid':0,
		'datalen':0,
		'payload':0
		}
		datacnt = 0

		self.recvskt.setblocking(blocking)

		# Denote transmission start
		recvmsg, addr = self.recvskt.recvfrom(65565)
		start_time = time.time()
		last_timestamp = 0
		print 'Begin listening...'
		while True:
			recvmsg, addr = self.recvskt.recvfrom(65565)
			if recvmsg == None:
				continue
			#recvdata = MCPacket.extractDataPacket(recvmsg)
			print 'Receiving from:', addr
			if recvmsg[0:2] != 'MC':
				continue
			datacnt += len(recvmsg)
			elp_time = time.time() - start_time
			#if elp_time >= last_timestamp:
				#last_timestamp += 10
			print 'Time elapsed:', elp_time, 'Data received:', datacnt, 'Bytes'
			print 'Bandwidth:', (datacnt * 8 / 1000000) / elp_time, 'Mbps'


		return datacnt

	def leave(self):
		# Define data for LEAVE packet
		data = {
		'type':MC.LEAVE,
		'srcaddr':self.srcaddr,
		'dstaddr':self.dstaddr,
		'dstport':self.dstport,
		}

		# Send management packet to controller
		msg = MCPacket.buildManagePacket(data)
		self.mngskt.sendto(msg, (self.mngaddr, self.mngport))

		# End all sockets
		self.recvskt.close()

		print 'Leave group.'

		# Begin transmission
		return True



