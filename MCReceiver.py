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

	# Test of application goodput
	# def recv(self, blocking = 1):
	# 	# Just count the amount of data received, regardless of the content
	# 	data = {
	# 	'type':MC.INIT,
	# 	'srcaddr':self.srcaddr,
	# 	'dstaddr':self.dstaddr,
	# 	'dstport':self.dstport,
	# 	'treeid':0,
	# 	'datalen':0,
	# 	'payload':0
	# 	}
	# 	datacnt = 0
	#
	# 	self.recvskt.setblocking(blocking)
	#
	#
	# 	file = open('log_'+str(time.time())+'.txt', 'w')
	#
	#
	# 	# Denote transmission start
	# 	recvmsg, addr = self.recvskt.recvfrom(65565)
	# 	start_time1 = start_time = time.time()
	# 	last_timestamp = 0
	# 	print 'Begin listening...'
	# 	nop = 0; datacnt1 = 0
	# 	while True:
	# 		recvmsg, addr = self.recvskt.recvfrom(65565)
	# 		if recvmsg == None:
	# 			continue
	# 		#recvdata = MCPacket.extractDataPacket(recvmsg)
	# 		print 'Receiving from:', addr
	# 		if recvmsg[0:2] != 'MC':
	# 			continue
	# 		nop += 1
	# 		datacnt += len(recvmsg)
	# 		datacnt1 += len(recvmsg)
	# 		elp_time = time.time() - start_time
	# 		elp_time1 = time.time() - start_time1
	# 		#if elp_time >= last_timestamp:
	# 			#last_timestamp += 10
	# 		print 'Time elapsed:', elp_time, 'Data received:', datacnt, 'Bytes'
	# 		print 'Bandwidth:', (datacnt * 8 / 1000000) / elp_time, 'Mbps'
	# 		if nop % 50 == 0:
	# 			file.write(str((float(datacnt1) * 8 / 1000000) / elp_time1) + '\n')
	# 			file.flush()
	# 			datacnt1 = 0
	# 			start_time1 = time.time()
	#
	# 	file.close()
	#
	# 	return datacnt

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


		file1 = open('log_'+str(26000)+'.txt', 'w')
		file2 = open('log_'+str(26001)+'.txt', 'w')
		file3 = open('log_'+str(26002)+'.txt', 'w')



		# Denote transmission start
		recvmsg, addr = self.recvskt.recvfrom(65565)
		start_time = start_time1 = start_time2 = start_time3 = time.time()
		last_timestamp = 0
		print 'Begin listening...'
		nop1 = 0; nop2 = 0; nop3 = 0; datacnt1 = 0; datacnt2 = 0; datacnt3 = 0
		while True:
			recvmsg, addr = self.recvskt.recvfrom(65565)
			if recvmsg == None:
				continue
			#recvdata = MCPacket.extractDataPacket(recvmsg)
			print 'Receiving from:', addr
			if recvmsg[0:2] != 'MC':
				continue
			if addr[1] == 26000:
				datacnt1 += len(recvmsg)
				elp_time1 = time.time() - start_time1
				nop1 += 1
			if addr[1] == 26001:
				datacnt2 += len(recvmsg)
				elp_time2 = time.time() - start_time2
				nop2 += 1
			if addr[1] == 26002:
				datacnt3 += len(recvmsg)
				elp_time3 = time.time() - start_time3
				nop3 += 1
			elp_time = time.time() - start_time
			datacnt += len(recvmsg)
			print 'Time elapsed:', elp_time, 'Data received:', datacnt, 'Bytes'
			print 'Bandwidth:', (datacnt * 8 / 1000000) / elp_time, 'Mbps'
			if nop1 and nop1 % 50 == 0:
				file1.write(str((float(datacnt1) * 8 / 1000000) / elp_time1) + '\n')
				file1.flush()
				datacnt1 = 0
				start_time1 = time.time()
				nop1 = 0
			if nop2 and nop2 % 50 == 0:
				file2.write(str((float(datacnt2) * 8 / 1000000) / elp_time2) + '\n')
				file2.flush()
				datacnt2 = 0
				start_time2 = time.time()
				nop2 = 0
			if nop3 and nop3 % 50 == 0:
				file3.write(str((float(datacnt3) * 8 / 1000000) / elp_time3) + '\n')
				file3.flush()
				datacnt3 = 0
				start_time3 = time.time()
				nop3 = 0

		file1.close()
		file2.close()
		file3.close()

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



