import socket as skt
from MCCommon import *
import struct

class MCPacket(MC):
	def init(self, dataIn = ''):
		data = dataIn
	def __init__(self, dataIn = ''):
		self.init(dataIn)

	# Push into the data string
	def addByte(self, byte):
		data += chr(byte)
	def addWord(self, word):
		data += chr((word >> 8) % 256)
		data += chr((word >> 0) % 256)
	def addDWord(self, dword):
		data += chr((word >> 24) % 256)
		data += chr((word >> 16) % 256)
		data += chr((word >> 8) % 256)
		data += chr((word >> 0) % 256)
	def addString(self, str):
		data += str

	# Pop from the tail of the data string
	def popByte(self):
		ret = ord(data[len(data)-1])
		data = data[0:len(data)-1]
		return ret
	def popWord(self):
		ret = ord(data[len(data)-1])*256
		ret += ord(data[len(data)-2])
		data = data[0:len(data)-2]
		return ret
	def popDWord(self):
		ret = ord(data[len(data)-1])*256*256*256
		ret += ord(data[len(data)-2])*256*256
		ret += ord(data[len(data)-3])*256
		ret += ord(data[len(data)-4])
		data = data[0:len(data)-4]
		return ret
	def popString(self, length):
		ret = data[len(data)-length:len(data)]
		data = data[0:len(data)-length]
		return ret

	# Pop from the front of the data string
	def popByteFront(self):
		ret = ord(data[0])
		data = data[1:len(data)]
		return ret
	def popWordFront(self):
		ret = ord(data[0])*256
		ret += ord(data[1])
		data = data[2:len(data)]
		return ret
	def popDWordFront(self):
		ret = ord(data[0])*256*256*256
		ret += ord(data[1])*256*256
		ret += ord(data[2])*256
		ret += ord(data[3])
		data = data[4:len(data)-4]
		return ret
	def popStringFront(self, length):
		ret = data[0:length]
		data = data[length:len(data)]
		return ret

	# Get from any position of the data string
	def getByte(self, pos):
		ret = ord(data[pos])
		return ret
	def getWord(self, pos):
		ret = ord(data[pos])*256
		ret += ord(data[pos+1])
		return ret
	def getDWord(self, pos):
		ret = ord(data[pos])*256*256*256
		ret += ord(data[pos+1])*256*256
		ret += ord(data[pos+2])*256
		ret += ord(data[pos+3])
		return ret
	def getString(self, pos, length):
		ret = data[pos:pos+length]
		return ret

	# Return data string
	def getData(self):
		return data

	# Construct management packet
	@staticmethod
	def buildManagePacket(data):
		# Construct packet message based on different packet types
		msg = MCPacket()

		if data['type'] == MC.INIT:
			msg.addDWord(MC.INIT)							# Packet type
			msg.addString(skt.inet_aton(data['dstaddr']))	# Destination IP address
			msg.addWord(data['dstport'])					# Destination port
			msg.addString(skt.inet_aton(data['srcaddr']))	# Source IP address
			msg.addWord(data['srcport'])					# Source port
			msg.addDWord(data['datalen'])					# Data length
			msg.addDWord(0x00000000)						# Number of trees, 0 means ask for, >0 means require
		elif data['type'] == MC.INIT_REPLY:
			msg.addDWord(MC.INIT_REPLY)						# Packet type
			msg.addString(skt.inet_aton(data['dstaddr']))	# Destination IP address
			msg.addWord(data['dstport'])					# Destination port
			msg.addString(skt.inet_aton(data['srcaddr']))	# Source IP address
			msg.addWord(data['srcport'])					# Source port
			msg.addDWord(data['datalen'])					# Data length
			msg.addDWord(data['nTree'])						# Number of trees, 0 means failed for allocation, >0 means the # of trees
			for i in xrange(data['nTree']):
				msg.addDWord(data['treelst'][i])
		elif data['type'] == MC.END:
			msg.addDWord(MC.END)							# Packet type
			msg.addString(skt.inet_aton(data['dstaddr']))	# Destination IP address
			msg.addWord(data['dstport'])					# Destination port
			msg.addString(skt.inet_aton(data['srcaddr']))	# Source IP address
			msg.addWord(data['srcport'])					# Source port
		elif data['type'] == MC.END_REPLY:
			msg.addDWord(MC.END_REPLY)						# Packet type
			msg.addString(skt.inet_aton(data['dstaddr']))	# Destination IP address
			msg.addWord(data['dstport'])					# Destination port
			msg.addString(skt.inet_aton(data['srcaddr']))	# Source IP address
			msg.addWord(data['srcport'])					# Source port
		elif data['type'] == MC.JOIN:
			msg.addDWord(MC.JOIN)							# Packet type
			msg.addString(skt.inet_aton(data['dstaddr']))	# Destination IP address
			msg.addWord(data['dstport'])					# Destination port
			msg.addString(skt.inet_aton(data['srcaddr']))	# Source IP address
			msg.addWord(0x00000000)							# 0 means ask for
		elif data['type'] == MC.JOIN_REPLY:
			msg.addDWord(MC.JOIN_REPLY)						# Packet type
			msg.addString(skt.inet_aton(data['dstaddr']))	# Destination IP address
			msg.addWord(data['dstport'])					# Destination port
			msg.addString(skt.inet_aton(data['srcaddr']))	# Source IP address
			msg.addWord(data['status'])						# 0 means failed, >0 means succeed
		elif data['type'] == MC.LEAVE:
			msg.addDWord(MC.LEAVE)							# Packet type
			msg.addString(skt.inet_aton(data['dstaddr']))	# Destination IP address
			msg.addWord(data['dstport'])					# Destination port
			msg.addString(skt.inet_aton(data['srcaddr']))	# Source IP address
		elif data['type'] == MC.LEAVE_REPLY:
			msg.addDWord(MC.LEAVE_REPLY)					# Packet type
			msg.addString(skt.inet_aton(data['dstaddr']))	# Destination IP address
			msg.addWord(data['dstport'])					# Destination port
			msg.addString(skt.inet_aton(data['srcaddr']))	# Source IP address

		return msg.getData()

	# Extract information from management packet
	@staticmethod
	def extractManagePacket(msg):
		# Construct packet message based on different packet types
		data = {}

		if msg.getDWord(0) == MC.INIT:
			data['type'] = MC.INIT
			data['dstaddr'] = skt.inet_atoi(msg.getString(4, 4))
			data['dstport'] = msg.getWord(8)
			data['srcaddr'] = skt.inet_atoi(msg.getString(10, 4))
			data['srcport'] = msg.getWord(14)
			data['datalen'] = msg.getDWord(16)
			data['nTree'] = msg.getDWord(20)
		elif data['type'] == MC.INIT_REPLY:
			data['type'] = MC.INIT_REPLY
			data['dstaddr'] = skt.inet_atoi(msg.getString(4, 4))
			data['dstport'] = msg.getWord(8)
			data['srcaddr'] = skt.inet_atoi(msg.getString(10, 4))
			data['srcport'] = msg.getWord(14)
			data['datalen'] = msg.getDWord(16)
			data['nTree'] = msg.getDWord(20)
			data['treelst'] = []
			for i in xrange(data['nTree']):
				data['treelst'].append(msg.getDWord(24 + 4 * i))
		elif data['type'] == MC.END:
			data['type'] = MC.END
			data['dstaddr'] = skt.inet_atoi(msg.getString(4, 4))
			data['dstport'] = msg.getWord(8)
			data['srcaddr'] = skt.inet_atoi(msg.getString(10, 4))
			data['srcport'] = msg.getWord(14)
		elif data['type'] == MC.END_REPLY:
			data['type'] = MC.END_REPLY
			data['dstaddr'] = skt.inet_atoi(msg.getString(4, 4))
			data['dstport'] = msg.getWord(8)
			data['srcaddr'] = skt.inet_atoi(msg.getString(10, 4))
			data['srcport'] = msg.getWord(14)
		elif data['type'] == MC.JOIN:
			data['type'] = MC.JOIN
			data['dstaddr'] = skt.inet_atoi(msg.getString(4, 4))
			data['dstport'] = msg.getWord(8)
			data['srcaddr'] = skt.inet_atoi(msg.getString(10, 4))
			data['status'] = msg.getWord(14)
		elif data['type'] == MC.JOIN_REPLY:
			data['type'] = MC.JOIN_REPLY
			data['dstaddr'] = skt.inet_atoi(msg.getString(4, 4))
			data['dstport'] = msg.getWord(8)
			data['srcaddr'] = skt.inet_atoi(msg.getString(10, 4))
			data['status'] = msg.getWord(14)
		elif data['type'] == MC.LEAVE:
			data['type'] = MC.LEAVE
			data['dstaddr'] = skt.inet_atoi(msg.getString(4, 4))
			data['dstport'] = msg.getWord(8)
			data['srcaddr'] = skt.inet_atoi(msg.getString(10, 4))
		elif data['type'] == MC.LEAVE_REPLY:
			data['type'] = MC.LEAVE_REPLY
			data['dstaddr'] = skt.inet_atoi(msg.getString(4, 4))
			data['dstport'] = msg.getWord(8)
			data['srcaddr'] = skt.inet_atoi(msg.getString(10, 4))

		return data


	# Construct data packet
	@staticmethod
	def buildDataPacket(data):
		# Construct packet message based on different packet types
		# Use src port for tree id (as binded in the send module)
		msg = MCPacket()



		return msg.getData()

	# Extract information from data packet
	@staticmethod
	def extractDataPacket(pkt):
		# Construct packet message based on different packet types
		# Use src port for tree id (as binded in the send module)
		data = {}


		# Unpacking from the packet
		# Take first 20 characters for the ip header
		ip_header = pkt[0:20]

		#now unpack them :)
		iph = struct.unpack('!BBHHHBBH4s4s' , ip_header)

		version_ihl = iph[0]
		version = version_ihl >> 4
		ihl = version_ihl & 0xF

		iph_length = ihl * 4

		ttl = iph[5]
		protocol = iph[6]
		s_addr = skt.inet_ntoa(iph[8]);
		d_addr = skt.inet_ntoa(iph[9]);


		# UDP packet header
		udp_header = pkt[iph_length:iph_length+20]
		#now unpack them :)
		udph = struct.unpack('!HHHH' , udp_header)

		source_port = udph[0]
		dest_port = udph[1]
		udp_length = udph[2]
		checksum = udph[3]

		h_size = iph_length + 8			# Whole header size
		data_size = len(pkt) - h_size

		#get data from the packet
		payload = pkt[h_size:]




		# Fill return structure
		data['type'] = MC.DATA_PACKET
		data['srcaddr'] = s_addr
		data['dstaddr'] = d_addr
		data['srcport'] = source_port
		data['dstport'] = dest_port
		data['payload'] = payload
		data['treeid'] = source_port
		data['TTL'] = ttl


		return data
