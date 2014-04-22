import socket as skt

class MC(object):
	# Definition for management communication
	INIT 		= 0x00000001
	INIT_REPLY 	= 0x00000002
	END 		= 0x00000010
	END_REPLY 	= 0x00000020
	JOIN		= 0x00000100
	JOIN_REPLY	= 0x00000200
	LEAVE		= 0x00001000
	LEAVE_REPLY	= 0x00002000
	UPDATE		= 0x00010000
	UPDATE_REPLY= 0x00020000

	mngaddrConst = '10.10.10.250'
	mngportConst = 1535

	# Definition for data communication
	DATA_PACKET	= 0xff000000
	dataportBase = 26000
	FIX_DATA_SIZE = 1400

def inttoip(ip):
	return skt.inet_ntoa(hex(ip)[2:].decode('hex'))
