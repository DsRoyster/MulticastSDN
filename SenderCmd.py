from MCSender import *
import time
import sys

WAIT_TIME = 1.5
ip = '10.10.10.240'
port = 11111

if len(sys.argv) > 1:
	nTree = int(sys.argv[1])
	print 'Requested tree number:', nTree
	if len(sys.argv) > 2:
		ip = sys.argv[2].split(':')
		print 'Destination IP:', ip[0]
		print 'Destination Port:', ip[1]
		port = int(ip[1])
		ip = ip[0]
s = MCSender(ip, port, nTreeIn = nTree)
print 'Initializing multicast session.'
while not s.init():
	print 'Initializing session failed. Reinitialize in', WAIT_TIME, 'sec.'
	time.sleep(WAIT_TIME)
time.sleep(WAIT_TIME)
print 'Initializing session succeeded. Sending.'
s.send(50000000)	# Send 10000 bytes
print 'Sending finished. Ending session.'
time.sleep(WAIT_TIME)
s.end()