from MCSender import *
import time
import sys

WAIT_TIME = 1.5

if len(sys.argv) > 1:
	nTree = int(sys.argv[1])
	print 'Requested tree number:', nTree
s = MCSender('10.10.10.240', 11111, nTreeIn = nTree)
print 'Initializing multicast session.'
while not s.init():
	print 'Initializing session failed. Reinitialize in', WAIT_TIME, 'sec.'
	time.sleep(WAIT_TIME)
time.sleep(WAIT_TIME)
print 'Initializing session succeeded. Sending.'
s.send(10000000)	# Send 10000 bytes
print 'Sending finished. Ending session.'
time.sleep(WAIT_TIME)
s.end()