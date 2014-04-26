from MCReceiver import *
import time, sys

WAIT_TIME = 1
ip = '10.10.10.240'
port = 11111

if len(sys.argv) > 1:
	ip = sys.argv[1].split(':')
	print 'Destination IP:', ip[0]
	print 'Destination Port:', ip[1]
	port = int(ip[1])
	ip = ip[0]
r = MCReceiver(ip, port)
print 'Joining group.'
while not r.join():
	print 'Joining group failed. Rejoin in', WAIT_TIME, 'sec.'
	time.sleep(WAIT_TIME)
print 'Joining group succeeded. Receiving.'
r.recv()
r.leave()