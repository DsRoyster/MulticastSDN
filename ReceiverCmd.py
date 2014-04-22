from MCReceiver import *
import time

WAIT_TIME = 1

r = MCReceiver('10.10.10.240', 11111)
print 'Joining group.'
while not r.join():
	print 'Joining group failed. Rejoin in', WAIT_TIME, 'sec.'
	time.sleep(WAIT_TIME)
print 'Joining group succeeded. Receiving.'
r.recv()
r.leave()