# Copyright 2012-2013 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#		 http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
A shortest-path forwarding application.

This is a standalone L2 switch that learns ethernet addresses
across the entire network and picks short paths between them.

You shouldn't really write an application this way -- you should
keep more state in the controller (that is, your flow tables),
and/or you should make your topology more static.	However, this
does (mostly) work. :)

Depends on openflow.discovery
Works with openflow.spanning_tree
"""

########################################################################
######## Work to go
# 4/15:	calcMCTrees
#		installTrees
#		uninstallTrees

from MCCommon import *
from MCPacket import *

from pox.lib.addresses import IPAddr, EthAddr
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.recoco import Timer
from collections import defaultdict
from pox.openflow.discovery import Discovery
from pox.lib.util import dpid_to_str
import pox.lib.packet as pkt
import time
from utils import *

log = core.getLogger()

# Adjacency map.	[sw1][sw2] -> port from sw1 to sw2
adjacency = defaultdict(lambda:defaultdict(lambda:None))

# Switches we know of.	[dpid] -> Switch
switches = {}

# ethaddr -> (switch, port)
mac_map = {}

# [sw1][sw2] -> (distance, intermediate)
path_map = defaultdict(lambda:defaultdict(lambda:(None,None)))

# Waiting path.	(dpid,xid)->WaitingPath
waiting_trees = {}

# Time to not flood in seconds
FLOOD_HOLDDOWN = 5

# Flow timeouts
FLOW_IDLE_TIMEOUT = 10
FLOW_HARD_TIMEOUT = 30

# How long is allowable to set up a path?
TREE_SETUP_TIME = 4



######################################################
## DFS find tree
def dfsTree(s, R, mark):
	sws = switches.values()
	tree = []
	stack = [s]
	visit = set([])
	pa = {s:None}
	while stack:
		# Traverse on v
		v = stack.pop()
		if v in visit:
			continue
		visit.add(v)
		# Put the link in tree. The mark of edge is guaranteed when pushing nodes
		if pa[v] != None:
			tree.append((pa[v], v))

		# Push adjacent nodes in stack
		for y in sws:
			# Guarantee mark
			if (y not in visit) and (adjacency[v][y] != None) and (mark[v][y] != None):
				stack.append(y)
				pa[y] = v

	for r in R:
		if r not in visit:
			return None

	return tree

######################################################
## Prune to be Steiner's tree
def pruneTree(s, R, tree):
	sFlg = set([r for r in R])
	while True:
		contFlg = False
		for e in tree:
			if e[1] in sFlg and e[0] not in sFlg:
				sFlg.add(e[0])
				contFlg = True
		if not contFlg:
			break
	for e in tree:
		if (e[0] not in sFlg) or (e[1] not in sFlg):
			tree.remove(e)

	return tree

######################################################
## Aggregate tree port information
# tr1: v -> (inport, outports)
def aggTree(s, R, tree):
	tr1 = {s: (None, [])}
	for (u, v) in tree:
		if u not in tr1.keys():
			tr1[u] = (None, [])
		tr1[u][1].append(adjacency[u][v])
		if v not in tr1.keys():
			tr1[v] = (None, [])
		tr1[v][0] = adjacency[v][u]

	return tr1

######################################################
## Calculating the trees
# Just use DFS
def calcMCTrees(s, R):
	# Mark edge when tree found
	# [sw1][sw2] -> mark
	mark = defaultdict(lambda:defaultdict(lambda:(False)))
	# Set output ports in the edge
	outPortLst = {r[0]:[] for r in R}
	for r in R:
		outPortLst[r[0]].append(r[1])


	# Find trees until cannot find one
	tlst = []
	while True:
		tree = dfsTree(s, R, mark)
		if tree == None:
			break
		tree = pruneTree(s, R, tree)
		for (u, v) in tree:
			mark[u][v] = True
		tr1 = aggTree(s, R, tree)
		# Set output for edges
		for r in R:
			tr1[r[0]][1] = outPortLst[r[0]]
		tlst.append(tr1)

	return tlst






def _calc_paths ():
	"""
	Essentially Floyd-Warshall algorithm
	"""

	def dump ():
		for i in sws:
			for j in sws:
				a = path_map[i][j][0]
				#a = adjacency[i][j]
				if a is None: a = "*"
				print a,
			print

	sws = switches.values()
	path_map.clear()
	for k in sws:
		for j,port in adjacency[k].iteritems():
			if port is None: continue
			path_map[k][j] = (1,None)
		path_map[k][k] = (0,None) # distance, intermediate

	#dump()

	for k in sws:
		for i in sws:
			for j in sws:
				if path_map[i][k][0] is not None:
					if path_map[k][j][0] is not None:
						# i -> k -> j exists
						ikj_dist = path_map[i][k][0]+path_map[k][j][0]
						if path_map[i][j][0] is None or ikj_dist < path_map[i][j][0]:
							# i -> k -> j is better than existing
							path_map[i][j] = (ikj_dist, k)

	#print "--------------------"
	#dump()


def _get_raw_path (src, dst):
	"""
	Get a raw path (just a list of nodes to traverse)
	"""
	if len(path_map) == 0: _calc_paths()
	if src is dst:
		# We're here!
		return []
	if path_map[src][dst][0] is None:
		return None
	intermediate = path_map[src][dst][1]
	if intermediate is None:
		# Directly connected
		return []
	return _get_raw_path(src, intermediate) + [intermediate] + \
				 _get_raw_path(intermediate, dst)


def _check_path (p):
	"""
	Make sure that a path is actually a string of nodes with connected ports

	returns True if path is valid
	"""
	for a,b in zip(p[:-1],p[1:]):
		if adjacency[a[0]][b[0]] != a[2]:
			return False
		if adjacency[b[0]][a[0]] != b[1]:
			return False
	return True


def _get_path (src, dst, first_port, final_port):
	"""
	Gets a cooked path -- a list of (node,in_port,out_port)
	"""
	# Start with a raw path...
	if src == dst:
		path = [src]
	else:
		path = _get_raw_path(src, dst)
		if path is None: return None
		path = [src] + path + [dst]

	# Now add the ports
	r = []
	in_port = first_port
	for s1,s2 in zip(path[:-1],path[1:]):
		out_port = adjacency[s1][s2]
		r.append((s1,in_port,out_port))
		in_port = adjacency[s2][s1]
	r.append((dst,in_port,final_port))

	assert _check_path(r), "Illegal path!"

	return r


class WaitingTree (object):
	"""
	A tree which is waiting for its paths to be established
	"""
	def __init__ (self, s, R, tree, packet):
		"""
		xids is a sequence of (dpid,xid)
		first_switch is the DPID where the packet came from (source switch)
		packet is something that can be sent in a packet_out
		"""
		self.expires_at = time.time() + TREE_SETUP_TIME
		self.tree = tree
		self.first_switch = tree[s]
		self.xids = set()
		self.packet = packet

		if len(waiting_trees) > 1000:
			WaitingTree.expire_waiting_trees()

	def add_xid (self, dpid, xid):
		self.xids.add((dpid,xid))
		waiting_trees[(dpid,xid)] = self

	@property
	def is_expired (self):
		return time.time() >= self.expires_at

	def notify (self, event):
		"""
		Called when a barrier has been received
		"""
		self.xids.discard((event.dpid,event.xid))
		if len(self.xids) == 0:
			# Done!
			if self.packet:
				log.debug("Sending delayed packet out %s"
									% (dpid_to_str(self.first_switch),))
				msg = of.ofp_packet_out(data=self.packet,
						action=of.ofp_action_output(port=of.OFPP_TABLE))
				core.openflow.sendToDPID(self.first_switch, msg)

			core.MCController.raiseEvent(TreeInstalled(self.tree))


	@staticmethod
	def expire_waiting_trees ():
		packets = set(waiting_trees.values())
		killed = 0
		for p in packets:
			if p.is_expired:
				killed += 1
				for entry in p.xids:
					waiting_trees.pop(entry, None)
		if killed:
			log.error("%i paths failed to install" % (killed,))


class TreeInstalled (Event):
	"""
	Fired when a path is installed
	"""
	def __init__ (self, path):
		Event.__init__(self)
		self.path = path





######################################################
## Group
class MCGroup (object):
	# Define status markers
	INITED = 0
	ACTIVE = 1
	FINISH = 2

	def __init__ (self, dstip, dstport):
		self.dstip = dstip
		self.dstport = dstport
		self.memlst = {}
	def addMem(self, srcip, status = ACTIVE):
		self.memlst[srcip] = status
	def delMem(self, srcip):
		if srcip in self.memlst.keys():
			del self.memlst[srcip]
	def updateMem(self, orgip, newip):
		if orgip in self.memlst.keys():
			self.memlst[newip] = self.memlst[orgip]
			del self.memlst[orgip]

	def getActiveMem(self):
		return [ip for ip,status in self.memlst.items() if status == MCGroup.ACTIVE]


######################################################
## Session
class MCSession (MCGroup):
	def __init__ (self, srcip, dstip, dstport):
		MCGroup.__init__(self, dstip, dstport)
		self.srcip = srcip
		self.nTree = None
		self.treemap = None
	def setTreeLst(self, treelst):
		self.treemap = {}
		# Assign tree ids on a port base. These are used as src ports to be matched.
		for i in xrange(len(treelst)):
			id = MC.dataportBase + i
			self.treemap[id] = treelst[i]
		self.nTree = len(treelst)
		return self.treemap.keys()

######################################################
#### Some explaination about the session management
# For each group, the group members are subject to
# dynamic changes.
# While for each session, the session member will not
# change during the transmission of the session.
# This means that we need to keep a copy of the group
# in order to mark leaving nodes, while keep each
# transmitting session unchanged.
######################################################
## Session Management
class MCSessionManager (object):
	def __init__(self):
		# (dstip, dstport) -> Group
		self.groupLst = {}
		# (dstip, dstport) -> [Session1, Session2, ...]
		self.sessionLst = {}
		# ip -> mac
		self.ipToMac = {}
	def setIpMap(self, packet):
		ip = packet.next.srcip
		eth = packet.src
		self.ipToMac[ip] = eth
	def addMem(self, data):
		dstip = data['dstaddr']
		dstport = data['dstport']
		if (dstip, dstport) not in self.groupLst.keys():
			self.groupLst[dstip, dstport] = MCGroup()
		self.groupLst[dstip, dstport].addMem(data['srcaddr'])
	def delMem(self, data):
		dstip = data['dstaddr']
		dstport = data['dstport']
		if (dstip, dstport) not in self.groupLst.keys():
			return
		self.groupLst[dstip, dstport].delMem(data['srcaddr'])

	# Initialize the session in this management system
	# Also need installing flows with the tree list returned
	def initSession(self, packet, data, s):
		dstip = data['dstaddr']
		dstport = data['dstport']
		if (dstip, dstport) not in self.groupLst.keys():
			# Do some thing say about no group exists
			pass
		else:
			if (dstip, dstport) not in self.sessionLst.keys():
				self.sessionLst[dstip, dstport] = []
			sess = MCSession(data['srcaddr'], data['dstaddr'], data['dstport'])
			# calcMCTrees(srceth, dsteths)
			# Here needs some mind, maybe the conversion is wrong for calculating. Please check..............
			# This mac_map is not right. mac_map only stores the information about end hosts
			rLst = [mac_map[self.ipToMac[ip]] for ip in self.groupLst[dstip, dstport].getActiveMem()]
			tLst = calcMCTrees(s, rLst)
			tidLst = sess.setTreeLst(tLst)
			self.sessionLst[dstip, dstport].append(sess)
		return tLst, tidLst

class Switch (EventMixin):
	def __init__ (self):
		self.connection = None
		self.ports = None
		self.dpid = None
		self._listeners = None
		self._connected_at = None

		# Session Manager. Very important
		self.mcsm = MCSessionManager()

	def __repr__ (self):
		return dpid_to_str(self.dpid)

	def _install (self, switch, in_port, out_port, match, buf = None):
		msg = of.ofp_flow_mod()
		msg.match = match
		if in_port != None:
			msg.match.in_port = in_port
		msg.idle_timeout = FLOW_IDLE_TIMEOUT
		msg.hard_timeout = FLOW_HARD_TIMEOUT
		for op in out_port:
			msg.actions.append(of.ofp_action_output(port = op))
		msg.buffer_id = buf
		switch.connection.send(msg)

	def _install_tree (self, tree, match, packet_in=None):
		wp = WaitingTree(tree, packet_in)
		for sw in tree.keys():
			in_port, out_port = tree[sw]
			self._install(sw, in_port, out_port, match)
			msg = of.ofp_barrier_request()
			sw.connection.send(msg)
			wp.add_xid(sw.dpid,msg.xid)


	######################################################
	## Install tree
	def installTrees (self, data, tLst, tidLst, match, event):
		"""
		Attempts to install a path between this switch and some destination
		"""

		log.debug("Installing trees for %s -> %s:%04x",
				match.nw_src, match.nw_dst, match.tp_src)

		# We have a path -- install it
		for t in tLst:
			tport = tidLst[tLst.index(t)]
			# Tree id as the source port
			match.tp_src = tport
			self._install_tree(t, match)

		# Now reverse it and install it backwards
		# (we'll just assume that will work)
		#p = [(sw,out_port,in_port) for sw,in_port,out_port in p]
		#self._install_path(p, match.flip())


	######################################################
	## uninstall tree
	def uninstallTrees (self, data, match, event):
		"""
		Attempts to install a path between this switch and some destination
		"""

		log.debug("Uninstalling trees for %s -> %s:%04x",
				match.nw_src, match.nw_dst, match.tp_src)

		# Not finished: need to uninstall flows. Now just leave them till expires
		pass
		# We have a path -- install it
		#for t in tLst:
		#	self._install_tree(t, match)

		# Now reverse it and install it backwards
		# (we'll just assume that will work)
		#p = [(sw,out_port,in_port) for sw,in_port,out_port in p]
		#self._install_path(p, match.flip())

	######################################################
	## Handle Management Packet
	def consMatch(self, data):
		match = of.ofp_match()
		match.dl_type = pkt.ethernet.IP_TYPE
		match.nw_proto = pkt.ipv4.UDP_PROTOCOL
		match.nw_src = IPAddr(data['srcaddr'])
		match.nw_dst = IPAddr(data['dstaddr'])
		match.tp_dst = data['dstport']
		return match

	######################################################
	## Sendout init reply
	def initReply(self, event, packet, data, tidLst):
		# Set backward MAC: how to set the src?
		packet.dst, packet.src = packet.src, packet.dst
		# Set backward IP
		packet.next.dstip, packet.next.srcip = packet.next.srcip, packet.next.dstip
		# Set backward Port
		packet.next.next.dstport, packet.next.next.srcport = packet.next.next.srcport, packet.next.next.dstport

		# Change data and rebuild packet
		data['type'] = MC.INIT_REPLY
		data['nTree'] = len(tidLst)
		data['treelst'] = tidLst		# Each tree id is an integer, written to be a DWord
		# If it does not work, pack the packet into byte stream and try again.
		packet.next.next.payload = MCPacket.buildManagePacket(data)

		# Send packet out message
		msg = of.ofp_packet_out(in_port=event.port)
		msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
		msg.data = packet
		self.connection.send(msg)

	######################################################
	## Sendout join reply
	def joinReply(self, event, packet, data):
		# Set backward MAC: how to set the src?
		packet.dst, packet.src = packet.src, packet.dst
		# Set backward IP
		packet.next.dstip, packet.next.srcip = packet.next.srcip, packet.next.dstip
		# Set backward Port
		packet.next.next.dstport, packet.next.next.srcport = packet.next.next.srcport, packet.next.next.dstport

		# If it does not work, pack the packet into byte stream and try again.

		# Send packet out message
		msg = of.ofp_packet_out(in_port=event.port)
		msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
		msg.data = packet
		self.connection.send(msg)

	######################################################
	## Handle Management Packet
	def handleMngPacket(self, packet, event, log):
		retPkt = None
		data = MCPacket.extractManagePacket(packet.next.next.payload)
		# Add the ethernet address into the ipMap. Used for topology construction in the view of ethernet view.

		if data['type'] == MC.INIT:
			log.debug('[INIT] Request received: %s -> %s:%04x', data['srcaddr'], data['dstaddr'], data['dstport'])
			# Initialize multicast session
			# 1. Construct multiple trees
			tlst, tidLst = self.mcsm.initSession(packet, data, self)
			log.debug('[INIT] Trees obtained: %s', str(tidLst))

			# 2. Construct match and install trees
			match = self.consMatch(data)
			self.installTrees(data, tlst, tidLst, match, event)		# need to record this in database
			log.debug('[INIT] Installed.')

			# 3. Reconstruct and reply the init packet
			retPkt = self.initReply(event, packet, data, tidLst)
			log.debug('[INIT] Replied.')
		elif data['type'] == MC.END:
			log.debug('[END] Request received: %s -> %s:%04x', data['srcaddr'], data['dstaddr'], data['dstport'])
			# End multicast session
			# 1. Uninstall trees
			match = self.consMatch(data)
			self.uninstallTrees(data, match, event)
			log.debug('[INIT] Processed.')
		elif data['type'] == MC.JOIN:
			log.debug('[JOIN] Request received: %s -> %s:%04x', data['srcaddr'], data['dstaddr'], data['dstport'])
			# Receiver joining a group
			# 1. record receiver
			self.mcsm.addMem(data)
			log.debug('[JOIN] Member added.')
			# 2. Reconstruct and reply the join packet
			retPkt = self.joinReply(event, packet, data)
			log.debug('[JOIN] Replied.')
		elif data['type'] == MC.LEAVE:
			# Receiver leaving a group
			# 1. delete receiver
			self.mcsm.delMem(data)
			log.debug('[LEAVE] Processed.')

		return retPkt


	def _handle_PacketIn (self, event):
		def flood ():
			""" Floods the packet """
			if self.is_holding_down:
				log.warning("Not flooding -- holddown active")
			msg = of.ofp_packet_out()
			# OFPP_FLOOD is optional; some switches may need OFPP_ALL
			msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
			msg.buffer_id = event.ofp.buffer_id
			msg.in_port = event.port
			self.connection.send(msg)

		def drop ():
			# Kill the buffer
			if event.ofp.buffer_id is not None:
				msg = of.ofp_packet_out()
				msg.buffer_id = event.ofp.buffer_id
				event.ofp.buffer_id = None # Mark is dead
				msg.in_port = event.port
				self.connection.send(msg)

		packet = event.parsed
		#################
		# Set the ip to mac mapping
		self.mcsm.setIpMap(packet)

		loc = (self, event.port) # Place we saw this ethaddr
		oldloc = mac_map.get(packet.src) # Place we last saw this ethaddr

		# LLDP is used for discovering the topology
		# Don't know why dropped. Maybe not useful in here?
		if packet.effective_ethertype == packet.LLDP_TYPE:
			drop()
			return

		# Update the location of an MAC address
		if oldloc is None:
			if packet.src.is_multicast == False:
				mac_map[packet.src] = loc # Learn position for ethaddr
				log.debug("Learned %s at %s.%i", packet.src, loc[0], loc[1])
		elif oldloc != loc:
			# ethaddr seen at different place!
			if core.openflow_discovery.is_edge_port(loc[0].dpid, loc[1]):
				# New place is another "plain" port (probably)
				log.debug("%s moved from %s.%i to %s.%i?", packet.src,
									dpid_to_str(oldloc[0].dpid), oldloc[1],
									dpid_to_str(	 loc[0].dpid),		loc[1])
				if packet.src.is_multicast == False:
					mac_map[packet.src] = loc # Learn position for ethaddr
					log.debug("Learned %s at %s.%i", packet.src, loc[0], loc[1])
			elif packet.dst.is_multicast == False:
				# New place is a switch-to-switch port!
				# Hopefully, this is a packet we're flooding because we didn't
				# know the destination, and not because it's somehow not on a
				# path that we expect it to be on.
				# If spanning_tree is running, we might check that this port is
				# on the spanning tree (it should be).
				if packet.dst in mac_map:
					# Unfortunately, we know the destination.	It's possible that
					# we learned it while it was in flight, but it's also possible
					# that something has gone wrong.
					log.warning("Packet from %s to known destination %s arrived "
											"at %s.%i without flow", packet.src, packet.dst,
											dpid_to_str(self.dpid), event.port)

		# Decide the action of the packet
		if packet.dst.is_multicast:
			log.debug("Flood multicast from %s", packet.src)
			flood()
		else:
			# Detect if this packet is a specific packet
			if packetIsUDP(packet, log):
				# Check if the packet is management packet
				if packetDstIp(packet, IPAddr(MC.mngaddrConst).toUnsignedN(), log) and packetDstUDPPort(packet, MC.mngportConst, log):
					# XXX Not right: If yes, we need to send to higher layers
					# If yes, we can deal with this in global view
					retPkt = self.handleMngPacket(packet, event, log)
				# If not management, then should be data packets. Just drop them.
				else:
					pass

			#if packet.dst not in mac_map:
			#	log.debug("%s unknown -- flooding" % (packet.dst,))
			#	flood()
			#else:
			#	dest = mac_map[packet.dst]
			#	match = of.ofp_match.from_packet(packet)
			#	self.install_path(dest[0], dest[1], match, event)

	def disconnect (self):
		if self.connection is not None:
			log.debug("Disconnect %s" % (self.connection,))
			self.connection.removeListeners(self._listeners)
			self.connection = None
			self._listeners = None

	def connect (self, connection):
		if self.dpid is None:
			self.dpid = connection.dpid
		assert self.dpid == connection.dpid
		if self.ports is None:
			self.ports = connection.features.ports
		self.disconnect()
		log.debug("Connect %s" % (connection,))
		self.connection = connection
		self._listeners = self.listenTo(connection)
		self._connected_at = time.time()

	@property
	def is_holding_down (self):
		if self._connected_at is None: return True
		if time.time() - self._connected_at > FLOOD_HOLDDOWN:
			return False
		return True

	def _handle_ConnectionDown (self, event):
		self.disconnect()


class MCController (EventMixin):

	_eventMixin_events = set([
		TreeInstalled,
	])

	def __init__ (self):
		# Listen to dependencies
		def startup ():
			core.openflow.addListeners(self, priority=0)
			core.openflow_discovery.addListeners(self)
		core.call_when_ready(startup, ('openflow','openflow_discovery'))

	def _handle_LinkEvent (self, event):
		def flip (link):
			return Discovery.Link(link[2],link[3], link[0],link[1])

		l = event.link
		sw1 = switches[l.dpid1]
		sw2 = switches[l.dpid2]

		# Invalidate all flows and path info.
		# For link adds, this makes sure that if a new link leads to an
		# improved path, we use it.
		# For link removals, this makes sure that we don't use a
		# path that may have been broken.
		#NOTE: This could be radically improved! (e.g., not *ALL* paths break)
		# clear = of.ofp_flow_mod(command=of.OFPFC_DELETE)
		#for sw in switches.itervalues():
		#	if sw.connection is None: continue
		#	sw.connection.send(clear)
		path_map.clear()

		if event.removed:
			# This link no longer okay
			if sw2 in adjacency[sw1]: del adjacency[sw1][sw2]
			if sw1 in adjacency[sw2]: del adjacency[sw2][sw1]

			# But maybe there's another way to connect these...
			for ll in core.openflow_discovery.adjacency:
				if ll.dpid1 == l.dpid1 and ll.dpid2 == l.dpid2:
					if flip(ll) in core.openflow_discovery.adjacency:
						# Yup, link goes both ways
						adjacency[sw1][sw2] = ll.port1
						adjacency[sw2][sw1] = ll.port2
						# Fixed -- new link chosen to connect these
						break
		else:
			# If we already consider these nodes connected, we can
			# ignore this link up.
			# Otherwise, we might be interested...
			if adjacency[sw1][sw2] is None:
				# These previously weren't connected.	If the link
				# exists in both directions, we consider them connected now.
				if flip(l) in core.openflow_discovery.adjacency:
					# Yup, link goes both ways -- connected!
					adjacency[sw1][sw2] = l.port1
					adjacency[sw2][sw1] = l.port2

			# If we have learned a MAC on this port which we now know to
			# be connected to a switch, unlearn it.
			bad_macs = set()
			for mac,(sw,port) in mac_map.iteritems():
				if sw is sw1 and port == l.port1: bad_macs.add(mac)
				if sw is sw2 and port == l.port2: bad_macs.add(mac)
			for mac in bad_macs:
				log.debug("Unlearned %s", mac)
				del mac_map[mac]

	def _handle_ConnectionUp (self, event):
		sw = switches.get(event.dpid)
		if sw is None:
			# New switch
			sw = Switch()
			switches[event.dpid] = sw
			sw.connect(event.connection)
		else:
			sw.connect(event.connection)

	def _handle_BarrierIn (self, event):
		wp = waiting_trees.pop((event.dpid,event.xid), None)
		if not wp:
			#log.info("No waiting packet %s,%s", event.dpid, event.xid)
			return
		#log.debug("Notify waiting packet %s,%s", event.dpid, event.xid)
		wp.notify(event)


def launch ():
	core.registerNew(MCController)

	timeout = min(max(TREE_SETUP_TIME, 5) * 2, 15)
	Timer(timeout, WaitingTree.expire_waiting_trees, recurring=True)














######################################################################################
######################################################################################
######################################################################################
######################################################################################
######################################################################################
######################################################################################
######################################################################################
######################################################################################
######################################################################################
######################################################################################
######################################################################################
######################################################################################
######################################################################################
######################################################################################
######################################################################################

# import socket as skt
# from MCCommon import *
# from MCPacket import *
# import time
#
# from pox.core import core
# import pox.openflow.libopenflow_01 as of
# from pox.lib.util import dpid_to_str
# from pox.lib.util import str_to_bool
# import pox.openflow.libopenflow_01 as of
# from pox.openflow.discovery import Discovery
#
# log = core.getLogger()
#
# class MCController(MC):
# 	def __init__ (self):
# 		self.connN = 0
# 		self.connLst = {}
# 		self.macToPortLst = {}
# 		self.eventLst = {}
# 		self.packetLst = {}
#
#
#
#
# 	###############################################################################
# 	# Global information gathering
#
# 	def updateTopo(self):
#
#
#
#
#
#
# 	###############################################################################
# 	# OF communication parts
#
# 	def addConnection(self, connection):
# 		dpid = connection.dpid
# 		# Add connection to list
# 		self.connLst[dpid] = connection
# 		self.macToPortLst[dpid] = {}
# 		self.eventLst[dpid] = None
# 		self.packetLst[dpid] = None
#
# 		# We want to hear PacketIn messages, so we listen
# 		# to the connection
# 		self.connLst[dpid].addListeners(self)
#
# 		#log.debug("Initializing LearningSwitch, transparent=%s",
# 		#					str(self.transparent))
#
# 		self.connN += 1
#
# 	def delConnection(self, dpid):
# 		if dpid in self.connLst.keys():
# 			del self.connLst[dpid]
# 			del self.macToPortLst[dpid]
# 			del self.eventLst[dpid]
# 			del self.packetLst[dpid]
# 			self.connN -= 1
#
# 	def handle_PacketIn (self, packet):
# 		pass
#
# 	def _handle_PacketIn (self, event):
# 		"""
# 		Handles packet in messages from the switch.
# 		"""
#
# 		packet = event.parsed # This is the parsed packet data.
# 		if not packet.parsed:
# 			log.warning("Ignoring incomplete packet")
# 			return
#
# 		packet_in = event.ofp # The actual ofp_packet_in message.
#
# 		# Store the latest packet for each switch
# 		self.packetLst[packet.dpid] = packet
# 		self.eventLst[packet.dpid] = event
# 		self.macToPort[packet.dpid][self.packet.src] = self.event.port
#
# 		# Then handle this packet
# 		self.handle_PacketIn(packet)
#




