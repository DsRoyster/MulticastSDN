from mininet.topo import Topo
from mininet.net import Mininet

class MyTopo( Topo ):
	def __init__( self ):
		

		# Initialize topology
		Topo.__init__( self )

		# Add all nodes
		s1 = self.addHost('s1')
		s2 = self.addHost('s2')
		s3 = self.addHost('s3')
		sw0 = self.addSwitch( 'sw0' )
		sw11 = self.addSwitch( 'sw11' )
		sw12 = self.addSwitch( 'sw12' )
		sw13 = self.addSwitch( 'sw13' )
		sw21 = self.addSwitch( 'sw21' )
		sw22 = self.addSwitch( 'sw22' )
		sw23 = self.addSwitch( 'sw23' )
		r1 = self.addHost('r1')
		r2 = self.addHost('r2')
		r3 = self.addHost('r3')
		# s1.setIP('10.10.10.1')
		# s2.setIP('10.10.10.2')
		# s3.setIP('10.10.10.3')
		# r1.setIP('10.10.10.11')
		# r2.setIP('10.10.10.12')
		# r3.setIP('10.10.10.13')

		# Add links
		self.addLink( s1, sw0 )
		self.addLink( s2, sw0 )
		self.addLink( s3, sw0 )
		self.addLink( sw0, sw11 )
		self.addLink( sw0, sw12 )
		self.addLink( sw0, sw13 )
		self.addLink( sw11, sw21 )
		self.addLink( sw11, sw22 )
		self.addLink( sw11, sw23 )
		self.addLink( sw12, sw21 )
		self.addLink( sw12, sw22 )
		self.addLink( sw12, sw23 )
		self.addLink( sw13, sw21 )
		self.addLink( sw13, sw22 )
		self.addLink( sw13, sw23 )
		self.addLink( sw21, r1 )
		self.addLink( sw22, r2 )
		self.addLink( sw23, r3 )

topos = { 'mytopo': ( lambda: MyTopo() ) }
# Assign IP addresses
# topo.get(s1).setIP('10.10.10.1')
# topo.get(s2).setIP('10.10.10.2')
# topo.get(s3).setIP('10.10.10.3')
# topo.get(r1).setIP('10.10.10.11')
# topo.get(r2).setIP('10.10.10.12')
# topo.get(r3).setIP('10.10.10.13')