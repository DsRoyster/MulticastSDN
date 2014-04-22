from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.node import CPULimitedHost

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

		# Add links
		opth = {'bw':100}
		optsw = {'bw':5}
		self.addLink( s1, sw0, **opth )
		self.addLink( s2, sw0, **opth )
		self.addLink( s3, sw0, **opth )
		self.addLink( sw0, sw11, **optsw )
		self.addLink( sw0, sw12, **optsw )
		self.addLink( sw0, sw13, **optsw )
		self.addLink( sw11, sw21, **optsw )
		self.addLink( sw11, sw22, **optsw )
		self.addLink( sw11, sw23, **optsw )
		self.addLink( sw12, sw21, **optsw )
		self.addLink( sw12, sw22, **optsw )
		self.addLink( sw12, sw23, **optsw )
		self.addLink( sw13, sw21, **optsw )
		self.addLink( sw13, sw22, **optsw )
		self.addLink( sw13, sw23, **optsw )
		self.addLink( sw21, r1, **opth )
		self.addLink( sw22, r2, **opth )
		self.addLink( sw23, r3, **opth )

topos = { 'mytopo': ( lambda: MyTopo() ) }
#topo = topos['mytopo']
#net = Mininet(topo = topo, host=CPULimitedHost, link = TCLink)
#net.start


