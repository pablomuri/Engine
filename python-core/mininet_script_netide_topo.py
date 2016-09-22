#!/usr/bin/env python

from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.node import Host
from mininet.node import OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink

def myNetwork():
	net = Mininet( topo=None,listenPort=6634,build=False,ipBase='10.0.0.0/16',link=TCLink)
	
	info( '*** Adding controller\n' )
	c0=net.addController(name='c0', controller=RemoteController, protocol='tcp', protocols='OpenFlow10', ip='127.0.0.1' )
	
	info( '*** Add switches\n')
	s1 = net.addSwitch('s1', cls=OVSKernelSwitch, dpid = '0000000000000001')

	
	info( '*** Add hosts\n')
	dmz = net.addHost('dns', cls=Host, ip='10.0.3.1/16')
	#www = net.addHost('www', cls=Host, ip='10.0.3.2/16')
	internet = net.addHost('internet', cls=Host, ip='10.0.2.1/16')
	interior = net.addHost('interior', cls=Host, ip='10.0.1.1/16')
	
	info( '*** Add links\n')
	net.addLink(s1, interior, port1=1)
	net.addLink(s1, internet, port1=2)
	#net.addLink(s1, www, port1=3)
	net.addLink(s1, dmz, port1=3)

	info( '*** Starting network\n')
	net.build()

	info( '*** Starting controllers\n')
	for controller in net.controllers:
		controller.start()
	
	info( '*** Starting switches\n')

	net.get('s1').start([c0])
	
	info( '*** Post configure switches and hosts\n')
	
	CLI(net)
	net.stop()

if __name__ == '__main__':
	setLogLevel( 'info' )
	myNetwork()
