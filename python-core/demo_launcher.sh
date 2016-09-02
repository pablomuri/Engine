#!/bin/bash

xterm -T "Python_core" -e python AdvancedProxyCore.py -c mycomp.xml &
cd ../ryu-shim && xterm -T "Ryu-Shim" -e ryu-manager ryu-shim.py &
cd ../ryu-backend && xterm -T "Ryu-backend + Modules" -e ryu-manager --ofp-tcp-listen-port 7733 ryu-backend.py tests/simple_switch.py tests/firewall1.py tests/firewall2.py &
sleep 3
cd ../python-core && xterm -T "Mininet" -e sudo ./mininet_script_netide_topo.py &