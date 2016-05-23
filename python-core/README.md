How it works.

To do the resolution, the core is storing flow-mods and packets-out recived from the backend. When the backend sends a fence message for each module, the resolution method is called.

For now, It only works with two modules. (Simple_switch and stealth_firewall)

-Flow_mod resolution:
The core first compare the match of the two flowmods. Then, if there are equals, It compares the action fields, if the actions are equals, save one flowmod for a later sending. Else, if there are one with no actions, It saves that flow-mod. If there are not flows with no actions, then saves the two flow-mods.

If the match are not equals, it saves the two flow mods.


-Packet_out resolution:
The packet_out resolution works the same way but It's not compare matches, only the actions field.


When the two fence messages arrive, the resolution method is called and then, the messages stored before are sended by the core.


-Using other SDN protocol.
If we wouldn't use OpenFlow, we would have to modify the CompositionManager.py file that contains the resolution methods and fence message handler. Also we would have to modify the OFMsg.py file that is used by the CompositionManager.





