# Zeek cluster node configuration.
#
# Rendered by infra/provision/vm-sec.sh: @@SPAN_OT_IF@@ / @@SPAN_DMZ_IF@@
# are replaced with the actual NIC names assigned by VirtualBox.
#
# Cluster mode is required because standalone takes only one interface;
# we need two SPAN listeners (OT zone + DMZ).

[manager]
type=manager
host=localhost

[proxy-1]
type=proxy
host=localhost

[worker-ot]
type=worker
host=localhost
interface=@@SPAN_OT_IF@@
lb_method=pf_ring
lb_procs=1

[worker-dmz]
type=worker
host=localhost
interface=@@SPAN_DMZ_IF@@
lb_method=pf_ring
lb_procs=1
