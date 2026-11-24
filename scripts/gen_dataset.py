#!/usr/bin/env python3
"""Generate labelled traffic in Mininet for integration/collect_dataset.py.
Usage: sudo python3 scripts/gen_dataset.py [rounds]
Needs the docker stack up and the collector running in the ml-bridge container."""
import json, os, random, subprocess, sys, time

# Mininet's Node.popen() reads os.environ['SHELL'] and raises KeyError when it is
# missing (e.g. when the script is launched through nsenter/docker exec, which
# does not export a login shell environment).
os.environ.setdefault('SHELL', '/bin/bash')

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'mininet'))
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.link import TCLink
from mininet.log import setLogLevel
import mininet_topology as mt

STATE = os.path.join(ROOT, 'data', 'label_state.json')
# host -> (switch, port); all in VLAN 100, victim h1 (10.0.0.1)
LOC = {'h2': ('s1', 2), 'h3': ('s1', 3), 'h16': ('s6', 1), 'h17': ('s6', 2), 'h18': ('s6', 3)}


def set_state(**kw):
    with open(STATE, 'w') as f:
        json.dump(kw, f)


def cleanup_stale_topology():
    """Remove any leftover Mininet topology.

    This script builds its own topology with the same bridge names (s1..s6) as
    mininet/mininet_topology.py. If an interactive topology is still running,
    OVS would reuse those bridges and the two topologies would fight over the
    same ports, corrupting the collected dataset.
    """
    try:
        subprocess.run(['mn', '-c'], check=False, timeout=60)
    except (OSError, subprocess.SubprocessError) as err:
        print(f'warning: could not clean up stale Mininet topology: {err}', flush=True)


def main(rounds):
    setLogLevel('error')
    cleanup_stale_topology()
    net = Mininet(topo=mt.DDoSTopo(), switch=OVSSwitch, controller=None, link=TCLink,
                  autoSetMacs=True, autoStaticArp=True)
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)
    net.addController('c1', controller=RemoteController, ip='127.0.0.1', port=6654)
    net.start(); mt.add_default_routes(net)
    set_state(mode='skip'); time.sleep(12)
    net.pingAll(timeout=1)
    h1 = net.get('h1'); h1.cmd('iperf3 -s -D')
    for h in ('h4', 'h7', 'h10', 'h13'):
        net.get(h).cmd('iperf3 -s -D')
    for r in range(rounds):
        # --- benign phase: mixed light/moderate legit traffic
        set_state(mode='skip'); time.sleep(11)
        set_state(mode='benign')
        procs = []
        for name in random.sample(list(LOC), 3):
            h = net.get(name); bw = random.choice([1, 2, 4, 6])
            procs.append(h.popen(f'iperf3 -c 10.0.0.1 -t 35 -b {bw}M -l 1000', shell=True))
            h.cmd('ping -c 20 -i 0.5 10.0.0.1 >/dev/null 2>&1 &')
        net.get('h5').cmd('iperf3 -c 10.0.1.1 -t 30 -b 3M >/dev/null 2>&1 &')
        net.get('h8').cmd('ping -c 25 -i 0.5 10.0.2.1 >/dev/null 2>&1 &')
        time.sleep(40)
        # --- attack phase: UDP flood from 1-2 hosts, random rate
        atk = random.sample(list(LOC), random.choice([1, 2]))
        set_state(mode='skip'); time.sleep(11)
        set_state(mode='attack', attackers=[list(LOC[a]) for a in atk], victim='10.0.0.1')
        for a in atk:
            net.get(a).cmd(f'iperf3 -c 10.0.0.1 -u -b {random.choice([30, 50, 80])}M -t 35 -l 1400 >/dev/null 2>&1 &')
        time.sleep(40)
        print(f"round {r}: attackers={atk}", flush=True)
    set_state(mode='skip')
    net.stop()


if __name__ == '__main__':
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 6)
