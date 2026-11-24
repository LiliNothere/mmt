"""Collect a LABELLED training dataset from the live Faucet/Gauge pipeline.

Run inside the ml-bridge container:
    docker exec ddos-ml-bridge python -m integration.collect_dataset --out /app/data/FlowStatsfile.csv

The label comes from /app/data/label_state.json, written by scripts/gen_dataset.py:
    {"mode": "skip|benign|attack", "attackers": [["s6", 2]], "victim": "10.0.0.1"}
One row per host ingress port ('vlan' table). Rows are labelled 1 when the port belongs to an
attacker while an attack is running.
"""
import argparse, asyncio, csv, json, os, time
from ml_service.faucet_client import FaucetClient
from ml_service.features import flows_to_rows

FIELDS = ['timestamp', 'datapath_id', 'flow_id', 'switch', 'in_port', 'ip_dst', 'tp_src', 'tp_dst',
          'ip_proto', 'icmp_code', 'icmp_type', 'packet_count', 'byte_count',
          'packet_count_per_second', 'byte_count_per_second', 'avg_packet_size', 'label']


def read_state(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {"mode": "skip"}


async def main(a):
    client = FaucetClient()
    last = {}
    new_file = not os.path.exists(a.out) or os.path.getsize(a.out) == 0
    f = open(a.out, 'a', newline='')
    w = csv.DictWriter(f, fieldnames=FIELDS, extrasaction='ignore')
    if new_file:
        w.writeheader()
    prev_t = None
    end = time.time() + a.duration
    while time.time() < end:
        t0 = time.time()
        flows = await client.get_flow_stats()
        st = read_state(a.state)
        elapsed = a.interval if prev_t is None else t0 - prev_t
        prev_t = t0
        by_sw = {}
        for fl in flows:
            by_sw.setdefault(fl.switch_id, []).append(fl)
        n = 0
        for sw, fls in by_sw.items():
            known = set(last.get(sw, {}))
            rows, _ = flows_to_rows(sw, fls, last.setdefault(sw, {}), elapsed)
            if st.get('mode') == 'skip':
                continue
            atk = {(s, int(p)) for s, p in st.get('attackers', [])}
            for r in rows:
                if ':vlan:' not in r['flow_id']:
                    continue                      # ACL counters are only used to find the victim IP
                if r['flow_id'] not in known:
                    continue                      # first sighting -> no valid rate
                is_att = st.get('mode') == 'attack' and (sw, r['in_port']) in atk
                r['label'] = int(is_att)
                w.writerow(r); n += 1
        f.flush()
        print(f"{time.strftime('%X')} mode={st.get('mode')} rows={n}", flush=True)
        await asyncio.sleep(max(0, a.interval - (time.time() - t0)))
    f.close()
    await client.close()


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--out', default='/app/data/FlowStatsfile.csv')
    p.add_argument('--state', default='/app/data/label_state.json')
    p.add_argument('--interval', type=float, default=10)
    p.add_argument('--duration', type=float, default=3600)
    asyncio.run(main(p.parse_args()))
