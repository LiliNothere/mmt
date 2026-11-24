"""Shared feature extraction used by the live bridge and the dataset collector,
so that training and inference see exactly the same feature definition."""
from typing import Dict, List, Optional, Tuple


def flows_to_rows(switch_id: str, flows: list, last_stats: Dict[str, dict],
                  elapsed: float) -> Tuple[List[dict], Optional[str]]:
    """Turn FlowStat objects into feature rows (rates from counter deltas).

    Mutates ``last_stats`` (counter snapshot for the next poll).
    Returns (rows, top_victim_ip) where top_victim_ip is the destination IP of the
    ACL counter with the highest packet rate.
    """
    rows: List[dict] = []
    top_rate, top_ip = -1.0, None
    dpid = int(switch_id.lstrip('s')) if switch_id.startswith('s') and switch_id[1:].isdigit() else 0
    for f in flows:
        prev = last_stats.get(f.flow_id)
        if prev is None:
            d_pkts = d_bytes = 0          # first sighting: no rate yet
        else:
            d_pkts = max(0, f.packet_count - prev['packet_count'])
            d_bytes = max(0, f.byte_count - prev['byte_count'])
        pps = d_pkts / elapsed if elapsed > 0 else 0.0
        bps = d_bytes / elapsed if elapsed > 0 else 0.0
        last_stats[f.flow_id] = {'packet_count': f.packet_count, 'byte_count': f.byte_count}

        if f.ipv4_dst not in ('0.0.0.0', '') and pps >= top_rate:
            top_rate, top_ip = pps, f.ipv4_dst

        rows.append({
            'timestamp': f.timestamp, 'datapath_id': dpid, 'flow_id': f.flow_id,
            'switch': switch_id, 'in_port': f.in_port, 'ip_dst': f.ipv4_dst,
            'tp_src': f.tcp_src or f.udp_src or 0,
            'tp_dst': f.tcp_dst or f.udp_dst or 0,
            'ip_proto': f.ip_proto,
            'icmp_code': f.icmpv4_code or 0, 'icmp_type': f.icmpv4_type or 0,
            'packet_count': f.packet_count, 'byte_count': f.byte_count,
            'packet_count_per_second': pps, 'byte_count_per_second': bps,
            'avg_packet_size': (d_bytes / d_pkts) if d_pkts else 0.0,
        })
    return rows, top_ip
