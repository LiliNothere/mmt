"""
Faucet Controller Client for ML Service Integration
Communicates with Faucet via REST API and Prometheus metrics
"""

import asyncio
import logging
import time
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime

import httpx
import yaml
from prometheus_client import CollectorRegistry, Gauge, Counter, Histogram, push_to_gateway, generate_latest

from .config import settings

logger = logging.getLogger(__name__)


class _NoAliasDumper(yaml.SafeDumper):
    """Dump repeated rule dicts in full instead of as YAML &anchors/*aliases."""
    def ignore_aliases(self, data):
        return True

# fcntl is Unix-only; provide fallback for Windows
try:
    import fcntl
    HAS_FCNTL = True
except ImportError:
    HAS_FCNTL = False
    import msvcrt  # Windows file locking


@dataclass
class FlowStat:
    """Flow statistics from Faucet/Gauge"""
    switch_id: str
    flow_id: str
    in_port: int
    eth_type: int
    ipv4_src: str
    ipv4_dst: str
    ip_proto: int
    tcp_src: Optional[int] = None
    tcp_dst: Optional[int] = None
    udp_src: Optional[int] = None
    udp_dst: Optional[int] = None
    icmpv4_type: Optional[int] = None
    icmpv4_code: Optional[int] = None
    packet_count: int = 0
    byte_count: int = 0
    duration_sec: int = 0
    duration_nsec: int = 0
    idle_timeout: int = 0
    hard_timeout: int = 0
    priority: int = 0
    cookie: int = 0
    timestamp: float = 0


@dataclass
class PortStat:
    """Port statistics from Faucet/Gauge"""
    switch_id: str
    port_number: int
    port_name: str
    tx_packets: int = 0
    rx_packets: int = 0
    tx_bytes: int = 0
    rx_bytes: int = 0
    tx_errors: int = 0
    rx_errors: int = 0
    dropped: int = 0
    timestamp: float = 0


class FaucetClient:
    """Client for communicating with Faucet controller"""

    def __init__(self):
        self.faucet_url = f"http://{settings.faucet_host}:{settings.faucet_rest_port}"
        self.gauge_url = __import__("os").environ.get("GAUGE_URL") or f"http://{settings.faucet_host}:{settings.gauge_prometheus_port}"
        self.acl_name = settings.faucet_acl_name
        self.client = httpx.AsyncClient(timeout=30.0)

        # Prometheus metrics for ML service
        self.registry = CollectorRegistry()
        self.predictions_total = Counter(
            'ddos_predictions_total',
            'Total predictions made',
            ['result'],
            registry=self.registry
        )
        self.attack_detected = Counter(
            'ddos_attacks_detected_total',
            'Total DDoS attacks detected',
            ['switch', 'victim'],
            registry=self.registry
        )
        self.mitigation_actions = Counter(
            'ddos_mitigation_actions_total',
            'Total mitigation actions taken',
            ['action', 'switch', 'result'],
            registry=self.registry
        )
        self.prediction_latency = Histogram(
            'ddos_prediction_latency_seconds',
            'Prediction latency in seconds',
            registry=self.registry
        )
        self.flow_count = Gauge(
            'ddos_flows_processed',
            'Number of flows processed',
            ['switch'],
            registry=self.registry
        )
        self.acl_operations = Counter(
            'ddos_acl_operations_total',
            'Total ACL operations',
            ['operation', 'switch', 'result'],
            registry=self.registry
        )

    async def close(self):
        await self.client.aclose()

    async def _prom_query(self, query: str) -> List[Dict[str, Any]]:
        """Run an instant query against Prometheus and return the result list."""
        response = await self.client.get(
            f"{self.gauge_url}/api/v1/query", params={'query': query}
        )
        if response.status_code != 200:
            return []
        data = response.json()
        return data['data']['result'] if data.get('status') == 'success' else []

    async def get_flow_stats(self) -> List[FlowStat]:
        """Fetch flow statistics exported by Gauge (flow_table watcher).

        Gauge exports one series per OpenFlow flow per Faucet table, named
        ``flow_packet_count_<table>`` / ``flow_byte_count_<table>``; the match
        fields are *labels* (in_port, ipv4_dst, ip_proto, ...), there is no
        per-field metric. Faucet pre-programs its tables, so per-5-tuple flows
        do not exist. We therefore build two kinds of records:

        * ``vlan`` table rows     -> one record per host ingress port
          (aggregate traffic entering from that port; used to pick the source port)
        * ``vlan_acl`` table rows -> records that carry ipv4_dst / ip_proto / L4 port
          (ACL rule counters; used to identify the victim IP)
        """
        try:
            pkts = await self._prom_query('{__name__=~"flow_packet_count_(vlan|vlan_acl)"}')
            byts = await self._prom_query('{__name__=~"flow_byte_count_(vlan|vlan_acl)"}')

            def key_of(metric: Dict[str, str]) -> str:
                lbl = {k: v for k, v in metric.items() if k != '__name__'}
                table = metric.get('__name__', '').rsplit('flow_packet_count_', 1)[-1] \
                    .rsplit('flow_byte_count_', 1)[-1]
                return table + '|' + '|'.join(f"{k}={lbl[k]}" for k in sorted(lbl))

            byte_by_key = {key_of(r['metric']): int(float(r['value'][1])) for r in byts}
            trunk = settings.faucet_trunk_port_threshold
            now = time.time()
            flows: Dict[str, FlowStat] = {}

            for r in pkts:
                m = r['metric']
                table = m.get('__name__', '').replace('flow_packet_count_', '')
                switch = m.get('dp_name', m.get('dp_id', 'unknown'))
                packets = int(float(r['value'][1]))
                k = key_of(m)

                def to_int(v, base=10):
                    try:
                        return int(str(v).split('/')[0], base)
                    except (TypeError, ValueError):
                        return 0

                in_port = to_int(m.get('in_port'))
                if table == 'vlan':
                    # Only host (access) ports; trunk ports carry aggregated traffic
                    if not in_port or in_port >= trunk or m.get('vlan_vid') not in ('0', None):
                        continue
                else:  # vlan_acl: keep only rules that identify an IP destination
                    if 'ipv4_dst' not in m:
                        continue

                flows[k] = FlowStat(
                    switch_id=switch,
                    flow_id=f"{switch}:{table}:{k.split('|', 1)[1]}",
                    in_port=in_port,
                    eth_type=to_int(m.get('eth_type'), 0) if m.get('eth_type') else 0,
                    ipv4_src=m.get('ipv4_src', '0.0.0.0').split('/')[0],
                    ipv4_dst=m.get('ipv4_dst', '0.0.0.0').split('/')[0],
                    ip_proto=to_int(m.get('ip_proto')),
                    tcp_src=to_int(m.get('tcp_src')) or None,
                    tcp_dst=to_int(m.get('tcp_dst')) or None,
                    udp_src=to_int(m.get('udp_src')) or None,
                    udp_dst=to_int(m.get('udp_dst')) or None,
                    icmpv4_type=to_int(m.get('icmpv4_type')) if 'icmpv4_type' in m else None,
                    icmpv4_code=to_int(m.get('icmpv4_code')) if 'icmpv4_code' in m else None,
                    packet_count=packets,
                    byte_count=byte_by_key.get(k, 0),
                    priority=to_int(m.get('priority')),
                    cookie=to_int(m.get('cookie')),
                    timestamp=now,
                )
            return list(flows.values())

        except Exception as e:
            logger.error(f"Failed to get flow stats: {e}")
            return []

    async def get_port_stats(self) -> List[PortStat]:
        """Fetch port statistics (Gauge metric names: of_port_{rx,tx}_{packets,bytes,errors,dropped})."""
        try:
            queries = {
                'tx_packets': 'of_port_tx_packets',
                'rx_packets': 'of_port_rx_packets',
                'tx_bytes': 'of_port_tx_bytes',
                'rx_bytes': 'of_port_rx_bytes',
                'tx_errors': 'of_port_tx_errors',
                'rx_errors': 'of_port_rx_errors',
            }
            ports_by_id: Dict[str, PortStat] = {}

            def get_port(metric) -> PortStat:
                switch = metric.get('dp_name', metric.get('dp_id', 'unknown'))
                port = metric.get('port', metric.get('port_name', '0'))
                key = f"{switch}:{port}"
                if key not in ports_by_id:
                    ports_by_id[key] = PortStat(
                        switch_id=switch,
                        port_number=int(port) if port.isdigit() else 0,
                        port_name=port,
                        timestamp=time.time(),
                    )
                return ports_by_id[key]

            for attr, q in queries.items():
                for r in await self._prom_query(q):
                    setattr(get_port(r['metric']), attr, int(float(r['value'][1])))
            # 'dropped' = rx_dropped + tx_dropped
            for q in ('of_port_rx_dropped', 'of_port_tx_dropped'):
                for r in await self._prom_query(q):
                    ps = get_port(r['metric'])
                    ps.dropped += int(float(r['value'][1]))

            return list(ports_by_id.values())

        except Exception as e:
            logger.error(f"Failed to get port stats: {e}")
            return []

    async def apply_acl(self, switch_id: str, port: int, block: bool = True) -> bool:
        """Apply ACL to block/unblock port on switch with atomic file operations.

        Updates the per-port ACL block-malicious-<switch>-p<port> in acls/block-malicious.yaml
        (included by faucet.yaml and attached to each host port via acls_in).
        """
        try:
            # Skip trunk/inter-switch ports (configurable threshold)
            # These are high ports that carry multiple VLANs
            trunk_threshold = settings.faucet_trunk_port_threshold
            if port >= trunk_threshold:
                logger.warning(f"Refusing to block trunk port {port} on {switch_id} (threshold: {trunk_threshold})")
                self.acl_operations.labels(
                    operation='block' if block else 'unblock',
                    switch=switch_id,
                    result='skipped_trunk'
                ).inc()
                return False

            # One ACL per host (ingress) port: block-malicious-<switch>-p<port>
            acl_name = f"{self.acl_name}-{switch_id}-p{port}"
            acl_file = Path(f"/etc/faucet/acls/{self.acl_name}.yaml")
            success = await self._atomic_acl_update(acl_file, acl_name, block)

            if success:
                # Trigger Faucet reload via SIGHUP
                await self.reload_faucet_config()

                self.acl_operations.labels(
                    operation='block' if block else 'unblock',
                    switch=switch_id,
                    result='success'
                ).inc()

                logger.info(f"{'Blocked' if block else 'Unblocked'} port {port} on {switch_id}")
                return True
            else:
                self.acl_operations.labels(
                    operation='block' if block else 'unblock',
                    switch=switch_id,
                    result='failed'
                ).inc()
                return False

        except Exception as e:
            logger.error(f"Failed to apply ACL: {e}")
            self.acl_operations.labels(
                operation='block' if block else 'unblock',
                switch=switch_id,
                result='error'
            ).inc()
            return False

    async def _atomic_acl_update(self, acl_file: Path, acl_name: str, block: bool) -> bool:
        """Atomically rewrite the per-port ACL inside the ACL file.

        Layout: {'acls': {'block-malicious-s6-p2': [<drop-all if blocked>, <allow-all>]}}
        The trailing allow-all is required: Faucet drops anything an ACL does not match.
        The ACL must already be declared (and attached to the port) in faucet.yaml.
        """
        lock_path = acl_file.with_suffix('.lock')
        try:
            acl_file.parent.mkdir(parents=True, exist_ok=True)
            with open(lock_path, 'a+') as lock:
                if HAS_FCNTL:
                    fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
                try:
                    data = {}
                    if acl_file.exists():
                        data = yaml.safe_load(acl_file.read_text()) or {}
                    acls = data.setdefault('acls', {})
                    if acl_name not in acls:
                        logger.error(f"ACL {acl_name} is not declared in {acl_file} / faucet.yaml "
                                     f"(only host access ports can be blocked)")
                        return False
                    allow_all = {'rule': {'actions': {'allow': True}}}
                    drop_all = {'rule': {'actions': {'allow': False}}}
                    acls[acl_name] = [drop_all, allow_all] if block else [allow_all]

                    # Keep the file's header comment, write atomically (temp + rename)
                    header = "".join(l for l in acl_file.read_text().splitlines(True)
                                     if l.startswith('#')) if acl_file.exists() else ''
                    tmp = acl_file.with_suffix('.tmp')
                    with open(tmp, 'w') as f:
                        f.write(header)
                        yaml.dump(data, f, Dumper=_NoAliasDumper, default_flow_style=False)
                        f.flush()
                        os.fsync(f.fileno())
                    os.replace(tmp, acl_file)
                finally:
                    if HAS_FCNTL:
                        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
            return True
        except Exception as e:
            logger.error(f"Atomic ACL update failed: {e}")
            return False

    async def reload_faucet_config(self) -> bool:
        """Trigger Faucet configuration reload via SIGHUP signal.

        REST API reload is deprecated. SIGHUP causes Faucet to reload
        configuration files including ACLs without restarting.
        """
        try:
            import subprocess
            try:
                result = subprocess.run(
                    ['pkill', '-HUP', '-f', 'faucet.faucet'],
                    capture_output=True,
                    timeout=5
                )
            except FileNotFoundError:      # no pkill in the slim ML image
                result = None
            if result is not None and result.returncode == 0:
                logger.info("Sent SIGHUP to Faucet process for config reload")
                return True
            # Faucet chạy ở container khác nên pkill không thấy. Faucet được bật
            # FAUCET_CONFIG_STAT_RELOAD=1 sẽ tự reload khi file ACL đổi.
            logger.info("Faucet not local; relying on FAUCET_CONFIG_STAT_RELOAD to pick up ACL change")
            return True
        except Exception as e:
            logger.error(f"Failed to reload Faucet config: {e}")
            return False

    async def get_switch_status(self) -> Dict[str, Any]:
        """Get Faucet switch status"""
        try:
            response = await self.client.get(f"{self.faucet_url}/metrics")
            if response.status_code == 200:
                return {"status": "ok", "metrics": response.text[:1000]}
            return {"status": "error"}
        except Exception as e:
            logger.error(f"Failed to get switch status: {e}")
            return {"status": "error", "error": str(e)}

    def record_prediction(self, is_ddos: bool, switch: str = "", victim: str = "") -> None:
        """Record prediction metrics"""
        self.predictions_total.labels(result='ddos' if is_ddos else 'benign').inc()
        if is_ddos and victim:
            self.attack_detected.labels(switch=switch, victim=victim).inc()

    def record_mitigation(self, action: str, switch: str, success: bool) -> None:
        """Record mitigation action"""
        self.mitigation_actions.labels(
            action=action,
            switch=switch,
            result='success' if success else 'failed'
        ).inc()

    def record_latency(self, latency: float) -> None:
        """Record prediction latency"""
        self.prediction_latency.observe(latency)

    def update_flow_count(self, switch: str, count: int) -> None:
        """Update flow count gauge"""
        self.flow_count.labels(switch=switch).set(count)

    def push_metrics(self, gateway: str = "pushgateway:9091") -> None:
        """Push metrics to Prometheus Pushgateway"""
        try:
            push_to_gateway(gateway, job='ddos_ml_service', registry=self.registry)
        except Exception as e:
            logger.warning(f"Failed to push metrics: {e}")

    def get_metrics(self) -> bytes:
        """Get Prometheus metrics in text format"""
        return generate_latest(self.registry)


class FaucetConfigManager:
    """Manage Faucet configuration files"""

    def __init__(self, config_dir: Path = Path("/etc/faucet")):
        self.config_dir = config_dir
        self.acl_dir = config_dir / "acls"
        self.acl_dir.mkdir(parents=True, exist_ok=True)

    def write_acl(self, name: str, rules: List[Dict]) -> bool:
        """Write ACL file atomically with proper 'acls:' wrapper"""
        try:
            acl_file = self.acl_dir / f"{name}.yaml"
            temp_file = acl_file.with_suffix('.tmp')

            # Wrap rules in 'acls:' dict for Faucet
            data = {'acls': {name: rules}}

            with open(temp_file, 'w') as f:
                yaml.dump(data, f, default_flow_style=False)

            temp_file.replace(acl_file)
            return True
        except Exception as e:
            logger.error(f"Failed to write ACL {name}: {e}")
            return False

    def read_acl(self, name: str) -> List[Dict]:
        """Read ACL file"""
        try:
            acl_file = self.acl_dir / f"{name}.yaml"
            if acl_file.exists():
                with open(acl_file) as f:
                    data = yaml.safe_load(f) or {}
                    # Extract rules from 'acls' wrapper
                    return data.get('acls', {}).get(name, [])
            return []
        except Exception as e:
            logger.error(f"Failed to read ACL {name}: {e}")
            return []

    def add_block_rule(self, acl_name: str, port: int, switch: str = None) -> bool:
        """Add port block rule to ACL"""
        rules = self.read_acl(acl_name)

        # Check if rule exists
        for rule in rules:
            if rule.get('rule', {}).get('in_port') == port:
                rule['rule']['actions']['allow'] = False
                return self.write_acl(acl_name, rules)

        # Add new rule
        new_rule = {
            "rule": {
                "in_port": port,
                "actions": {"allow": False}
            }
        }
        if switch:
            new_rule["rule"]["dp_name"] = switch

        rules.append(new_rule)
        return self.write_acl(acl_name, rules)

    def remove_block_rule(self, acl_name: str, port: int) -> bool:
        """Remove port block rule from ACL"""
        rules = self.read_acl(acl_name)

        # Remove rule for this port
        rules = [r for r in rules if r.get('rule', {}).get('in_port') != port]

        return self.write_acl(acl_name, rules)

    def generate_faucet_config(self, switches: List[Dict]) -> str:
        """Generate Faucet config from topology"""
        # This would generate faucet.yaml from topology description
        # For now, return template
        return ""