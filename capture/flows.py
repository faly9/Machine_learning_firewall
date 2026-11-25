from collections import defaultdict, deque
from time import monotonic
from statistics import mean, pstdev

from scapy.all import IP, TCP, UDP, ICMP

from config import (
    PORTSCAN_WINDOW_SECONDS,
    PORTSCAN_THRESHOLD,
    PORTSCAN_ALERT_COOLDOWN,
)


# ============================================================
# 23 CARACTERISTIQUES DU RANDOM FOREST
# ============================================================

FEATURES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "SYN Flag Count",
    "ACK Flag Count",
    "RST Flag Count",
    "FIN Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Packet Length Mean",
    "Fwd Packet Length Max",
    "Bwd Packet Length Max",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward"
]


class WindowAggregator:

    def __init__(self, window_seconds=10, min_packets=3):

        self.window_seconds = window_seconds
        self.min_packets = min_packets

        self.flows = {}
        self.started = monotonic()

        # ----------------------------------------------------
        # PORT SCAN
        # ----------------------------------------------------

        self.portscan_windows = defaultdict(deque)
        self.portscan_last_alert = {}
        self.portscan_alerts = []

        # ----------------------------------------------------
        # DETECTION COMPORTEMENTALE
        # ----------------------------------------------------

        self.behavior_window_seconds = 10

        self.ssh_threshold = 15
        self.ftp_threshold = 15
        self.http_threshold = 30

        self.syn_flood_threshold = 50
        self.dos_threshold = 100

        self.ddos_threshold = 100
        self.ddos_min_sources = 5

        self.behavior_windows = defaultdict(deque)
        self.service_windows = defaultdict(deque)

        self.behavior_last_alert = {}
        self.behavior_alerts = []

        self.behavior_alert_cooldown = 5

        # ----------------------------------------------------
        # NETTOYAGE MEMOIRE (evite la croissance infinie
        # des dictionnaires de fenetres sur un lab longue duree)
        # ----------------------------------------------------

        self._last_gc = monotonic()
        self._gc_interval = 30  # secondes

    # ========================================================
    # GESTION DES ENDPOINTS
    # ========================================================

    @staticmethod
    def _endpoint(ip, port):
        return (ip, int(port))

    @staticmethod
    def _new_flow(
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol
    ):

        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,

            "src_port": src_port,
            "dst_port": dst_port,

            "protocol": protocol,

            "fwd_packets": 0,
            "bwd_packets": 0,

            "fwd_bytes": 0,
            "bwd_bytes": 0,

            "fwd_lengths": [],
            "bwd_lengths": [],

            "timestamps": [],

            "syn": 0,
            "ack": 0,
            "rst": 0,
            "fin": 0,

            "init_win_fwd": -1,
            "init_win_bwd": -1,

            "act_data_pkt_fwd": 0,
            "min_seg_size_forward": None
        }

    # ========================================================
    # EMISSION DES ALERTES
    # ========================================================

    def _emit_behavior(
        self,
        detection,
        src_ip,
        dst_ip,
        detail,
        timestamp,
        decision="SUSPECT",
        **extra
    ):

        key = (detection, src_ip, dst_ip)

        last_alert = self.behavior_last_alert.get(key)

        if (
            last_alert is not None
            and timestamp - last_alert
            < self.behavior_alert_cooldown
        ):
            return

        self.behavior_last_alert[key] = timestamp

        alert = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "detection": detection,
            "decision": decision,
            "detail": detail,
            **extra
        }

        self.behavior_alerts.append(alert)

    # ========================================================
    # DETECTION PORT SCAN
    # ========================================================

    def _observe_portscan(
        self,
        src_ip,
        dst_ip,
        dst_port,
        timestamp
    ):

        key = (src_ip, dst_ip)

        events = self.portscan_windows[key]

        events.append((timestamp, dst_port))

        while (
            events
            and timestamp - events[0][0]
            > PORTSCAN_WINDOW_SECONDS
        ):
            events.popleft()

        unique_ports = {
            port for _, port in events
        }

        if len(unique_ports) < PORTSCAN_THRESHOLD:
            return

        last_alert = self.portscan_last_alert.get(key)

        if (
            last_alert is not None
            and timestamp - last_alert
            < PORTSCAN_ALERT_COOLDOWN
        ):
            return

        self.portscan_last_alert[key] = timestamp

        alert = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "unique_ports": len(unique_ports),
            "ports": sorted(unique_ports),
            "window_seconds": PORTSCAN_WINDOW_SECONDS,
            "detection": "PORTSCAN_BEHAVIOR",
            "decision": "MALICIOUS"
        }

        self.portscan_alerts.append(alert)

    def flush_portscan_alerts(self):

        alerts = self.portscan_alerts[:]
        self.portscan_alerts.clear()

        return alerts

    # ========================================================
    # DETECTION SSH / FTP / HTTP
    # ========================================================

    def _observe_service(
        self,
        src_ip,
        dst_ip,
        dst_port,
        timestamp
    ):

        service = None
        threshold = None

        if dst_port == 22:
            service = "SSH_CONNECTION_BURST_BEHAVIOR"
            threshold = self.ssh_threshold

        elif dst_port == 21:
            service = "FTP_CONNECTION_BURST_BEHAVIOR"
            threshold = self.ftp_threshold

        elif dst_port in {80, 443, 8080, 8443}:
            service = "HTTP_CONNECTION_BURST_BEHAVIOR"
            threshold = self.http_threshold

        if service is None:
            return

        key = (src_ip, dst_ip, dst_port)

        events = self.service_windows[key]

        events.append(timestamp)

        while (
            events
            and timestamp - events[0]
            > self.behavior_window_seconds
        ):
            events.popleft()

        if len(events) < threshold:
            return

        # Rafale de connexions au-dela du seuil : classee
        # directement MALICIOUS (detection deterministe par seuil,
        # pas une heuristique floue).
        self._emit_behavior(
            service,
            src_ip,
            dst_ip,
            (
                f"{len(events)} connexions TCP initiales "
                f"vers le port {dst_port} en "
                f"{self.behavior_window_seconds} secondes"
            ),
            timestamp,
            decision="MALICIOUS",
            attempts=len(events),
            destination_port=dst_port
        )

    # ========================================================
    # DETECTION DOS / DDOS / SYN FLOOD
    # ========================================================

    def _observe_traffic(
        self,
        src_ip,
        dst_ip,
        dst_port,
        protocol,
        is_syn,
        timestamp
    ):

        window = self.behavior_window_seconds

        events = self.behavior_windows[dst_ip]

        events.append((
            timestamp,
            src_ip,
            dst_port,
            protocol,
            is_syn
        ))

        # Nettoyage de la fenêtre
        while (
            events
            and timestamp - events[0][0] > window
        ):
            events.popleft()

        # ----------------------------------------------------
        # DOS : volume élevé d'une seule source
        # ----------------------------------------------------

        source_events = [
            event for event in events
            if event[1] == src_ip
        ]

        if len(source_events) >= self.dos_threshold:

            # CORRECTION : un depassement net de seuil volumetrique
            # est une preuve suffisante -> MALICIOUS (et non SUSPECT),
            # sinon le score de risque peut ne jamais declencher
            # le blocage automatique pendant un test DoS.
            self._emit_behavior(
                "DOS_BEHAVIOR",
                src_ip,
                dst_ip,
                (
                    f"{len(source_events)} paquets envoyés "
                    f"en {window} secondes"
                ),
                timestamp,
                decision="MALICIOUS",
                packet_count=len(source_events)
            )

        # ----------------------------------------------------
        # SYN FLOOD
        # ----------------------------------------------------

        source_syn_events = [
            event for event in events
            if event[1] == src_ip and event[4]
        ]

        if len(source_syn_events) >= self.syn_flood_threshold:

            # CORRECTION : idem, le SYN flood est une detection
            # deterministe -> MALICIOUS directement.
            self._emit_behavior(
                "SYN_FLOOD_BEHAVIOR",
                src_ip,
                dst_ip,
                (
                    f"{len(source_syn_events)} paquets SYN "
                    f"en {window} secondes"
                ),
                timestamp,
                decision="MALICIOUS",
                packet_count=len(source_syn_events)
            )

        # ----------------------------------------------------
        # DDOS : plusieurs sources vers une destination
        # ----------------------------------------------------

        unique_sources = {
            event[1] for event in events
        }

        if (
            len(events) >= self.ddos_threshold
            and len(unique_sources) >= self.ddos_min_sources
        ):

            # Reste "MALICIOUS" mais non bloquable individuellement
            # (blockable=False) car la source est "MULTIPLE" :
            # a traiter via une regle de blocage collective/CIDR
            # cote firewall, pas via decision.engine.
            self._emit_behavior(
                "DDOS_BEHAVIOR",
                "MULTIPLE",
                dst_ip,
                (
                    f"{len(events)} paquets provenant de "
                    f"{len(unique_sources)} sources "
                    f"en {window} secondes"
                ),
                timestamp,
                decision="MALICIOUS",
                packet_count=len(events),
                sources=sorted(unique_sources),
                blockable=False
            )

    # ========================================================
    # OBSERVATION GENERALE DU TRAFIC
    # ========================================================

    def _observe_behavior(
        self,
        src_ip,
        dst_ip,
        dst_port,
        protocol,
        is_syn,
        timestamp
    ):

        self._observe_traffic(
            src_ip,
            dst_ip,
            dst_port,
            protocol,
            is_syn,
            timestamp
        )

        if protocol == 6 and is_syn:

            self._observe_service(
                src_ip,
                dst_ip,
                dst_port,
                timestamp
            )

        self._maybe_garbage_collect(timestamp)

    def flush_behavior_alerts(self):

        alerts = self.behavior_alerts[:]
        self.behavior_alerts.clear()

        return alerts

    # ========================================================
    # NETTOYAGE PERIODIQUE DES FENETRES
    # ========================================================
    # Sans ca, portscan_windows / behavior_windows / service_windows
    # et les dicts de cooldown associes grossissent indefiniment
    # (une entree par IP/port/paire jamais revue), ce qui finit
    # par degrader les performances sur un lab qui tourne longtemps.

    def _maybe_garbage_collect(self, timestamp):

        now = monotonic()

        if now - self._last_gc < self._gc_interval:
            return

        self._last_gc = now

        cutoff_portscan = timestamp - PORTSCAN_WINDOW_SECONDS
        cutoff_behavior = timestamp - self.behavior_window_seconds

        for key in list(self.portscan_windows.keys()):

            events = self.portscan_windows[key]

            if not events or events[-1][0] < cutoff_portscan:
                del self.portscan_windows[key]

        for key in list(self.behavior_windows.keys()):

            events = self.behavior_windows[key]

            if not events or events[-1][0] < cutoff_behavior:
                del self.behavior_windows[key]

        for key in list(self.service_windows.keys()):

            events = self.service_windows[key]

            if not events or events[-1] < cutoff_behavior:
                del self.service_windows[key]

        stale_cutoff = timestamp - max(
            PORTSCAN_ALERT_COOLDOWN,
            self.behavior_alert_cooldown
        ) * 10

        for key in list(self.portscan_last_alert.keys()):
            if self.portscan_last_alert[key] < stale_cutoff:
                del self.portscan_last_alert[key]

        for key in list(self.behavior_last_alert.keys()):
            if self.behavior_last_alert[key] < stale_cutoff:
                del self.behavior_last_alert[key]

    # ========================================================
    # CAPTURE DES PAQUETS
    # ========================================================

    def add_packet(self, pkt):

        if IP not in pkt:
            return

        ip = pkt[IP]

        timestamp = float(pkt.time)

        # ----------------------------------------------------
        # TCP
        # ----------------------------------------------------

        if TCP in pkt:

            protocol = 6

            src_port = int(pkt[TCP].sport)
            dst_port = int(pkt[TCP].dport)

            tcp = pkt[TCP]

            flags = int(tcp.flags)

            is_syn = bool(
                flags & 0x02
                and not (flags & 0x10)
            )

            if is_syn:

                self._observe_portscan(
                    ip.src,
                    ip.dst,
                    dst_port,
                    timestamp
                )

            self._observe_behavior(
                ip.src,
                ip.dst,
                dst_port,
                protocol,
                is_syn,
                timestamp
            )

        # ----------------------------------------------------
        # UDP
        # ----------------------------------------------------

        elif UDP in pkt:

            protocol = 17

            src_port = int(pkt[UDP].sport)
            dst_port = int(pkt[UDP].dport)

            self._observe_behavior(
                ip.src,
                ip.dst,
                dst_port,
                protocol,
                False,
                timestamp
            )

        # ----------------------------------------------------
        # ICMP
        # ----------------------------------------------------

        elif ICMP in pkt:

            protocol = 1

            src_port = 0
            dst_port = 0

            self._observe_behavior(
                ip.src,
                ip.dst,
                dst_port,
                protocol,
                False,
                timestamp
            )

        else:
            return

        # ----------------------------------------------------
        # CREATION DE LA CLE DU FLUX
        # ----------------------------------------------------

        src_endpoint = self._endpoint(
            ip.src,
            src_port
        )

        dst_endpoint = self._endpoint(
            ip.dst,
            dst_port
        )

        endpoints = sorted([
            src_endpoint,
            dst_endpoint
        ])

        flow_key = (
            endpoints[0],
            endpoints[1],
            protocol
        )

        # ----------------------------------------------------
        # INITIALISATION DU FLUX
        # ----------------------------------------------------

        if flow_key not in self.flows:

            self.flows[flow_key] = self._new_flow(
                ip.src,
                ip.dst,
                src_port,
                dst_port,
                protocol
            )

        flow = self.flows[flow_key]

        # ----------------------------------------------------
        # DETERMINATION DU SENS
        # ----------------------------------------------------

        forward = (
            src_endpoint == self._endpoint(
                flow["src_ip"],
                flow["src_port"]
            )
        )

        packet_length = float(len(ip))

        flow["timestamps"].append(timestamp)

        # ----------------------------------------------------
        # DRAPEAUX TCP
        # ----------------------------------------------------

        if TCP in pkt:

            flags = int(pkt[TCP].flags)

            if flags & 0x02:
                flow["syn"] += 1

            if flags & 0x10:
                flow["ack"] += 1

            if flags & 0x04:
                flow["rst"] += 1

            if flags & 0x01:
                flow["fin"] += 1

        # ----------------------------------------------------
        # FORWARD
        # ----------------------------------------------------

        if forward:

            flow["fwd_packets"] += 1
            flow["fwd_bytes"] += packet_length

            flow["fwd_lengths"].append(
                packet_length
            )

            if TCP in pkt:

                tcp = pkt[TCP]

                if flow["init_win_fwd"] == -1:

                    flow["init_win_fwd"] = int(
                        tcp.window
                    )

                payload_length = len(
                    bytes(tcp.payload)
                )

                if payload_length > 0:
                    flow["act_data_pkt_fwd"] += 1

                segment_size = int(
                    tcp.dataofs or 5
                ) * 4

                current = flow[
                    "min_seg_size_forward"
                ]

                if current is None or segment_size < current:

                    flow["min_seg_size_forward"] = segment_size

        # ----------------------------------------------------
        # BACKWARD
        # ----------------------------------------------------

        else:

            flow["bwd_packets"] += 1
            flow["bwd_bytes"] += packet_length

            flow["bwd_lengths"].append(
                packet_length
            )

            if TCP in pkt:

                tcp = pkt[TCP]

                if flow["init_win_bwd"] == -1:

                    flow["init_win_bwd"] = int(
                        tcp.window
                    )

    # ========================================================
    # CONSTRUCTION DES 23 CARACTERISTIQUES
    # ========================================================

    def _build_features(self, flow):

        fwd_packets = flow["fwd_packets"]
        bwd_packets = flow["bwd_packets"]

        total_packets = fwd_packets + bwd_packets

        total_bytes = (
            flow["fwd_bytes"] + flow["bwd_bytes"]
        )

        timestamps = sorted(
            flow["timestamps"]
        )

        duration_seconds = max(
            0.0,
            timestamps[-1] - timestamps[0]
        )

        duration_us = duration_seconds * 1_000_000

        if duration_seconds > 0:

            flow_bytes_s = total_bytes / duration_seconds
            flow_packets_s = total_packets / duration_seconds

        else:

            flow_bytes_s = 0.0
            flow_packets_s = 0.0

        iats = [
            (
                timestamps[i] - timestamps[i - 1]
            ) * 1_000_000

            for i in range(1, len(timestamps))
        ]

        iat_mean = mean(iats) if iats else 0.0

        iat_std = (
            pstdev(iats)
            if len(iats) > 1 else 0.0
        )

        all_lengths = (
            flow["fwd_lengths"] + flow["bwd_lengths"]
        )

        packet_length_mean = (
            mean(all_lengths) if all_lengths else 0.0
        )

        average_packet_size = (
            total_bytes / total_packets
            if total_packets else 0.0
        )

        fwd_max = (
            max(flow["fwd_lengths"])
            if flow["fwd_lengths"] else 0.0
        )

        bwd_max = (
            max(flow["bwd_lengths"])
            if flow["bwd_lengths"] else 0.0
        )

        down_up_ratio = (
            bwd_packets / fwd_packets
            if fwd_packets else 0.0
        )

        min_seg_size = (
            flow["min_seg_size_forward"]
            if flow["min_seg_size_forward"] is not None
            else 0
        )

        features = {

            "Destination Port": float(flow["dst_port"]),
            "Flow Duration": float(duration_us),

            "Total Fwd Packets": float(fwd_packets),
            "Total Backward Packets": float(bwd_packets),

            "Total Length of Fwd Packets": float(flow["fwd_bytes"]),
            "Total Length of Bwd Packets": float(flow["bwd_bytes"]),

            "Flow Bytes/s": float(flow_bytes_s),
            "Flow Packets/s": float(flow_packets_s),

            "SYN Flag Count": float(flow["syn"]),
            "ACK Flag Count": float(flow["ack"]),
            "RST Flag Count": float(flow["rst"]),
            "FIN Flag Count": float(flow["fin"]),

            "Down/Up Ratio": float(down_up_ratio),

            "Average Packet Size": float(average_packet_size),
            "Packet Length Mean": float(packet_length_mean),

            "Fwd Packet Length Max": float(fwd_max),
            "Bwd Packet Length Max": float(bwd_max),

            "Flow IAT Mean": float(iat_mean),
            "Flow IAT Std": float(iat_std),

            "Init_Win_bytes_forward": float(flow["init_win_fwd"]),
            "Init_Win_bytes_backward": float(flow["init_win_bwd"]),

            "act_data_pkt_fwd": float(flow["act_data_pkt_fwd"]),
            "min_seg_size_forward": float(min_seg_size)
        }

        return features

    # ========================================================
    # ENVOI DES FLUX AU RANDOM FOREST
    # ========================================================

    def flush_if_due(self):

        now = monotonic()

        if now - self.started < self.window_seconds:
            return []

        output = []

        for flow in self.flows.values():

            total_packets = (
                flow["fwd_packets"] + flow["bwd_packets"]
            )

            if total_packets < self.min_packets:
                continue

            features = self._build_features(flow)

            output.append((
                flow["src_ip"],
                features
            ))

        self.flows.clear()

        self.started = now

        return output
