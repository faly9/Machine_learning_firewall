
import logging
import queue

from scapy.all import AsyncSniffer

from capture.flows import WindowAggregator
from ml.detectors import Detectors

from decision.engine import (
    evaluate,
    evaluate_behavior,
)

from firewall.ipset_manager import ensure_set

from config import (
    INTERFACE,
    CAPTURE_FILTER,
    WINDOW_SECONDS,
    MIN_PACKETS,
    AUTO_BLOCK
)


# ============================================================
# CONFIGURATION DES LOGS
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)


# ============================================================
# TRAITEMENT DE LA FILE DES PAQUETS
# ============================================================

def process_packet_queue(packet_queue, aggregator):

    processed = 0

    while True:

        try:
            pkt = packet_queue.get_nowait()

        except queue.Empty:
            break

        try:
            aggregator.add_packet(pkt)
            processed += 1

        except Exception:
            logging.exception(
                "Erreur pendant le traitement d'un paquet"
            )

    return processed


# ============================================================
# TRAITEMENT DES ALERTES COMPORTEMENTALES
# ============================================================

def process_behavior_alerts(aggregator):

    alerts = aggregator.flush_behavior_alerts()

    for alert in alerts:

        try:

            result = evaluate_behavior(alert)

            logging.warning(
                "ALERTE COMPORTEMENTALE | TYPE=%s | RESULTAT=%s",
                alert.get("detection"),
                result
            )

        except Exception:

            logging.exception(
                "Erreur pendant le traitement de l'alerte : %s",
                alert
            )


# ============================================================
# TRAITEMENT DES ALERTES PORTSCAN
# ============================================================

def process_portscan_alerts(aggregator):

    alerts = aggregator.flush_portscan_alerts()

    for alert in alerts:

        try:

            result = evaluate_behavior(alert)

            logging.warning(
                "ALERTE PORTSCAN | RESULTAT=%s",
                result
            )

        except Exception:

            logging.exception(
                "Erreur pendant le traitement du portscan"
            )


# ============================================================
# TRAITEMENT DES FLUX RANDOM FOREST
# ============================================================

def process_flows(aggregator, detectors):

    flows = aggregator.flush_if_due()

    for src_ip, features in flows:

        try:

            logging.info(
                "CARACTERISTIQUES | IP=%s | FEATURES=%s",
                src_ip,
                features
            )

            result = evaluate(
                src_ip,
                features,
                detectors
            )

            logging.info(
                "DECISION ML | IP=%s | RESULTAT=%s",
                src_ip,
                result
            )

        except Exception:

            logging.exception(
                "Erreur pendant l'analyse du flux de %s",
                src_ip
            )


# ============================================================
# TRAITEMENT CENTRAL
# ============================================================

def process_all(aggregator, detectors):

    # 1. Alertes comportementales générales
    process_behavior_alerts(aggregator)

    # 2. Compatibilité avec les alertes portscan
    process_portscan_alerts(aggregator)

    # 3. Classification ML
    process_flows(aggregator, detectors)


# ============================================================
# PROGRAMME PRINCIPAL
# ============================================================

def main():

    logging.info("=" * 60)
    logging.info("FIREWALL INTELLIGENT - DEMARRAGE")
    logging.info("=" * 60)

    sniffer = None

    # --------------------------------------------------------
    # 1. Initialisation IPSET
    # --------------------------------------------------------

    ensure_set()

    logging.info("IPSET initialise.")

    # --------------------------------------------------------
    # 2. Initialisation de l'agrégateur
    # --------------------------------------------------------

    aggregator = WindowAggregator(
        window_seconds=WINDOW_SECONDS,
        min_packets=MIN_PACKETS
    )

    logging.info(
        "Agregation des flux : %s secondes",
        WINDOW_SECONDS
    )

    logging.info(
        "Nombre minimal de paquets : %s",
        MIN_PACKETS
    )

    # --------------------------------------------------------
    # 3. Initialisation des détecteurs
    # --------------------------------------------------------

    detectors = Detectors()

    logging.info(
        "Random Forest et Half-Space Trees initialises."
    )

    # --------------------------------------------------------
    # 4. File de réception
    # --------------------------------------------------------

    packet_queue = queue.Queue()

    # --------------------------------------------------------
    # 5. Configuration Scapy
    # --------------------------------------------------------

    sniffer = AsyncSniffer(
        iface=INTERFACE,
        filter=CAPTURE_FILTER,
        prn=packet_queue.put,
        store=False
    )

    logging.info("Interface reseau : %s", INTERFACE)
    logging.info("Filtre de capture : %s", CAPTURE_FILTER)

    logging.info(
        "Blocage automatique : %s",
        "ACTIVE" if AUTO_BLOCK else "DESACTIVE"
    )

    if not AUTO_BLOCK:

        logging.info(
            "Mode observation : aucun blocage automatique."
        )

    # --------------------------------------------------------
    # 6. DEMARRAGE
    # --------------------------------------------------------

    try:

        logging.info("Demarrage de la capture...")

        sniffer.start()

        logging.info(
            "Capture demarree. Ctrl+C pour arreter."
        )

        # ----------------------------------------------------
        # BOUCLE PRINCIPALE
        # ----------------------------------------------------

        while True:

            try:

                pkt = packet_queue.get(timeout=1)

                aggregator.add_packet(pkt)

            except queue.Empty:
                pass

            except Exception:

                logging.exception(
                    "Erreur pendant la reception d'un paquet"
                )

            # Traiter les autres paquets en attente
            process_packet_queue(
                packet_queue,
                aggregator
            )

            # Traiter toutes les alertes et les flux
            process_all(
                aggregator,
                detectors
            )

            if packet_queue.qsize() > 10000:

                logging.warning(
                    "File de capture importante : %s paquets",
                    packet_queue.qsize()
                )

    except KeyboardInterrupt:

        logging.info(
            "Arret demande par l'utilisateur."
        )

    except Exception:

        logging.exception(
            "Erreur critique dans le firewall."
        )

    finally:

        # ----------------------------------------------------
        # 7. ARRET DU SNIFFER
        # ----------------------------------------------------

        if sniffer is not None:

            try:

                if sniffer.running:

                    logging.info(
                        "Arret du sniffer..."
                    )

                    sniffer.stop()

            except Exception:

                logging.exception(
                    "Erreur pendant l'arret du sniffer"
                )

        # ----------------------------------------------------
        # 8. DERNIERS PAQUETS
        # ----------------------------------------------------

        logging.info(
            "Traitement des derniers paquets..."
        )

        process_packet_queue(
            packet_queue,
            aggregator
        )

        # ----------------------------------------------------
        # 9. DERNIERES ALERTES ET DERNIERS FLUX
        # ----------------------------------------------------

        aggregator.started -= aggregator.window_seconds

        process_all(
            aggregator,
            detectors
        )

        logging.info("=" * 60)
        logging.info("FIREWALL INTELLIGENT ARRETE")
        logging.info("=" * 60)


# ============================================================
# POINT D'ENTREE
# ============================================================

if __name__ == "__main__":
    main()
