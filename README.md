# Intelligent Firewall - laboratoire GNS3

Prototype pédagogique IPv4 : Scapy -> agrégation en fenêtres -> Random Forest (si modèle disponible) + River HalfSpaceTrees -> moteur de décision -> ipset/iptables -> SQLite/FastAPI.

## Important
- Le projet démarre en **observe-only** (`AUTO_BLOCK=false`). Il ne bloque rien tant que vous n'avez pas validé la capture, les caractéristiques et les seuils.
- À utiliser uniquement sur votre réseau de laboratoire autorisé.
- Ne remplacez pas les règles de production. Sauvegardez d'abord `iptables-save`.
- Le modèle n'apprend pas automatiquement les événements suspects. Les observations ne sont apprises par HST que si elles sont considérées normales par la politique; adaptez et validez ce mécanisme.
- L'extraction de flux de ce prototype est volontairement légère : elle utilise des fenêtres temporelles par IP source et non une implémentation complète CICFlowMeter. Pour des résultats de soutenance, entraînement et inférence doivent utiliser exactement les mêmes features.

## Architecture de fichiers
- `firewall/`: création de la chaîne et gestion ipset
- `capture/`: capture Scapy et agrégation de fenêtres
- `ml/`: chargement Random Forest et HST River
- `decision/`: politique de décision
- `storage/`: SQLite
- `api/`: API FastAPI en lecture
- `train.py`: entraînement initial depuis un CSV préparé

## 1. Identifier les interfaces
Sur Ubuntu firewall :
```bash
ip -br link
ip -br addr
ip route
```
Dans le lab précédemment décrit, les noms proposés étaient `enp0s3` WAN, `enp0s8` LAN1, `enp0s9` LAN2, `enp0s10` DMZ. Confirmez-les avant d'appliquer la configuration.

Plan IP proposé (à adapter à la topologie réellement câblée) :
- WAN `enp0s3`: `10.10.10.1/24`, route par défaut via `10.10.10.254`
- LAN1 `enp0s8`: `192.168.10.1/24`
- LAN2 `enp0s9`: `192.168.20.1/24`
- DMZ `enp0s10`: `192.168.30.1/24`

Ne configurez pas une deuxième passerelle par défaut sur les interfaces LAN/DMZ.

## 2. Installer le système
```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip iptables ipset tcpdump conntrack libpcap-dev
mkdir -p ~/intelligent-firewall
cd ~/intelligent-firewall
# Décompresser ici l'archive, puis :
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Si `pip` indique que River ne prend pas en charge la version de Python, utilisez un environnement Python compatible (Python 3.11 recommandé) sans remplacer le Python système.

## 3. Préparer les règles firewall
Sauvegarde :
```bash
sudo iptables-save | sudo tee /root/iptables-before-ai.rules >/dev/null
sudo ip6tables-save | sudo tee /root/ip6tables-before-ai.rules >/dev/null
```
Créer la chaîne et l'ensemble de blocage :
```bash
sudo ipset create AI_BLOCKED hash:ip family inet timeout 900 -exist
sudo iptables -N AI_INPUT 2>/dev/null || true
sudo iptables -N AI_FORWARD 2>/dev/null || true
sudo iptables -C INPUT -j AI_INPUT 2>/dev/null || sudo iptables -I INPUT 1 -j AI_INPUT
sudo iptables -C FORWARD -j AI_FORWARD 2>/dev/null || sudo iptables -I FORWARD 1 -j AI_FORWARD
sudo iptables -C AI_INPUT -m set --match-set AI_BLOCKED src -j DROP 2>/dev/null || sudo iptables -A AI_INPUT -m set --match-set AI_BLOCKED src -j DROP
sudo iptables -C AI_FORWARD -m set --match-set AI_BLOCKED src -j DROP 2>/dev/null || sudo iptables -A AI_FORWARD -m set --match-set AI_BLOCKED src -j DROP
sudo iptables -A AI_INPUT -j RETURN 2>/dev/null || true
sudo iptables -A AI_FORWARD -j RETURN 2>/dev/null || true
```
Ces règles ne configurent pas à elles seules une politique complète INPUT/FORWARD/NAT. Ajoutez les règles réseau adaptées à votre topologie après validation. Ne mettez pas DROP par défaut sans avoir préparé et testé les règles d'administration, DNS, DHCP, LAN/DMZ et retour ESTABLISHED,RELATED.

## 4. Exécution
```bash
source .venv/bin/activate
cp .env.example .env
# Vérifier INTERFACE dans .env
sudo -E .venv/bin/python main.py
```
L'API (optionnelle) :
```bash
.venv/bin/uvicorn api.app:app --host 127.0.0.1 --port 8000
```
Ne publiez pas l'API sur WAN. Le prototype expose uniquement des événements de lecture.

## 5. Entraînement Random Forest
Préparez `dataset.csv` avec les colonnes numériques suivantes :
`duration,packets,bytes,src_dst_ports,protocol_tcp,protocol_udp,protocol_icmp,syn_packets,unique_dst_ports,failed_estimate`
et une colonne `Label` avec les classes `BENIGN`, `ATTACK` (ou des familles d'attaque regroupées).
```bash
python train.py dataset.csv
```
Attention : un CSV CIC-IDS2017 brut n'a pas automatiquement ces colonnes. Il faut réaliser une étape de transformation identique à celle de l'inférence. Ne mélangez pas les IP ou identifiants qui permettraient au modèle de mémoriser les fichiers. Faites une séparation par jour/PCAP ou par groupe de capture pour éviter la fuite de données.

## 6. Tests
1. Laisser `AUTO_BLOCK=false`.
2. Vérifier que les événements arrivent dans SQLite et `/events`.
3. Générer du trafic normal puis un scan limité dans le lab.
4. Comparer les scores, ajuster les seuils, mesurer faux positifs/faux négatifs.
5. Seulement après validation, activer `AUTO_BLOCK=true`.
6. Tester l'expiration ipset et le déblocage manuel :
```bash
sudo ipset list AI_BLOCKED
sudo ipset del AI_BLOCKED 192.0.2.123
```

## Limites du prototype
- Scapy en Python n'est pas un moteur de capture haut débit. La documentation Scapy recommande un filtre BPF pour réduire le volume capturé.
- La détection par fenêtre IP est un prototype; pour une évaluation académique robuste, implémentez une agrégation bidirectionnelle par 5-tuple et des features compatibles avec CICFlowMeter.
- Le score HST est une anomalie, pas une preuve d'attaque. Il ne faut pas bloquer sur le seul score HST.
- Une vraie politique doit gérer les IP spoofées, IPv6, fragmentation, NAT, exceptions de confiance, limitation de débit, journaux, et rollback.
