"""
client_sniffer.py — Cliente NetMonitor para equipos del aula
=============================================================
- Captura tráfico DNS y TCP con Scapy
- Incluye hostname del equipo en cada lote de paquetes
- Reconexión automática si el servidor no está disponible
- Se lanza en los 22 equipos con PsExec desde el equipo del profesor

Requisitos:
  pip install scapy
  Npcap instalado (https://npcap.com)
  Ejecutar como Administrador

Uso:
  python client_sniffer.py --servidor 127.0.0.1
  python client_sniffer.py  (usa SERVIDOR_HOST por defecto)
"""

import socket
import json
import time
import threading
import argparse
import platform
from datetime import datetime

print("[*] Cargando Scapy...")
from scapy.all import sniff, DNS, DNSQR, IP, TCP, UDP, Raw
print("[*] Scapy listo.")

# ─── Configuración ───────────────────────────────────────────────
SERVIDOR_HOST  = '127.0.0.1'   # ← Cambiar a la IP del servidor del profesor
SERVIDOR_PORT  = 9998
FLUSH_INTERVAL = 3                 # Segundos entre envíos
MAX_COLA       = 300

HOSTNAME = socket.gethostname()

# ─── Caché de resolución de dominios ─────────────────────────────
rdns_cache   = {}
rdns_pending = set()
rdns_lock    = threading.Lock()

PUERTOS = {
    80: 'HTTP', 443: 'HTTPS', 53: 'DNS', 22: 'SSH', 21: 'FTP',
    25: 'SMTP', 110: 'POP3', 143: 'IMAP', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
    3306: 'MySQL', 5432: 'PostgreSQL', 6379: 'Redis',
}

def nombre_protocolo(puerto):
    return PUERTOS.get(puerto, f'TCP/{puerto}')

def aprender_dns(dominio, ip):
    if ip and dominio:
        with rdns_lock:
            rdns_cache[ip] = dominio

def resolver_rdns(ip):
    with rdns_lock:
        if ip in rdns_cache or ip in rdns_pending:
            return
        rdns_pending.add(ip)
    def _r():
        try:
            nombre = socket.gethostbyaddr(ip)[0]
            with rdns_lock:
                rdns_cache[ip] = nombre
                rdns_pending.discard(ip)
        except Exception:
            with rdns_lock:
                rdns_cache[ip] = ip
                rdns_pending.discard(ip)
    threading.Thread(target=_r, daemon=True).start()

def get_hostname_ip(ip):
    with rdns_lock:
        val = rdns_cache.get(ip)
    return val if val != ip else None

# ─── Cola de paquetes ─────────────────────────────────────────────
cola      = []
cola_lock = threading.Lock()

def procesar_paquete(pkt):
    try:
        info = {
            'ts':         datetime.now().strftime('%H:%M:%S.%f')[:-3],
            'tipo':       'UNKNOWN',
            'dominio':    None,
            'ip_src':     None,
            'ip_dst':     None,
            'puerto_dst': None,
            'protocolo':  None,
            'tamano':     len(pkt),
            'ttl':        None,
            'flags':      None,
        }

        if IP in pkt:
            info['ip_src'] = pkt[IP].src
            info['ip_dst'] = pkt[IP].dst
            info['ttl']    = pkt[IP].ttl

        # DNS query
        if DNS in pkt and pkt[DNS].qr == 0 and DNSQR in pkt:
            dominio = pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
            info.update({'tipo': 'DNS', 'dominio': dominio, 'protocolo': 'DNS', 'puerto_dst': 53})

        # DNS response — aprender IP→dominio
        elif DNS in pkt and pkt[DNS].qr == 1 and DNSQR in pkt:
            dominio = pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
            info.update({'tipo': 'DNS_RESP', 'dominio': dominio, 'protocolo': 'DNS', 'puerto_dst': 53})
            try:
                from scapy.layers.dns import DNSRR
                ans = pkt[DNS].an
                while ans and ans != 0:
                    if hasattr(ans, 'rdata'):
                        try:
                            ip_str = str(ans.rdata)
                            if ip_str and not ip_str.startswith('0.'):
                                aprender_dns(dominio, ip_str)
                        except Exception:
                            pass
                    ans = ans.payload if hasattr(ans, 'payload') and ans.payload else None
            except Exception:
                pass

        # TCP
        elif TCP in pkt and IP in pkt:
            tcp    = pkt[TCP]
            puerto = tcp.dport
            ip_dst = info['ip_dst']

            flags = []
            if tcp.flags.S: flags.append('SYN')
            if tcp.flags.A: flags.append('ACK')
            if tcp.flags.F: flags.append('FIN')
            if tcp.flags.R: flags.append('RST')
            if tcp.flags.P: flags.append('PSH')
            if tcp.flags.U: flags.append('URG')

            info.update({
                'tipo':       'TCP',
                'protocolo':  nombre_protocolo(puerto),
                'puerto_dst': puerto,
                'flags':      ' | '.join(flags) if flags else '-',
            })

            # Extraer Host HTTP
            if Raw in pkt:
                payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                for linea in payload.split('\n'):
                    if linea.lower().startswith('host:'):
                        info['dominio'] = linea.split(':', 1)[1].strip()
                        break

            # Resolver desde caché DNS
            if not info['dominio'] and ip_dst:
                hostname_ip = get_hostname_ip(ip_dst)
                if hostname_ip:
                    info['dominio'] = hostname_ip
                else:
                    resolver_rdns(ip_dst)
        else:
            return

        with cola_lock:
            cola.append(info)
            if len(cola) > MAX_COLA:
                cola.pop(0)

    except Exception:
        pass

# ─── Hilo de envío ───────────────────────────────────────────────
def hilo_envio(servidor_host):
    sock = None
    while True:
        time.sleep(FLUSH_INTERVAL)

        with cola_lock:
            if not cola:
                continue
            lote = cola.copy()
            cola.clear()

        if sock is None:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect((servidor_host, SERVIDOR_PORT))
                print(f"[+] Conectado al servidor {servidor_host}:{SERVIDOR_PORT} como [{HOSTNAME}]")
            except Exception:
                print(f"[!] No se puede conectar a {servidor_host}:{SERVIDOR_PORT}. Reintentando...")
                sock = None
                continue

        try:
            msg = json.dumps({'hostname': HOSTNAME, 'paquetes': lote}) + '\n'
            sock.sendall(msg.encode('utf-8'))
            print(f"  [{HOSTNAME}] {len(lote)} paquetes enviados")
        except Exception:
            print("[!] Conexión perdida. Reconectando...")
            try: sock.close()
            except: pass
            sock = None

# ─── Main ────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description='NetMonitor Aula — Cliente Sniffer')
    parser.add_argument('--servidor', default=SERVIDOR_HOST,
                        help=f'IP del servidor (default: {SERVIDOR_HOST})')
    args = parser.parse_args()

    print("=" * 55)
    print(f"  NetMonitor Aula — Cliente [{HOSTNAME}]")
    print("=" * 55)
    print(f"  Servidor : {args.servidor}:{SERVIDOR_PORT}")
    print(f"  Equipo   : {HOSTNAME} ({platform.node()})")
    print(f"  SO       : {platform.system()} {platform.release()}")
    print(f"  Flush    : cada {FLUSH_INTERVAL}s")
    print("=" * 55)
    print("  [!] Ejecutar como Administrador")
    print()

    threading.Thread(target=hilo_envio, args=(args.servidor,), daemon=True).start()

    try:
        print("[*] Capturando tráfico... (Ctrl+C para detener)\n")
        sniff(filter="udp port 53 or tcp", prn=procesar_paquete, store=False)
    except KeyboardInterrupt:
        print("\n[*] Sniffer detenido.")
    except Exception as e:
        print(f"[!] Error: {e}")
        print("    ¿Npcap instalado? ¿Ejecutando como Administrador?")

if __name__ == '__main__':
    main()
