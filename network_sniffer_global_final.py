import os
import sys
import subprocess
import platform

# ==============================================================================
# 1. AUTO-INSTALACIÓN (COMPATIBLE CON PARROT 7 / PEP 668)
# ==============================================================================
def install_dependencies():
    libs = ["scapy", "python-nmap", "plyer", "psutil"]
    for lib in libs:
        try:
            if lib == "python-nmap": import nmap
            else: __import__(lib.replace("-", "_"))
        except ImportError:
            pip_cmd = [sys.executable, "-m", "pip", "install", lib]
            if platform.system() != "Windows":
                pip_cmd.append("--break-system-packages")
            try:
                subprocess.check_call(pip_cmd)
            except:
                pass

install_dependencies()

# ==============================================================================
# 2. IMPORTACIONES
# ==============================================================================
import threading
import psutil
from scapy.all import sniff, IP, Ether, ARP
from datetime import datetime
from plyer import notification

# ==============================================================================
# 3. CONFIGURACIÓN DE RUTAS Y LOGS
# ==============================================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FOLDER = os.path.join(BASE_DIR, "Usuarios_capturados")
if not os.path.exists(FOLDER): os.makedirs(FOLDER)

LOG_FILE = os.path.join(FOLDER, f"Auditoria_{datetime.now().strftime('%Y-%m-%d_%H-%M')}.txt")

with open(LOG_FILE, "w", encoding="utf-8") as f:
    f.write(f"=== REPORTE DE RED COMPLETO: {datetime.now()} ===\n")
    f.write(f"Registro: {LOG_FILE}\n" + "="*60 + "\n")

# ==============================================================================
# 4. FUNCIONES TÉCNICAS
# ==============================================================================
seen_ips = set()
arp_table = {}

def mostrar_interfaces():
    print("\n" + "="*50)
    print(f"{'INTERFAZ':<20} {'IP LOCAL':<15}")
    print("-" * 50)
    for itface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == 2:
                print(f"{itface:<20} {addr.address:<15}")
    print("="*50 + "\n")

def enviar_alerta(title, message, critical=False):
    try:
        notification.notify(title=title, message=message, app_name="Sniffer Pro", timeout=5)
    except: pass
    if critical: print(f"\033[91m[ALERTA]\033[0m {title}: {message}")

# ==============================================================================
# 5. ANÁLISIS ROBUSTO (EVITA ERRORES XML/WRONG TYPE)
# ==============================================================================
def analizar_dispositivo(ip, mac_vendor):
    print(f"\033[94m[*] Nueva IP detectada: {ip} | Escaneando...\033[0m")
    
    try:
        # Ejecutamos NMAP directamente por consola para evitar errores de la librería python-nmap
        # -sV: Versiones, -T4: Rapidez, --top-ports 20, --script vuln
        comando = ["nmap", "-sV", "--top-ports", "20", "--script", "vuln", ip]
        resultado = subprocess.run(comando, capture_output=True, text=True, timeout=120)
        
        output = resultado.stdout
        vulnerable = "VULNERABLE" in output.upper()

        if vulnerable:
            enviar_alerta("¡VULNERABILIDAD!", f"Detectada en {ip}", critical=True)

        # ESCRITURA INMEDIATA AL LOG
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"\n[{datetime.now().strftime('%H:%M:%S')}] DISPOSITIVO: {ip}\n")
            f.write(f"MAC/VENDOR: {mac_vendor}\n")
            f.write(f"RESULTADO DE ESCANEO:\n{output if output else 'Sin respuesta'}\n")
            f.write("-" * 60 + "\n")
            f.flush()
            os.fsync(f.fileno())

        print(f"\033[92m[V] Datos guardados para {ip}\033[0m")

    except Exception as e:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{datetime.now().strftime('%H:%M:%S')}] Error en {ip}: {str(e)}\n")
        print(f"[-] Fallo en análisis de {ip}")

def procesar_paquete(pkt):
    # Detección ARP Spoofing
    if ARP in pkt:
        ip_arp, mac_arp = pkt[ARP].psrc, pkt[ARP].hwsrc
        if ip_arp in arp_table and arp_table[ip_arp] != mac_arp:
            enviar_alerta("ATAQUE ARP", f"IP {ip_arp} suplantada", critical=True)
        arp_table[ip_arp] = mac_arp

    # Detección Tráfico IP
    if IP in pkt:
        ip_src = pkt[IP].src
        if ip_src not in seen_ips:
            seen_ips.add(ip_src)
            mac_src = pkt[Ether].src if Ether in pkt else "Desconocido"
            threading.Thread(target=analizar_dispositivo, args=(ip_src, mac_src), daemon=True).start()

# ==============================================================================
# 6. INICIO
# ==============================================================================
if __name__ == "__main__":
    mostrar_interfaces()
    print(f"[*] Registrando en: {LOG_FILE}")
    print("[*] Sniffer iniciado. Esperando actividad...")
    
    try:
        sniff(prn=procesar_paquete, store=0, filter="arp or ip")
    except KeyboardInterrupt:
        print(f"\n[!] Finalizado. Revisa: {LOG_FILE}")
        sys.exit(0)
    except PermissionError:
        print("\n[X] ERROR: Ejecuta con 'sudo'")