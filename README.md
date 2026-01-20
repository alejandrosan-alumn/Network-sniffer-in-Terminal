# Network Sniffer & Vulnerability Scanner in Python

Herramienta avanzada de monitoreo de red desarrollada en **Python** para entornos de ciberseguridad. Diseñada específicamente para ser portable y funcional en sistemas como Linux, Windows y macOS.

## Funcionalidades
- **Detección Pasiva:** Identifica dispositivos nuevos en la red local mediante captura de paquetes e intenta ofrecer información al respecto del mismo.
- **Escaneo Activo:** Realiza auditorías de puertos y servicios utilizando **Nmap**.
- **Auditoría de Vulnerabilidades:** Ejecuta scripts `vuln` para detectar fallos críticos en tiempo real.
- **Protección ARP:** Detecta intentos de suplantación de identidad (**ARP Spoofing**) y ataques Man-in-the-Middle.
- **Reportes Automáticos:** Genera logs detallados en formato `.txt` dentro de la carpeta `Usuarios_capturados`, si no se tiene esta carpeta el script lo generará.
- **Auto-Gestión:** Instala automáticamente todas las librerías necesarias (Scapy, Psutil, etc.)

## Instalación y Uso rápido
1. Asegúrate de tener **Nmap** instalado en tu sistema.
2. Clona este repositorio:
   ```bash
   git clone [https://github.com/alejandrosan-alumn/Network-sniffer-Terminal.git](https://github.com/alejandrosan-alumn/Network-sniffer-Terminal.git)
