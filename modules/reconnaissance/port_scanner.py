"""
Scanner de ports avancé - Nmap + alternatives asynchrones
Supporte Masscan, Rustscan, et scan TCP/UDP rapide
"""

import asyncio
from typing import Dict, List, Set, Tuple
from loguru import logger
import socket
import nmap
import time
import subprocess
from urllib.parse import urlparse


class ScannerPorts:
    """
    Scanner de ports avancé avec multiples méthodes
    """

    def __init__(self):
        # Configuration avancée
        self.timeout = 1.0  # Timeout par port
        self.max_concurrent = 100  # Scans simultanés
        self.ports_communs = [
            21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
            993, 995, 1433, 1521, 3306, 3389, 5432, 5985, 5986,
            8080, 8443, 8888, 9000, 9200, 9300, 10000, 27017
        ]

        # Ports étendus pour scan complet
        self.ports_etendus = list(range(1, 1025))  # 1-1024
        self.ports_web = [80, 81, 443, 444, 8080, 8443, 8888, 9000]

        # Vérifier les outils disponibles
        self.outils_disponibles = self._verifier_outils()

    def _verifier_outils(self) -> Dict[str, bool]:
        """Vérifie quels outils de scan sont disponibles"""
        outils = {}

        # Nmap
        try:
            self.nm = nmap.PortScanner()
            outils['nmap'] = True
        except:
            outils['nmap'] = False
            self.nm = None

        # Masscan
        try:
            result = subprocess.run(['masscan', '--version'],
                                  capture_output=True, text=True, timeout=5)
            outils['masscan'] = result.returncode == 0
        except:
            outils['masscan'] = False

        # Rustscan
        try:
            result = subprocess.run(['rustscan', '--version'],
                                  capture_output=True, text=True, timeout=5)
            outils['rustscan'] = result.returncode == 0
        except:
            outils['rustscan'] = False

        logger.info("Outils de scan disponibles: " +
                   ", ".join([k for k, v in outils.items() if v]))

        return outils

    async def scanner(self, url: str, intensite: str = 'normal') -> Dict[int, str]:
        """
        Scanner de ports avancé avec stratégie adaptative

        Args:
            url: URL de la cible
            intensite: 'fast', 'normal', 'deep'

        Returns:
            Dict[int, str]: Dictionnaire {port: service}
        """
        try:
            parsed = urlparse(url)
            hote = parsed.netloc or parsed.path

            # Enlever le port si présent
            if ':' in hote:
                hote = hote.split(':')[0]

            logger.info(f"🔍 Scan de ports avancé: {hote} (intensité: {intensite})")

            # Choisir la stratégie selon l'intensité et les outils disponibles
            if intensite == 'fast':
                ports_a_scanner = self.ports_web  # Seulement ports web
            elif intensite == 'deep':
                ports_a_scanner = self.ports_etendus  # 1-1024
            else:  # normal
                ports_a_scanner = self.ports_communs  # ~30 ports courants

            # Essayer les outils dans l'ordre de préférence
            ports_trouves = {}

            # 1. Essayer Masscan (ultra-rapide)
            if self.outils_disponibles.get('masscan', False):
                logger.debug("🛠️  Utilisation de Masscan...")
                ports_masscan = await self._scanner_masscan(hote, ports_a_scanner)
                ports_trouves.update(ports_masscan)

            # 2. Essayer Rustscan (rapide et précis)
            elif self.outils_disponibles.get('rustscan', False):
                logger.debug("🛠️  Utilisation de Rustscan...")
                ports_rustscan = await self._scanner_rustscan(hote, ports_a_scanner)
                ports_trouves.update(ports_rustscan)

            # 3. Essayer Nmap (fiable)
            elif self.outils_disponibles.get('nmap', False):
                logger.debug("🛠️  Utilisation de Nmap...")
                ports_nmap = await self._scanner_nmap(hote, ports_a_scanner)
                ports_trouves.update(ports_nmap)

            # 4. Fallback: Scanner TCP asynchrone
            else:
                logger.debug("🔄 Utilisation du scanner TCP asynchrone...")
                ports_tcp = await self._scanner_tcp_asynchrone(hote, ports_a_scanner)
                ports_trouves.update(ports_tcp)

            # Détection des services pour les ports ouverts
            if ports_trouves:
                ports_avec_services = await self._detecter_services(hote, ports_trouves)
            else:
                # Fallback aux ports web par défaut
                logger.warning("⚠️  Aucun port détecté - Utilisation des ports par défaut")
                ports_avec_services = {80: 'http', 443: 'https'}

            logger.success(f"✅ {len(ports_avec_services)} ports ouverts trouvés")
            return ports_avec_services

        except Exception as e:
            logger.error(f"Erreur scan ports avancé: {str(e)}")
            return {80: 'http', 443: 'https'}

    async def _scanner_masscan(self, hote: str, ports: List[int]) -> Dict[int, str]:
        """Scanner ultra-rapide avec Masscan"""
        ports_trouves = {}

        try:
            ports_str = ','.join(map(str, ports))

            # Masscan avec timeout court
            cmd = [
                'masscan', hote,
                '-p', ports_str,
                '--rate=1000',  # 1000 paquets/seconde
                '--wait=2',     # Attendre 2 secondes
                '-oG', '-'      # Output grepable
            ]

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=10
            )

            # Parser le output de Masscan
            output = stdout.decode()
            for line in output.split('\n'):
                if 'Ports:' in line:
                    # Extraire les ports du format Masscan
                    import re
                    port_matches = re.findall(r'(\d+)/open', line)
                    for port_str in port_matches:
                        port = int(port_str)
                        ports_trouves[port] = 'unknown'  # Service à déterminer

        except Exception as e:
            logger.debug(f"Erreur Masscan: {str(e)}")

        return ports_trouves

    async def _scanner_rustscan(self, hote: str, ports: List[int]) -> Dict[int, str]:
        """Scanner rapide avec Rustscan"""
        ports_trouves = {}

        try:
            # Rustscan avec paramètres optimisés
            cmd = [
                'rustscan', '-a', hote,
                '--ports', ','.join(map(str, ports)),
                '--timeout', '1000',  # 1 seconde timeout
                '--tries', '1',       # 1 essai par port
                '-q'                  # Quiet mode
            ]

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=30
            )

            # Parser le output de Rustscan
            output = stdout.decode()
            for line in output.split('\n'):
                line = line.strip()
                if line and line.isdigit():
                    port = int(line)
                    ports_trouves[port] = 'unknown'

        except Exception as e:
            logger.debug(f"Erreur Rustscan: {str(e)}")

        return ports_trouves

    async def _scanner_nmap(self, hote: str, ports: List[int]) -> Dict[int, str]:
        """Scanner Nmap traditionnel"""
        ports_trouves = {}

        try:
            ports_str = ','.join(map(str, ports))

            # Nmap avec détection de services
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.nm.scan(
                    hote,
                    ports_str,
                    arguments='-sV -T4 --open --host-timeout 30s'
                )
            )

            # Extraire les résultats
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    ports_list = self.nm[host][proto].keys()
                    for port in ports_list:
                        service = self.nm[host][proto][port]['name']
                        ports_trouves[port] = service

        except Exception as e:
            logger.debug(f"Erreur Nmap: {str(e)}")

        return ports_trouves

    async def _scanner_tcp_asynchrone(self, hote: str, ports: List[int]) -> Dict[int, str]:
        """Scanner TCP asynchrone rapide (fallback)"""
        ports_trouves = {}
        semaphore = asyncio.Semaphore(self.max_concurrent)

        async def scan_port(port: int):
            async with semaphore:
                try:
                    # Créer une connexion TCP
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(hote, port),
                        timeout=self.timeout
                    )
                    writer.close()
                    await writer.wait_closed()

                    ports_trouves[port] = 'unknown'
                    logger.debug(f"   🔌 Port {port} ouvert")

                except:
                    pass  # Port fermé ou timeout

        # Scanner tous les ports en parallèle
        tasks = [scan_port(port) for port in ports]
        await asyncio.gather(*tasks, return_exceptions=True)

        return ports_trouves

    async def _detecter_services(self, hote: str, ports: Dict[int, str]) -> Dict[int, str]:
        """Détection des services pour les ports ouverts"""
        services_detectes = {}

        # Services connus par port
        services_connus = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
            53: 'dns', 80: 'http', 110: 'pop3', 135: 'msrpc',
            139: 'netbios-ssn', 143: 'imap', 443: 'https', 445: 'microsoft-ds',
            993: 'imaps', 995: 'pop3s', 1433: 'ms-sql-s', 1521: 'oracle',
            3306: 'mysql', 3389: 'ms-wbt-server', 5432: 'postgresql',
            5985: 'wsman', 5986: 'wsman', 8080: 'http-proxy',
            8443: 'https-alt', 8888: 'http', 9000: 'http',
            9200: 'elasticsearch', 9300: 'elasticsearch', 10000: 'webmin',
            27017: 'mongodb'
        }

        for port, service in ports.items():
            if service != 'unknown':
                services_detectes[port] = service
            elif port in services_connus:
                services_detectes[port] = services_connus[port]
            else:
                # Essayer de détecter par banner grabbing simple
                service_detecte = await self._banner_grab(hote, port)
                services_detectes[port] = service_detecte or 'unknown'

        return services_detectes

    async def _banner_grab(self, hote: str, port: int) -> str:
        """Simple banner grabbing pour identification de service"""
        try:
            if port in [80, 8080, 8888, 9000]:  # HTTP
                return 'http'
            elif port in [443, 8443]:  # HTTPS
                return 'https'
            elif port == 22:  # SSH
                return 'ssh'

            # Pour les autres ports, essayer une connexion rapide
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(hote, port),
                timeout=0.5
            )

            # Lire quelques octets pour le banner
            data = await asyncio.wait_for(
                reader.read(64), timeout=0.5
            )

            writer.close()
            await writer.wait_closed()

            # Analyse simple du banner
            banner = data.decode('utf-8', errors='ignore').strip()

            if 'SSH' in banner:
                return 'ssh'
            elif 'FTP' in banner:
                return 'ftp'
            elif 'HTTP' in banner or banner.startswith('GET'):
                return 'http'
            elif banner:
                return 'unknown'

        except:
            pass

        return 'unknown'

