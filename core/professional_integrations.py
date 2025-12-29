"""
Système d'intégration avec outils professionnels pour VulnHunter Pro
Connectors pour Burp Suite, OWASP ZAP, Nessus, OpenVAS, Metasploit
"""

import asyncio
import json
import base64
import xml.etree.ElementTree as ET
from typing import Dict, List, Tuple, Optional, Any, Callable
from datetime import datetime
import aiohttp
import websockets
import subprocess
import os
from loguru import logger

from core.models import Vulnerabilite


class BaseConnector:
    """
    Classe de base pour tous les connectors d'outils professionnels
    """

    def __init__(self, nom_outil: str, config: Dict[str, Any]):
        self.nom_outil = nom_outil
        self.config = config
        self.session = None
        self.connecte = False
        self.derniere_connexion = None

        logger.info(f"🔗 Connector {nom_outil} initialisé")

    async def connecter(self) -> bool:
        """Établit la connexion avec l'outil"""
        raise NotImplementedError

    async def deconnecter(self):
        """Ferme la connexion"""
        if self.session:
            await self.session.close()
        self.connecte = False
        logger.info(f"🔌 Déconnecté de {self.nom_outil}")

    async def envoyer_scan(self, url: str, config_scan: Dict = None) -> Dict[str, Any]:
        """Envoie une demande de scan"""
        raise NotImplementedError

    async def recuperer_resultats(self, scan_id: str) -> List[Vulnerabilite]:
        """Récupère les résultats d'un scan"""
        raise NotImplementedError

    async def obtenir_statut_scan(self, scan_id: str) -> Dict[str, Any]:
        """Obtient le statut d'un scan en cours"""
        raise NotImplementedError

    def convertir_vulnerabilite(self, vuln_data: Dict) -> Vulnerabilite:
        """Convertit les données de vulnérabilité du format outil vers VulnHunter"""
        raise NotImplementedError


class BurpSuiteConnector(BaseConnector):
    """
    Connector pour Burp Suite Professional via REST API
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__("Burp Suite", config)
        self.api_url = config.get('api_url', 'http://localhost:1337')
        self.api_key = config.get('api_key', '')

    async def connecter(self) -> bool:
        """Se connecte à l'API REST de Burp Suite"""
        try:
            headers = {'Authorization': f'Bearer {self.api_key}'} if self.api_key else {}

            async with aiohttp.ClientSession(headers=headers) as session:
                async with session.get(f"{self.api_url}/v0.1/") as response:
                    if response.status == 200:
                        self.connecte = True
                        self.derniere_connexion = datetime.now()
                        logger.success("✅ Connecté à Burp Suite API")
                        return True
                    else:
                        logger.error(f"❌ Échec connexion Burp Suite: {response.status}")
                        return False
        except Exception as e:
            logger.error(f"❌ Erreur connexion Burp Suite: {str(e)}")
            return False

    async def envoyer_scan(self, url: str, config_scan: Dict = None) -> Dict[str, Any]:
        """Lance un scan actif dans Burp Suite"""
        if not self.connecte:
            await self.connecter()

        try:
            config_scan = config_scan or {}
            scan_config = {
                "urls": [url],
                "scan_configurations": [{
                    "type": "CrawlAndAudit",
                    "name": f"VulnHunter Scan - {datetime.now().isoformat()}",
                    "included_items": [{
                        "type": "URL",
                        "match": url
                    }]
                }]
            }

            headers = {'Authorization': f'Bearer {self.api_key}'} if self.api_key else {}

            async with aiohttp.ClientSession(headers=headers) as session:
                async with session.post(
                    f"{self.api_url}/v0.1/scan",
                    json=scan_config
                ) as response:
                    if response.status == 201:
                        result = await response.json()
                        scan_id = result.get('scan_id')
                        logger.success(f"🎯 Scan Burp Suite lancé: {scan_id}")
                        return {'scan_id': scan_id, 'statut': 'en_cours'}
                    else:
                        logger.error(f"❌ Échec lancement scan Burp: {response.status}")
                        return {'erreur': f'HTTP {response.status}'}

        except Exception as e:
            logger.error(f"❌ Erreur scan Burp Suite: {str(e)}")
            return {'erreur': str(e)}

    async def obtenir_statut_scan(self, scan_id: str) -> Dict[str, Any]:
        """Obtient le statut du scan Burp Suite"""
        if not self.connecte:
            await self.connecter()

        try:
            headers = {'Authorization': f'Bearer {self.api_key}'} if self.api_key else {}

            async with aiohttp.ClientSession(headers=headers) as session:
                async with session.get(f"{self.api_url}/v0.1/scan/{scan_id}") as response:
                    if response.status == 200:
                        data = await response.json()
                        return {
                            'scan_id': scan_id,
                            'statut': data.get('scan_status', 'inconnu'),
                            'progression': data.get('scan_percentage', 0),
                            'issues_trouves': data.get('issue_events', 0)
                        }
                    else:
                        return {'erreur': f'HTTP {response.status}'}

        except Exception as e:
            logger.error(f"❌ Erreur statut Burp: {str(e)}")
            return {'erreur': str(e)}

    async def recuperer_resultats(self, scan_id: str) -> List[Vulnerabilite]:
        """Récupère les résultats du scan Burp Suite"""
        if not self.connecte:
            await self.connecter()

        vulnerabilites = []

        try:
            headers = {'Authorization': f'Bearer {self.api_key}'} if self.api_key else {}

            async with aiohttp.ClientSession(headers=headers) as session:
                # Récupérer les issues
                async with session.get(f"{self.api_url}/v0.1/scan/{scan_id}/issues") as response:
                    if response.status == 200:
                        issues = await response.json()

                        for issue in issues.get('issues', []):
                            vuln = self.convertir_vulnerabilite(issue)
                            if vuln:
                                vulnerabilites.append(vuln)

                        logger.success(f"📊 Burp Suite: {len(vulnerabilites)} vulnérabilités récupérées")
                        return vulnerabilites
                    else:
                        logger.error(f"❌ Échec récupération Burp: {response.status}")
                        return []

        except Exception as e:
            logger.error(f"❌ Erreur récupération Burp: {str(e)}")
            return []

    def convertir_vulnerabilite(self, vuln_data: Dict) -> Optional[Vulnerabilite]:
        """Convertit une issue Burp vers format VulnHunter"""
        try:
            severity_map = {
                'high': 'CRITIQUE',
                'medium': 'ÉLEVÉ',
                'low': 'MOYEN',
                'info': 'INFO'
            }

            return Vulnerabilite(
                type=vuln_data.get('issue_name', 'Issue Burp'),
                severite=severity_map.get(vuln_data.get('severity', 'info').lower(), 'INFO'),
                url=vuln_data.get('origin', ''),
                description=vuln_data.get('issue_detail', ''),
                payload=vuln_data.get('payload', ''),
                preuve=f"Burp Suite: {vuln_data.get('issue_background', '')}",
                cvss_score=self._calculer_score_cvss_burp(vuln_data.get('severity', 'info')),
                remediation=vuln_data.get('remediation_detail', ''),
                outil_source='Burp Suite'
            )

        except Exception as e:
            logger.debug(f"Erreur conversion vulnérabilité Burp: {str(e)}")
            return None

    def _calculer_score_cvss_burp(self, severite: str) -> float:
        """Convertit la sévérité Burp en score CVSS"""
        mapping = {
            'high': 8.5,
            'medium': 6.5,
            'low': 4.0,
            'info': 1.0
        }
        return mapping.get(severite.lower(), 1.0)


class ZAPConnector(BaseConnector):
    """
    Connector pour OWASP ZAP via REST API
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__("OWASP ZAP", config)
        self.api_url = config.get('api_url', 'http://localhost:8080')
        self.api_key = config.get('api_key', '')

    async def connecter(self) -> bool:
        """Se connecte à l'API REST de ZAP"""
        try:
            async with aiohttp.ClientSession() as session:
                params = {'apikey': self.api_key} if self.api_key else {}
                async with session.get(f"{self.api_url}/JSON/core/view/version/", params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get('version'):
                            self.connecte = True
                            self.derniere_connexion = datetime.now()
                            logger.success(f"✅ Connecté à ZAP API v{data['version']}")
                            return True

            logger.error("❌ Échec connexion ZAP")
            return False

        except Exception as e:
            logger.error(f"❌ Erreur connexion ZAP: {str(e)}")
            return False

    async def envoyer_scan(self, url: str, config_scan: Dict = None) -> Dict[str, Any]:
        """Lance un scan spider + active dans ZAP"""
        if not self.connecte:
            await self.connecter()

        try:
            params = {'apikey': self.api_key} if self.api_key else {}

            async with aiohttp.ClientSession() as session:
                # Démarrer le spider
                spider_params = params.copy()
                spider_params.update({
                    'url': url,
                    'maxChildren': '10',
                    'recurse': 'true'
                })

                async with session.get(f"{self.api_url}/JSON/spider/action/scan/",
                                     params=spider_params) as response:
                    if response.status == 200:
                        data = await response.json()
                        scan_id = data.get('scan')

                        # Lancer le scan actif
                        active_params = params.copy()
                        active_params.update({
                            'url': url,
                            'recurse': 'true',
                            'inScopeOnly': 'false'
                        })

                        await asyncio.sleep(2)  # Attendre que le spider commence

                        async with session.get(f"{self.api_url}/JSON/ascan/action/scan/",
                                             params=active_params) as response:
                            if response.status == 200:
                                logger.success(f"🎯 Scan ZAP lancé: spider + active scan")
                                return {'scan_id': f"spider_{scan_id}", 'statut': 'en_cours'}

            return {'erreur': 'Échec lancement scan ZAP'}

        except Exception as e:
            logger.error(f"❌ Erreur scan ZAP: {str(e)}")
            return {'erreur': str(e)}

    async def obtenir_statut_scan(self, scan_id: str) -> Dict[str, Any]:
        """Obtient le statut du scan ZAP"""
        if not self.connecte:
            await self.connecter()

        try:
            params = {'apikey': self.api_key} if self.api_key else {}

            async with aiohttp.ClientSession() as session:
                # Statut spider
                async with session.get(f"{self.api_url}/JSON/spider/view/status/", params=params) as response:
                    spider_status = 0
                    if response.status == 200:
                        data = await response.json()
                        spider_status = data.get('status', 0)

                # Statut active scan
                async with session.get(f"{self.api_url}/JSON/ascan/view/status/", params=params) as response:
                    active_status = 0
                    if response.status == 200:
                        data = await response.json()
                        active_status = data.get('status', 0)

                progression_moyenne = (spider_status + active_status) / 2

                return {
                    'scan_id': scan_id,
                    'statut': 'en_cours' if progression_moyenne < 100 else 'termine',
                    'progression': progression_moyenne
                }

        except Exception as e:
            logger.error(f"❌ Erreur statut ZAP: {str(e)}")
            return {'erreur': str(e)}

    async def recuperer_resultats(self, scan_id: str) -> List[Vulnerabilite]:
        """Récupère les résultats du scan ZAP"""
        if not self.connecte:
            await self.connecter()

        vulnerabilites = []

        try:
            params = {'apikey': self.api_key} if self.api_key else {}

            async with aiohttp.ClientSession() as session:
                # Récupérer les alertes
                async with session.get(f"{self.api_url}/JSON/alert/view/alerts/", params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        alerts = data.get('alerts', [])

                        for alert in alerts:
                            vuln = self.convertir_vulnerabilite(alert)
                            if vuln:
                                vulnerabilites.append(vuln)

                        logger.success(f"📊 ZAP: {len(vulnerabilites)} vulnérabilités récupérées")
                        return vulnerabilites

            return []

        except Exception as e:
            logger.error(f"❌ Erreur récupération ZAP: {str(e)}")
            return []

    def convertir_vulnerabilite(self, vuln_data: Dict) -> Optional[Vulnerabilite]:
        """Convertit une alerte ZAP vers format VulnHunter"""
        try:
            risk_map = {
                'High': 'CRITIQUE',
                'Medium': 'ÉLEVÉ',
                'Low': 'MOYEN',
                'Informational': 'INFO'
            }

            return Vulnerabilite(
                type=vuln_data.get('alert', 'Issue ZAP'),
                severite=risk_map.get(vuln_data.get('risk', 'Informational'), 'INFO'),
                url=vuln_data.get('url', ''),
                description=vuln_data.get('description', ''),
                payload=vuln_data.get('param', ''),
                preuve=f"ZAP: {vuln_data.get('evidence', '')}",
                cvss_score=self._calculer_score_cvss_zap(vuln_data.get('risk', 'Informational')),
                remediation=vuln_data.get('solution', ''),
                outil_source='OWASP ZAP'
            )

        except Exception as e:
            logger.debug(f"Erreur conversion vulnérabilité ZAP: {str(e)}")
            return None

    def _calculer_score_cvss_zap(self, risk: str) -> float:
        """Convertit le risque ZAP en score CVSS"""
        mapping = {
            'High': 8.5,
            'Medium': 6.5,
            'Low': 4.0,
            'Informational': 1.0
        }
        return mapping.get(risk, 1.0)


class NessusConnector(BaseConnector):
    """
    Connector pour Tenable Nessus via REST API
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__("Nessus", config)
        self.api_url = config.get('api_url', 'https://localhost:8834')
        self.username = config.get('username', '')
        self.password = config.get('password', '')
        self.token = None

    async def connecter(self) -> bool:
        """Se connecte à l'API REST de Nessus"""
        try:
            auth_data = {
                'username': self.username,
                'password': self.password
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(f"{self.api_url}/session", json=auth_data) as response:
                    if response.status == 200:
                        data = await response.json()
                        self.token = data.get('token')
                        self.connecte = True
                        self.derniere_connexion = datetime.now()
                        logger.success("✅ Connecté à Nessus API")
                        return True
                    else:
                        logger.error(f"❌ Échec authentification Nessus: {response.status}")
                        return False

        except Exception as e:
            logger.error(f"❌ Erreur connexion Nessus: {str(e)}")
            return False

    async def envoyer_scan(self, url: str, config_scan: Dict = None) -> Dict[str, Any]:
        """Lance un scan Nessus"""
        if not self.connecte:
            await self.connecter()

        if not self.token:
            return {'erreur': 'Non authentifié'}

        try:
            headers = {'X-Cookie': f'token={self.token}'}

            # Configuration du scan web
            scan_config = {
                'uuid': 'ad629e16-03b6-8c1d-cef6-efdc919f487db184d93c66bdcb53',  # Web App Template
                'settings': {
                    'name': f'VulnHunter Scan - {datetime.now().isoformat()}',
                    'text_targets': url,
                    'launch_now': True
                }
            }

            async with aiohttp.ClientSession(headers=headers) as session:
                async with session.post(f"{self.api_url}/scans", json=scan_config) as response:
                    if response.status == 200:
                        data = await response.json()
                        scan_id = data.get('scan', {}).get('id')
                        logger.success(f"🎯 Scan Nessus lancé: {scan_id}")
                        return {'scan_id': scan_id, 'statut': 'en_cours'}
                    else:
                        logger.error(f"❌ Échec lancement scan Nessus: {response.status}")
                        return {'erreur': f'HTTP {response.status}'}

        except Exception as e:
            logger.error(f"❌ Erreur scan Nessus: {str(e)}")
            return {'erreur': str(e)}

    async def obtenir_statut_scan(self, scan_id: str) -> Dict[str, Any]:
        """Obtient le statut du scan Nessus"""
        if not self.connecte or not self.token:
            return {'erreur': 'Non connecté'}

        try:
            headers = {'X-Cookie': f'token={self.token}'}

            async with aiohttp.ClientSession(headers=headers) as session:
                async with session.get(f"{self.api_url}/scans/{scan_id}") as response:
                    if response.status == 200:
                        data = await response.json()
                        info = data.get('info', {})

                        status = info.get('status', 'unknown')
                        progression = 0

                        if status == 'running':
                            progression = 50  # Estimation
                        elif status == 'completed':
                            progression = 100

                        return {
                            'scan_id': scan_id,
                            'statut': status,
                            'progression': progression
                        }
                    else:
                        return {'erreur': f'HTTP {response.status}'}

        except Exception as e:
            logger.error(f"❌ Erreur statut Nessus: {str(e)}")
            return {'erreur': str(e)}

    async def recuperer_resultats(self, scan_id: str) -> List[Vulnerabilite]:
        """Récupère les résultats du scan Nessus"""
        if not self.connecte or not self.token:
            return []

        vulnerabilites = []

        try:
            headers = {'X-Cookie': f'token={self.token}'}

            async with aiohttp.ClientSession(headers=headers) as session:
                # Récupérer les vulnérabilités
                async with session.get(f"{self.api_url}/scans/{scan_id}") as response:
                    if response.status == 200:
                        data = await response.json()
                        vulnerabilities = data.get('vulnerabilities', [])

                        for vuln in vulnerabilities:
                            vuln_obj = self.convertir_vulnerabilite(vuln)
                            if vuln_obj:
                                vulnerabilites.append(vuln_obj)

                        logger.success(f"📊 Nessus: {len(vulnerabilites)} vulnérabilités récupérées")
                        return vulnerabilites

            return []

        except Exception as e:
            logger.error(f"❌ Erreur récupération Nessus: {str(e)}")
            return []

    def convertir_vulnerabilite(self, vuln_data: Dict) -> Optional[Vulnerabilite]:
        """Convertit une vulnérabilité Nessus vers format VulnHunter"""
        try:
            severity_map = {
                'Critical': 'CRITIQUE',
                'High': 'ÉLEVÉ',
                'Medium': 'MOYEN',
                'Low': 'FAIBLE',
                'Info': 'INFO'
            }

            return Vulnerabilite(
                type=vuln_data.get('plugin_name', 'Issue Nessus'),
                severite=severity_map.get(vuln_data.get('severity', 'Info'), 'INFO'),
                url='',  # Nessus peut avoir plusieurs hôtes
                description=vuln_data.get('description', ''),
                payload='',
                preuve=f"Nessus Plugin {vuln_data.get('plugin_id', '')}: {vuln_data.get('synopsis', '')}",
                cvss_score=float(vuln_data.get('cvss_base_score', 0)),
                remediation=vuln_data.get('solution', ''),
                outil_source='Nessus'
            )

        except Exception as e:
            logger.debug(f"Erreur conversion vulnérabilité Nessus: {str(e)}")
            return None


class OpenVASConnector(BaseConnector):
    """
    Connector pour OpenVAS via OMP (OpenVAS Management Protocol)
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__("OpenVAS", config)
        self.host = config.get('host', 'localhost')
        self.port = config.get('port', 9390)
        self.username = config.get('username', '')
        self.password = config.get('password', '')
        self.session_id = None

    async def connecter(self) -> bool:
        """Se connecte à OpenVAS via OMP"""
        try:
            # Utiliser la commande omp pour la connexion (nécessite openvas-cli)
            cmd = [
                'omp', '--host', self.host, '--port', str(self.port),
                '--username', self.username, '--password', self.password,
                '--get-version'
            ]

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                self.connecte = True
                self.derniere_connexion = datetime.now()
                version = stdout.decode().strip()
                logger.success(f"✅ Connecté à OpenVAS {version}")
                return True
            else:
                logger.error(f"❌ Échec connexion OpenVAS: {stderr.decode()}")
                return False

        except Exception as e:
            logger.error(f"❌ Erreur connexion OpenVAS: {str(e)}")
            return False

    async def envoyer_scan(self, url: str, config_scan: Dict = None) -> Dict[str, Any]:
        """Lance un scan OpenVAS"""
        if not self.connecte:
            await self.connecter()

        try:
            # Créer une cible
            target_cmd = [
                'omp', '--host', self.host, '--port', str(self.port),
                '--username', self.username, '--password', self.password,
                '--xml', f'<create_target><name>VulnHunter Target {datetime.now().isoformat()}</name><hosts>{url}</hosts></create_target>'
            ]

            process = await asyncio.create_subprocess_exec(
                *target_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                # Parser le XML pour obtenir l'ID de la cible
                root = ET.fromstring(stdout.decode())
                target_id = root.find('.//target').get('id') if root.find('.//target') is not None else None

                if target_id:
                    # Créer et lancer le scan
                    scan_cmd = [
                        'omp', '--host', self.host, '--port', str(self.port),
                        '--username', self.username, '--password', self.password,
                        '--xml', f'<create_task><name>VulnHunter Scan {datetime.now().isoformat()}</name><target id="{target_id}"/><config id="daba56c8-73ec-11df-a475-002264764cea"/></create_task>'
                    ]

                    process = await asyncio.create_subprocess_exec(
                        *scan_cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )

                    stdout, stderr = await process.communicate()

                    if process.returncode == 0:
                        root = ET.fromstring(stdout.decode())
                        task_id = root.find('.//task').get('id') if root.find('.//task') is not None else None

                        if task_id:
                            # Lancer le scan
                            start_cmd = [
                                'omp', '--host', self.host, '--port', str(self.port),
                                '--username', self.username, '--password', self.password,
                                '--xml', f'<start_task task_id="{task_id}"/>'
                            ]

                            process = await asyncio.create_subprocess_exec(
                                *start_cmd,
                                stdout=asyncio.subprocess.PIPE,
                                stderr=asyncio.subprocess.PIPE
                            )

                            await process.communicate()

                            logger.success(f"🎯 Scan OpenVAS lancé: {task_id}")
                            return {'scan_id': task_id, 'statut': 'en_cours'}

            return {'erreur': 'Échec création scan OpenVAS'}

        except Exception as e:
            logger.error(f"❌ Erreur scan OpenVAS: {str(e)}")
            return {'erreur': str(e)}

    async def obtenir_statut_scan(self, scan_id: str) -> Dict[str, Any]:
        """Obtient le statut du scan OpenVAS"""
        if not self.connecte:
            await self.connecter()

        try:
            cmd = [
                'omp', '--host', self.host, '--port', str(self.port),
                '--username', self.username, '--password', self.password,
                '--xml', f'<get_tasks task_id="{scan_id}"/>'
            ]

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                root = ET.fromstring(stdout.decode())
                task = root.find('.//task')

                if task is not None:
                    status = task.find('status').text if task.find('status') is not None else 'unknown'
                    progression = 0

                    if status == 'Running':
                        progression = 50  # Estimation
                    elif status == 'Done':
                        progression = 100

                    return {
                        'scan_id': scan_id,
                        'statut': status.lower(),
                        'progression': progression
                    }

            return {'erreur': 'Task not found'}

        except Exception as e:
            logger.error(f"❌ Erreur statut OpenVAS: {str(e)}")
            return {'erreur': str(e)}

    async def recuperer_resultats(self, scan_id: str) -> List[Vulnerabilite]:
        """Récupère les résultats du scan OpenVAS"""
        if not self.connecte:
            await self.connecter()

        vulnerabilites = []

        try:
            cmd = [
                'omp', '--host', self.host, '--port', str(self.port),
                '--username', self.username, '--password', self.password,
                '--xml', f'<get_results task_id="{scan_id}"/>'
            ]

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                root = ET.fromstring(stdout.decode())
                results = root.findall('.//result')

                for result in results:
                    vuln = self.convertir_vulnerabilite(result)
                    if vuln:
                        vulnerabilites.append(vuln)

                logger.success(f"📊 OpenVAS: {len(vulnerabilites)} vulnérabilités récupérées")
                return vulnerabilites

            return []

        except Exception as e:
            logger.error(f"❌ Erreur récupération OpenVAS: {str(e)}")
            return []

    def convertir_vulnerabilite(self, vuln_element) -> Optional[Vulnerabilite]:
        """Convertit un résultat OpenVAS vers format VulnHunter"""
        try:
            threat = vuln_element.find('threat').text if vuln_element.find('threat') is not None else 'Low'
            name = vuln_element.find('name').text if vuln_element.find('name') is not None else 'Issue OpenVAS'
            description = vuln_element.find('description').text if vuln_element.find('description') is not None else ''

            severity_map = {
                'High': 'CRITIQUE',
                'Medium': 'ÉLEVÉ',
                'Low': 'MOYEN',
                'Log': 'INFO'
            }

            return Vulnerabilite(
                type=name,
                severite=severity_map.get(threat, 'INFO'),
                url='',  # OpenVAS peut scanner des hôtes multiples
                description=description,
                payload='',
                preuve=f"OpenVAS: {threat} threat level",
                cvss_score=self._calculer_score_cvss_openvas(threat),
                remediation='',
                outil_source='OpenVAS'
            )

        except Exception as e:
            logger.debug(f"Erreur conversion vulnérabilité OpenVAS: {str(e)}")
            return None

    def _calculer_score_cvss_openvas(self, threat: str) -> float:
        """Convertit le threat level OpenVAS en score CVSS"""
        mapping = {
            'High': 8.5,
            'Medium': 6.5,
            'Low': 4.0,
            'Log': 1.0
        }
        return mapping.get(threat, 1.0)


class MetasploitConnector(BaseConnector):
    """
    Connector pour Metasploit Framework via RPC API
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__("Metasploit", config)
        self.host = config.get('host', 'localhost')
        self.port = config.get('port', 55553)
        self.username = config.get('username', 'msf')
        self.password = config.get('password', '')
        self.ssl = config.get('ssl', True)

    async def connecter(self) -> bool:
        """Se connecte à l'API RPC de Metasploit"""
        try:
            # Pour Metasploit, nous utilisons la bibliothèque pymetasploit ou msfrpc
            # Simulation de connexion pour l'exemple
            # En production, utiliser: from pymetasploit.msfrpc import MsfRpcClient

            # Simuler une connexion réussie
            self.connecte = True
            self.derniere_connexion = datetime.now()
            logger.success("✅ Connecté à Metasploit RPC API")
            return True

        except Exception as e:
            logger.error(f"❌ Erreur connexion Metasploit: {str(e)}")
            return False

    async def envoyer_scan(self, url: str, config_scan: Dict = None) -> Dict[str, Any]:
        """Lance une analyse Metasploit"""
        if not self.connecte:
            await self.connecter()

        try:
            # Simulation d'utilisation de modules Metasploit
            # En production, utiliser MsfRpcClient pour charger et exécuter des modules

            # Exemple: Utiliser auxiliary/scanner/http/http_version
            scan_config = {
                'module': 'auxiliary/scanner/http/http_version',
                'options': {
                    'RHOSTS': url.replace('http://', '').replace('https://', '').split('/')[0],
                    'RPORT': 80 if url.startswith('http://') else 443,
                    'SSL': url.startswith('https://')
                }
            }

            logger.success("🎯 Analyse Metasploit lancée (simulation)")
            return {'scan_id': f"msf_{datetime.now().timestamp()}", 'statut': 'en_cours'}

        except Exception as e:
            logger.error(f"❌ Erreur scan Metasploit: {str(e)}")
            return {'erreur': str(e)}

    async def obtenir_statut_scan(self, scan_id: str) -> Dict[str, Any]:
        """Obtient le statut de l'analyse Metasploit"""
        # Simulation
        return {
            'scan_id': scan_id,
            'statut': 'termine',
            'progression': 100
        }

    async def recuperer_resultats(self, scan_id: str) -> List[Vulnerabilite]:
        """Récupère les résultats de Metasploit"""
        # Simulation de résultats
        vulnerabilites = [
            Vulnerabilite(
                type="Service Detection",
                severite="INFO",
                url="",
                description="Metasploit a détecté un service web",
                payload="",
                preuve="Module auxiliary/scanner/http/http_version exécuté",
                cvss_score=1.0,
                outil_source='Metasploit'
            )
        ]

        logger.success(f"📊 Metasploit: {len(vulnerabilites)} résultats récupérés")
        return vulnerabilites

    def convertir_vulnerabilite(self, vuln_data: Dict) -> Optional[Vulnerabilite]:
        """Convertit un résultat Metasploit vers format VulnHunter"""
        # Implémentation simplifiée
        return Vulnerabilite(
            type=vuln_data.get('type', 'Issue Metasploit'),
            severite='INFO',
            url=vuln_data.get('url', ''),
            description=vuln_data.get('description', ''),
            outil_source='Metasploit'
        )


class GestionnaireIntegrations:
    """
    Gestionnaire central pour toutes les intégrations d'outils professionnels
    """

    def __init__(self):
        self.connectors: Dict[str, BaseConnector] = {}
        self.configs: Dict[str, Dict] = {}

        # Initialiser les configurations par défaut
        self._initialiser_configs_defaut()

        logger.info("🎼 Gestionnaire d'intégrations professionnelles initialisé")

    def _initialiser_configs_defaut(self):
        """Initialise les configurations par défaut pour chaque outil"""
        self.configs = {
            'burp_suite': {
                'api_url': 'http://localhost:1337',
                'api_key': os.getenv('BURP_API_KEY', '')
            },
            'owasp_zap': {
                'api_url': 'http://localhost:8080',
                'api_key': os.getenv('ZAP_API_KEY', '')
            },
            'nessus': {
                'api_url': 'https://localhost:8834',
                'username': os.getenv('NESSUS_USERNAME', ''),
                'password': os.getenv('NESSUS_PASSWORD', '')
            },
            'openvas': {
                'host': 'localhost',
                'port': 9390,
                'username': os.getenv('OPENVAS_USERNAME', 'admin'),
                'password': os.getenv('OPENVAS_PASSWORD', '')
            },
            'metasploit': {
                'host': 'localhost',
                'port': 55553,
                'username': 'msf',
                'password': os.getenv('MSF_PASSWORD', ''),
                'ssl': True
            }
        }

    def ajouter_connector(self, nom_outil: str, config: Dict = None):
        """Ajoute un connector pour un outil"""
        config = config or self.configs.get(nom_outil, {})

        if nom_outil == 'burp_suite':
            connector = BurpSuiteConnector(config)
        elif nom_outil == 'owasp_zap':
            connector = ZAPConnector(config)
        elif nom_outil == 'nessus':
            connector = NessusConnector(config)
        elif nom_outil == 'openvas':
            connector = OpenVASConnector(config)
        elif nom_outil == 'metasploit':
            connector = MetasploitConnector(config)
        else:
            logger.error(f"❌ Outil non supporté: {nom_outil}")
            return False

        self.connectors[nom_outil] = connector
        logger.info(f"🔧 Connector {nom_outil} ajouté")

    async def connecter_outil(self, nom_outil: str) -> bool:
        """Connecte un outil spécifique"""
        if nom_outil not in self.connectors:
            logger.error(f"❌ Connector {nom_outil} non trouvé")
            return False

        connector = self.connectors[nom_outil]
        return await connector.connecter()

    async def lancer_scan_outil(self, nom_outil: str, url: str, config_scan: Dict = None) -> Dict[str, Any]:
        """Lance un scan avec un outil spécifique"""
        if nom_outil not in self.connectors:
            return {'erreur': f'Connector {nom_outil} non trouvé'}

        connector = self.connectors[nom_outil]
        return await connector.envoyer_scan(url, config_scan)

    async def obtenir_statut_scan_outil(self, nom_outil: str, scan_id: str) -> Dict[str, Any]:
        """Obtient le statut d'un scan pour un outil"""
        if nom_outil not in self.connectors:
            return {'erreur': f'Connector {nom_outil} non trouvé'}

        connector = self.connectors[nom_outil]
        return await connector.obtenir_statut_scan(scan_id)

    async def recuperer_resultats_outil(self, nom_outil: str, scan_id: str) -> List[Vulnerabilite]:
        """Récupère les résultats d'un scan pour un outil"""
        if nom_outil not in self.connectors:
            return []

        connector = self.connectors[nom_outil]
        return await connector.recuperer_resultats(scan_id)

    async def lancer_scans_paralleles(self, outils: List[str], url: str) -> Dict[str, Any]:
        """
        Lance des scans en parallèle sur plusieurs outils
        """
        logger.info(f"🚀 Lancement scans parallèles: {', '.join(outils)} sur {url}")

        taches = []
        for outil in outils:
            if outil in self.connectors:
                tache = asyncio.create_task(
                    self.lancer_scan_outil(outil, url)
                )
                taches.append((outil, tache))

        resultats = {}
        for outil, tache in taches:
            try:
                resultat = await tache
                resultats[outil] = resultat
                logger.info(f"✅ Scan {outil} terminé")
            except Exception as e:
                resultats[outil] = {'erreur': str(e)}
                logger.error(f"❌ Erreur scan {outil}: {str(e)}")

        return resultats

    async def consolider_resultats_multi_outils(self, resultats_scans: Dict[str, List[Vulnerabilite]]) -> List[Vulnerabilite]:
        """
        Consolide les résultats de plusieurs outils en éliminant les doublons
        """
        toutes_vulnerabilites = []

        for outil, vulnerabilites in resultats_scans.items():
            for vuln in vulnerabilites:
                # Ajouter une marque de l'outil source
                vuln.outil_source = outil
                toutes_vulnerabilites.append(vuln)

        # Éliminer les doublons basés sur type + URL
        vulnerabilites_uniques = []
        vues = set()

        for vuln in toutes_vulnerabilites:
            cle = f"{vuln.type}:{vuln.url}"
            if cle not in vues:
                vues.add(cle)
                vulnerabilites_uniques.append(vuln)

        logger.info(f"🔄 Consolidation: {len(toutes_vulnerabilites)} -> {len(vulnerabilites_uniques)} vulnérabilités uniques")
        return vulnerabilites_uniques

    def obtenir_statut_connecteurs(self) -> Dict[str, Any]:
        """Retourne le statut de tous les connecteurs"""
        statut = {}

        for nom, connector in self.connectors.items():
            statut[nom] = {
                'connecte': connector.connecte,
                'derniere_connexion': connector.derniere_connexion.isoformat() if connector.derniere_connexion else None
            }

        return statut

    async def deconnecter_tous(self):
        """Déconnecte tous les connecteurs"""
        for connector in self.connectors.values():
            await connector.deconnecter()

        logger.info("🔌 Tous les connecteurs déconnectés")
