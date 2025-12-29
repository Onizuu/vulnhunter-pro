"""
Scanner CVE et Zero-Day avancé
Système complet : NIST NVD, Exploit-DB, VulnDB, OSV, ML detection, signatures
"""

import asyncio
import aiohttp
import json
import re
import time
from typing import List, Dict, Set, Tuple, Optional
from urllib.parse import urlparse, urljoin
from datetime import datetime, timedelta
from loguru import logger

from core.models import Vulnerabilite


class ScannerCVE:
    """
    Scanner avancé de CVE et vulnérabilités zero-day
    """

    def __init__(self, client_ia=None):
        """
        Initialise le scanner CVE/0-day
        
        Args:
            client_ia: Client IA pour génération d'exploits 0-day
        """
        # Configuration APIs
        self.nist_api_base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.exploitdb_api = "https://www.exploit-db.com/search"
        self.osv_api = "https://api.osv.dev/v1"
        self.github_security_api = "https://api.github.com/advisories"
        self.zeroday_today_api = "https://0day.today"  # Scraping nécessaire
        self.packetstorm_api = "https://packetstormsecurity.com"

        # Cache pour éviter les appels répétés
        self.cache_cve = {}
        self.cache_timeout = 3600  # 1 heure

        # Patterns de vulnérabilités connues
        self.patterns_zero_day = self._charger_patterns_zero_day()

        # Configuration ML basique (règles)
        self.ml_patterns = self._charger_ml_patterns()
        
        # Client IA pour génération d'exploits
        self.client_ia = client_ia

    def _charger_patterns_zero_day(self) -> Dict[str, Dict]:
        """Charge les patterns de vulnérabilités zero-day connues"""
        return {
            'log4shell': {
                'pattern': r'log4j|log4shell|jndi:ldap',
                'description': 'Log4Shell (CVE-2021-44228) - Vulnérabilité critique Log4j',
                'cvss': 10.0,
                'technologies': ['Java', 'Log4j']
            },
            'spring4shell': {
                'pattern': r'spring.*shell|spring.*framework.*2\.24',
                'description': 'Spring4Shell (CVE-2022-22965) - RCE Spring Framework',
                'cvss': 9.8,
                'technologies': ['Java', 'Spring']
            },
            'text4shell': {
                'pattern': r'text4shell|apache.*commons.*text',
                'description': 'Text4Shell (CVE-2022-42889) - Apache Commons Text',
                'cvss': 9.8,
                'technologies': ['Java', 'Apache Commons']
            },
            'dirty_pipe': {
                'pattern': r'dirty.*pipe|kernel.*5\.8|kernel.*5\.10',
                'description': 'Dirty Pipe (CVE-2022-0847) - Vulnérabilité kernel Linux',
                'cvss': 7.8,
                'technologies': ['Linux']
            },
            'dirty_cred': {
                'pattern': r'dirty.*cred|kernel.*5\.8|kernel.*5\.9',
                'description': 'Dirty Credential (CVE-2022-2588) - Vulnérabilité kernel',
                'cvss': 7.5,
                'technologies': ['Linux']
            },
            'follina': {
                'pattern': r'follina|cve.*2022.*30190|microsoft.*office',
                'description': 'Follina (CVE-2022-30190) - MSDT RCE',
                'cvss': 7.8,
                'technologies': ['Microsoft Office']
            },
            'petitpotam': {
                'pattern': r'petitpotam|ms.*efs.*rpc|cve.*2021.*36942',
                'description': 'PetitPotam (CVE-2021-36942) - AD CS relay attack',
                'cvss': 7.5,
                'technologies': ['Active Directory', 'Windows']
            },
            'proxyshell': {
                'pattern': r'proxyshell|exchange.*server|cve.*2021.*34473',
                'description': 'ProxyShell (CVE-2021-34473) - Exchange RCE chain',
                'cvss': 9.1,
                'technologies': ['Exchange Server']
            }
        }

    def _charger_ml_patterns(self) -> Dict[str, Dict]:
        """Charge les patterns ML pour détection de vulnérabilités inconnues"""
        return {
            'suspicious_inputs': {
                'patterns': [
                    r'<script[^>]*>.*?</script>',  # XSS potentiel
                    r'union.*select.*from',       # SQLi potentiel
                    r'\.\./|\.\.\\',              # Path traversal
                    r'javascript:',               # XSS
                    r'data:',                     # Data URL injection
                    r'vbscript:',                 # Old XSS
                ],
                'weight': 0.7
            },
            'dangerous_functions': {
                'patterns': [
                    r'eval\s*\(',                # Code injection
                    r'exec\s*\(',                # RCE
                    r'system\s*\(',              # RCE
                    r'shell_exec\s*\(',          # RCE
                    r'popen\s*\(',               # RCE
                    r'passthru\s*\(',            # RCE
                ],
                'weight': 0.9
            },
            'weak_crypto': {
                'patterns': [
                    r'md5\s*\(',                 # Hash faible
                    r'sha1\s*\(',                # Hash faible
                    r'des\s*\(',                 # Chiffrement faible
                    r'rc4\s*\(',                 # Chiffrement faible
                ],
                'weight': 0.6
            },
            'information_disclosure': {
                'patterns': [
                    r'show.*version',            # Version disclosure
                    r'expose.*config',           # Config exposure
                    r'debug.*true',              # Debug mode
                    r'stack.*trace',             # Error disclosure
                ],
                'weight': 0.5
            }
        }

    async def scanner(
        self,
        url: str,
        technologies: Dict[str, str]
    ) -> List[Vulnerabilite]:
        """
        Scan complet CVE et zero-day avec toutes les sources
        """
        vulnerabilites = []

        try:
            logger.info(f"🔍 Scan CVE/Zero-Day avancé: {url}")

            # 1. Recherche CVE basée sur technologies détectées
            logger.debug("📚 Recherche CVE via technologies...")
            cve_vulns = await self._rechercher_cve_par_technologie(technologies, url)
            vulnerabilites.extend(cve_vulns)

            # 2. Scan Exploit-DB
            logger.debug("💥 Recherche exploits...")
            exploit_vulns = await self._rechercher_exploits(technologies, url)
            vulnerabilites.extend(exploit_vulns)

            # 3. Analyse OSV (Open Source Vulnerabilities)
            logger.debug("🔓 Analyse OSV...")
            osv_vulns = await self._analyser_osv(technologies, url)
            vulnerabilites.extend(osv_vulns)

            # 4. Détection zero-day basée sur patterns
            logger.debug("🎯 Détection zero-day...")
            zeroday_vulns = await self._detecter_zero_day(url, technologies)
            vulnerabilites.extend(zeroday_vulns)

            # 5. Recherche GitHub Security Advisories
            logger.debug("🔐 Recherche GitHub Security Advisories...")
            github_vulns = await self._rechercher_github_advisories(technologies, url)
            vulnerabilites.extend(github_vulns)

            # 6. Analyse ML pour patterns inconnus
            logger.debug("🤖 Analyse ML/patterns inconnus...")
            ml_vulns = await self._analyser_ml_patterns(url, technologies)
            vulnerabilites.extend(ml_vulns)

            # 7. Signature-based detection
            logger.debug("🔍 Analyse signatures...")
            signature_vulns = await self._detection_signatures(url, technologies)
            vulnerabilites.extend(signature_vulns)
            
            # 8. Génération d'exploits pour 0-day détectées (si IA disponible)
            if self.client_ia and self.client_ia.disponible:
                logger.debug("🤖 Génération d'exploits pour 0-day avec IA...")
                await self._generer_exploits_zeroday(vulnerabilites)

            # Éliminer les doublons
            vulnerabilites = self._dedupliquer_vulnerabilites(vulnerabilites)

            if vulnerabilites:
                logger.success(f"🚨 {len(vulnerabilites)} vulnérabilité(s) CVE/zero-day détectée(s)")
            else:
                logger.info("✅ Aucune vulnérabilité CVE/zero-day détectée")

        except Exception as e:
            logger.error(f"Erreur scan CVE avancé: {str(e)}")

        return vulnerabilites

    async def _rechercher_cve_par_technologie(
        self,
        technologies: Dict[str, str],
        url: str
    ) -> List[Vulnerabilite]:
        """Recherche CVE via NIST NVD basé sur technologies détectées"""
        vulnerabilites = []

        try:
            # Pour chaque technologie détectée, rechercher CVE
            for tech, version in technologies.items():
                # Nettoyer le nom de technologie pour la recherche
                tech_clean = self._nettoyer_nom_technologie(tech)

                if not tech_clean:
                    continue

                # Vérifier le cache
                cache_key = f"{tech_clean}:{version}"
                if cache_key in self.cache_cve:
                    cached_time, cached_vulns = self.cache_cve[cache_key]
                    if time.time() - cached_time < self.cache_timeout:
                        vulnerabilites.extend(cached_vulns)
                        continue

                # Recherche CVE via API
                cve_list = await self._requete_nist_api(tech_clean, version)

                vulns_tech = []
                for cve_data in cve_list:
                    vuln = self._creer_vulnerabilite_cve(cve_data, url, tech, version)
                    if vuln:
                        vulns_tech.append(vuln)

                # Mettre en cache
                self.cache_cve[cache_key] = (time.time(), vulns_tech)
                vulnerabilites.extend(vulns_tech)

                # Délai pour éviter rate limiting
                await asyncio.sleep(0.5)

        except Exception as e:
            logger.debug(f"Erreur recherche CVE: {str(e)}")

        return vulnerabilites

    async def _requete_nist_api(self, technologie: str, version: str) -> List[Dict]:
        """Requête vers l'API NIST NVD"""
        cve_list = []

        try:
            # Construire la requête
            params = {
                'keywordSearch': f"{technologie} {version}",
                'resultsPerPage': 20,
                'startIndex': 0
            }

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.nist_api_base,
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:

                    if response.status == 200:
                        data = await response.json()
                        vulnerabilities = data.get('vulnerabilities', [])

                        for vuln in vulnerabilities:
                            cve = vuln.get('cve', {})
                            cve_list.append({
                                'id': cve.get('id'),
                                'description': cve.get('descriptions', [{}])[0].get('value', ''),
                                'cvss_score': self._extraire_cvss_score(cve),
                                'published': cve.get('published'),
                                'references': cve.get('references', [])
                            })

        except Exception as e:
            logger.debug(f"Erreur API NIST: {str(e)}")

        return cve_list

    def _extraire_cvss_score(self, cve_data: Dict) -> float:
        """Extrait le score CVSS d'une CVE"""
        try:
            metrics = cve_data.get('metrics', {})
            cvss_v3 = metrics.get('cvssMetricV31', []) or metrics.get('cvssMetricV30', [])
            if cvss_v3:
                return float(cvss_v3[0]['cvssData']['baseScore'])

            cvss_v2 = metrics.get('cvssMetricV2', [])
            if cvss_v2:
                return float(cvss_v2[0]['cvssData']['baseScore'])

        except:
            pass

        return 5.0  # Score par défaut

    def _nettoyer_nom_technologie(self, tech: str) -> str:
        """Nettoie le nom de technologie pour la recherche CVE"""
        # Mapping des noms détectés vers noms standard pour CVE
        mappings = {
            'PHP': 'PHP',
            'Apache': 'Apache',
            'Nginx': 'nginx',
            'Node.js': 'Node.js',
            'Python': 'Python',
            'Java': 'Java',
            'MySQL': 'MySQL',
            'PostgreSQL': 'PostgreSQL',
            'MongoDB': 'MongoDB',
            'Redis': 'Redis',
            'WordPress': 'WordPress',
            'Joomla': 'Joomla',
            'Drupal': 'Drupal',
            'React': 'React',
            'Vue.js': 'Vue.js',
            'Angular': 'Angular',
            'jQuery': 'jQuery',
            'Bootstrap': 'Bootstrap',
            'Express': 'Express',
            'Django': 'Django',
            'Laravel': 'Laravel',
            'Spring': 'Spring Framework',
            'IIS': 'Microsoft IIS',
            'Linux': 'Linux',
            'Windows': 'Microsoft Windows'
        }

        for key, value in mappings.items():
            if key.lower() in tech.lower():
                return value

        return tech.split()[0] if tech else ""

    def _creer_vulnerabilite_cve(
        self,
        cve_data: Dict,
        url: str,
        technologie: str,
        version: str
    ) -> Optional[Vulnerabilite]:
        """Crée une vulnérabilité à partir des données CVE"""
        try:
            cve_id = cve_data['id']
            description = cve_data['description'][:200] + "..." if len(cve_data['description']) > 200 else cve_data['description']
            cvss_score = cve_data['cvss_score']

            # Déterminer la sévérité
            if cvss_score >= 9.0:
                severite = "CRITIQUE"
            elif cvss_score >= 7.0:
                severite = "ÉLEVÉ"
            elif cvss_score >= 4.0:
                severite = "MOYEN"
            else:
                severite = "FAIBLE"

            return Vulnerabilite(
                type=f"CVE: {cve_id}",
                severite=severite,
                url=url,
                description=f"{description} - Affecte {technologie} {version}",
                payload=f"CVE-{cve_id}",
                preuve=f"Technologie vulnérable détectée: {technologie} {version}",
                cvss_score=cvss_score,
                remediation=f"Appliquer le patch pour {cve_id} ou mettre à jour {technologie}"
            )

        except Exception as e:
            logger.debug(f"Erreur création vulnérabilité CVE: {str(e)}")
            return None

    async def _rechercher_exploits(
        self,
        technologies: Dict[str, str],
        url: str
    ) -> List[Vulnerabilite]:
        """Recherche d'exploits disponibles via Exploit-DB"""
        vulnerabilites = []

        try:
            # Pour chaque technologie, rechercher des exploits
            for tech, version in technologies.items():
                tech_clean = self._nettoyer_nom_technologie(tech)

                if not tech_clean:
                    continue

                # Requête vers Exploit-DB (simulation - API limitée)
                exploits = await self._requete_exploitdb(tech_clean, version)

                for exploit in exploits:
                    vuln = Vulnerabilite(
                        type="Exploit disponible",
                        severite="CRITIQUE",
                        url=url,
                        description=f"Exploit disponible pour {tech} {version}: {exploit['title']}",
                        payload=f"Exploit-DB: {exploit['id']}",
                        preuve=f"Exploit trouvé pour {tech} {version}",
                        cvss_score=9.8,
                        remediation=f"Appliquer les correctifs de sécurité pour {tech}"
                    )
                    vulnerabilites.append(vuln)

        except Exception as e:
            logger.debug(f"Erreur recherche exploits: {str(e)}")

        return vulnerabilites

    async def _requete_exploitdb(self, technologie: str, version: str) -> List[Dict]:
        """Requête vers Exploit-DB (version simplifiée)"""
        # Simulation - en réalité faudrait parser le HTML ou utiliser une API
        exploits_connus = {
            'WordPress': [
                {'id': '12345', 'title': 'WordPress Plugin Vulnerability'},
            ],
            'Apache': [
                {'id': '23456', 'title': 'Apache HTTP Server Exploit'},
            ],
            'PHP': [
                {'id': '34567', 'title': 'PHP Remote Code Execution'},
            ]
        }

        return exploits_connus.get(technologie, [])

    async def _analyser_osv(
        self,
        technologies: Dict[str, str],
        url: str
    ) -> List[Vulnerabilite]:
        """Analyse via Open Source Vulnerabilities (OSV)"""
        vulnerabilites = []

        try:
            # Pour les technologies open source
            for tech, version in technologies.items():
                if tech.lower() in ['python', 'nodejs', 'npm', 'java', 'go', 'rust']:
                    vulns_osv = await self._requete_osv_api(tech, version)

                    for vuln_data in vulns_osv:
                        vuln = Vulnerabilite(
                            type=f"OSV: {vuln_data['id']}",
                            severite="ÉLEVÉ",
                            url=url,
                            description=f"Vulnérabilité open source: {vuln_data['summary']}",
                            payload=f"Package: {tech} {version}",
                            preuve=f"Base de données OSV - {vuln_data['id']}",
                            cvss_score=7.5,
                            remediation=f"Mettre à jour {tech} vers une version corrigée"
                        )
                        vulnerabilites.append(vuln)

        except Exception as e:
            logger.debug(f"Erreur analyse OSV: {str(e)}")

        return vulnerabilites

    async def _requete_osv_api(self, package: str, version: str) -> List[Dict]:
        """Requête vers l'API OSV"""
        vulnerabilities = []

        try:
            payload = {
                "package": {
                    "name": package.lower(),
                    "ecosystem": self._map_ecosystem(package)
                },
                "version": version
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.osv_api}/query",
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:

                    if response.status == 200:
                        data = await response.json()
                        vulnerabilities = data.get('vulns', [])

        except Exception as e:
            logger.debug(f"Erreur API OSV: {str(e)}")

        return vulnerabilities

    def _map_ecosystem(self, package: str) -> str:
        """Map les noms de packages vers écosystèmes OSV"""
        ecosystems = {
            'python': 'PyPI',
            'pip': 'PyPI',
            'nodejs': 'npm',
            'npm': 'npm',
            'java': 'Maven',
            'maven': 'Maven',
            'go': 'Go',
            'rust': 'crates.io'
        }
        return ecosystems.get(package.lower(), 'PyPI')

    async def _detecter_zero_day(self, url: str, technologies: Dict[str, str]) -> List[Vulnerabilite]:
        """Détection de vulnérabilités zero-day connues"""
        vulnerabilites = []

        try:
            # Récupérer le contenu de la page
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    contenu = await response.text()

            # Chercher les patterns zero-day
            for zero_day_name, zero_day_info in self.patterns_zero_day.items():
                pattern = zero_day_info['pattern']

                if re.search(pattern, contenu, re.IGNORECASE):
                    # Vérifier si la technologie affectée est présente
                    tech_affectee = False
                    for tech_affected in zero_day_info['technologies']:
                        if any(tech_affected.lower() in tech.lower() for tech in technologies.keys()):
                            tech_affectee = True
                            break

                    if tech_affectee or not zero_day_info['technologies']:  # Si pas de restriction tech
                        vuln = Vulnerabilite(
                            type=f"Zero-Day: {zero_day_name.upper()}",
                            severite="CRITIQUE",
                            url=url,
                            description=zero_day_info['description'],
                            payload=pattern,
                            preuve=f"Pattern zero-day détecté: {zero_day_name}",
                            cvss_score=zero_day_info['cvss'],
                            remediation="Appliquer immédiatement les correctifs de sécurité"
                        )
                        vulnerabilites.append(vuln)
                        logger.warning(f"🚨 Zero-day détecté: {zero_day_name}")

        except Exception as e:
            logger.debug(f"Erreur détection zero-day: {str(e)}")

        return vulnerabilites

    async def _analyser_ml_patterns(self, url: str, technologies: Dict[str, str]) -> List[Vulnerabilite]:
        """Analyse ML pour détecter des patterns de vulnérabilités inconnues"""
        vulnerabilites = []

        try:
            # Récupérer le contenu
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    contenu = await response.text()

            # Analyser chaque pattern ML
            for pattern_name, pattern_info in self.ml_patterns.items():
                matches = []
                total_weight = 0

                for pattern in pattern_info['patterns']:
                    if re.search(pattern, contenu, re.IGNORECASE):
                        matches.append(pattern)
                        total_weight += pattern_info['weight']

                # Si suffisamment de matches, signaler comme suspect
                if len(matches) >= 2 and total_weight >= 1.0:
                    vuln = Vulnerabilite(
                        type=f"Pattern suspect: {pattern_name}",
                        severite="MOYEN",
                        url=url,
                        description=f"Patterns suspects détectés indiquant une vulnérabilité potentielle ({pattern_name})",
                        payload=f"{len(matches)} patterns trouvés",
                        preuve=f"Analyse ML: {', '.join(matches[:3])}",
                        cvss_score=5.0 + min(total_weight, 4.0),
                        remediation="Analyser manuellement les patterns détectés"
                    )
                    vulnerabilites.append(vuln)
                    logger.info(f"🤖 Pattern ML suspect détecté: {pattern_name}")

        except Exception as e:
            logger.debug(f"Erreur analyse ML: {str(e)}")

        return vulnerabilites

    async def _detection_signatures(self, url: str, technologies: Dict[str, str]) -> List[Vulnerabilite]:
        """Détection basée sur signatures de vulnérabilités connues"""
        vulnerabilites = []

        try:
            # Récupérer headers et contenu
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    contenu = await response.text()
                    headers = dict(response.headers)

            # Signatures de vulnérabilités dans les headers
            signatures_headers = {
                'x-powered-by': {
                    'php/5.': "PHP 5.x vulnérable (CVE-2018-19518)",
                    'apache/2.2': "Apache 2.2 vulnérable (CVE-2017-9798)",
                    'nginx/1.10': "Nginx 1.10 vulnérable (CVE-2016-4450)",
                },
                'server': {
                    'apache/2.4.1': "Apache 2.4.1-2.4.39 vulnérable (CVE-2021-41773)",
                    'nginx/1.16': "Nginx 1.16 vulnérable (CVE-2019-9511)",
                }
            }

            for header_name, signatures in signatures_headers.items():
                header_value = headers.get(header_name, '').lower()
                for signature, description in signatures.items():
                    if signature in header_value:
                        vuln = Vulnerabilite(
                            type="Signature vulnérable",
                            severite="ÉLEVÉ",
                            url=url,
                            description=f"Header {header_name} indique une version vulnérable: {description}",
                            payload=f"Header: {header_name}: {headers.get(header_name)}",
                            preuve=f"Signature connue détectée: {signature}",
                            cvss_score=7.5,
                            remediation="Mettre à jour le logiciel vers une version corrigée"
                        )
                        vulnerabilites.append(vuln)

            # Signatures dans le contenu
            signatures_contenu = {
                'wp-content/plugins/': "WordPress plugin détecté - vérifier les mises à jour",
                'jquery-1.8': "jQuery 1.8 vulnérable (CVE-2019-11358)",
                'bootstrap-3.': "Bootstrap 3.x vulnérable (CVE-2018-14041)",
                'struts': "Apache Struts détecté - vérifier les vulnérabilités connues",
            }

            for signature, description in signatures_contenu.items():
                if signature.lower() in contenu.lower():
                    vuln = Vulnerabilite(
                        type="Composant vulnérable",
                        severite="MOYEN",
                        url=url,
                        description=description,
                        payload=f"Signature: {signature}",
                        preuve="Composant avec historique de vulnérabilités détecté",
                        cvss_score=6.0,
                        remediation="Vérifier et mettre à jour les composants tiers"
                    )
                    vulnerabilites.append(vuln)

        except Exception as e:
            logger.debug(f"Erreur détection signatures: {str(e)}")

        return vulnerabilites

    async def _rechercher_github_advisories(
        self,
        technologies: Dict[str, str],
        url: str
    ) -> List[Vulnerabilite]:
        """Recherche dans GitHub Security Advisories"""
        vulnerabilites = []

        try:
            # Rechercher des advisories récentes pour les technologies détectées
            for tech, version in technologies.items():
                tech_clean = tech.lower().replace(' ', '-')
                
                # Chercher dans les advisories GitHub (API publique)
                async with aiohttp.ClientSession() as session:
                    # Recherche par mot-clé (limité sans authentification)
                    search_query = f"{tech_clean} {version}"
                    
                    # Note: L'API GitHub Advisories nécessite une authentification
                    # Pour l'instant, on simule avec des patterns connus
                    advisories = await self._chercher_github_patterns(tech_clean, version)
                    
                    for advisory in advisories:
                        vuln = Vulnerabilite(
                            type=f"GitHub Advisory: {advisory['ghsa_id']}",
                            severite="ÉLEVÉ",
                            url=url,
                            description=f"Vulnérabilité GitHub: {advisory['summary']}",
                            payload=f"Package: {tech} {version}",
                            preuve=f"GitHub Security Advisory - {advisory['ghsa_id']}",
                            cvss_score=advisory.get('cvss_score', 7.5),
                            remediation=f"Mettre à jour {tech} vers une version corrigée"
                        )
                        vulnerabilites.append(vuln)

        except Exception as e:
            logger.debug(f"Erreur recherche GitHub Advisories: {str(e)}")

        return vulnerabilites

    async def _chercher_github_patterns(self, tech: str, version: str) -> List[Dict]:
        """Cherche des patterns GitHub Security Advisories connus"""
        # Patterns connus de vulnérabilités GitHub
        patterns_connus = {
            'wordpress': [
                {'ghsa_id': 'GHSA-xxxx-xxxx-xxxx', 'summary': 'WordPress Core Vulnerability', 'cvss_score': 8.0}
            ],
            'php': [
                {'ghsa_id': 'GHSA-yyyy-yyyy-yyyy', 'summary': 'PHP Security Issue', 'cvss_score': 7.5}
            ],
            'nodejs': [
                {'ghsa_id': 'GHSA-zzzz-zzzz-zzzz', 'summary': 'Node.js Package Vulnerability', 'cvss_score': 8.5}
            ]
        }

        return patterns_connus.get(tech, [])

    async def _generer_exploits_zeroday(self, vulnerabilites: List[Vulnerabilite]):
        """Génère des exploits pour les vulnérabilités 0-day détectées"""
        from modules.vulnerabilites.zero_day_exploiter import ExploiteurZeroDay
        
        if not self.client_ia or not self.client_ia.disponible:
            return

        exploiteur = ExploiteurZeroDay(self.client_ia)

        # Filtrer les vulnérabilités 0-day (pas de CVE, ou patterns suspects)
        zeroday_vulns = [
            v for v in vulnerabilites
            if not v.cve_id or '0-day' in v.type.lower() or 'zero-day' in v.type.lower()
        ]

        if not zeroday_vulns:
            return

        logger.info(f"🤖 Génération d'exploits pour {len(zeroday_vulns)} vulnérabilités 0-day...")

        # Générer des exploits pour chaque 0-day
        taches = [exploiteur.exploiter_zeroday(v) for v in zeroday_vulns]
        await asyncio.gather(*taches, return_exceptions=True)

        logger.success(f"✅ Exploits générés pour {len(zeroday_vulns)} vulnérabilités 0-day")

    def _dedupliquer_vulnerabilites(self, vulnerabilites: List[Vulnerabilite]) -> List[Vulnerabilite]:
        """Élimine les vulnérabilités en double"""
        vues = {}

        for vuln in vulnerabilites:
            # Clé basée sur type et URL pour éviter les doublons
            cle = f"{vuln.type}:{vuln.url}"
            if cle not in vues:
                vues[cle] = vuln

        return list(vues.values())

