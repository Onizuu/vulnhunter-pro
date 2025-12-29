"""
Orchestrateur principal des scans
Coordonne tous les modules de scan et l'analyse IA
"""

import asyncio
import aiohttp
import time
import os  # Pour NIST_API_KEY
from datetime import datetime
from typing import Dict, List, Optional
from loguru import logger

from core.models import DonneesReconnaissance, Vulnerabilite, RapportScan
from integration_ia.openai_client import ClientOpenAI
from integration_ia.mistral_client import ClientMistral
from integration_ia.ia_client_fallback import ClientIAFallback
from core.validator import ValidateurVulnerabilites
from core.exploit_generator import GenerateurExploits
from modules.reconnaissance.subdomain_enum import EnumerateurSousdomaines
from modules.reconnaissance.port_scanner import ScannerPorts
from modules.reconnaissance.tech_detection import DetecteurTechnologies
from modules.reconnaissance.directory_fuzzer import FuzzerRepertoires
from modules.reconnaissance.parameter_discovery import DecouvreurParametres
from modules.reconnaissance.wayback_analyzer import WaybackAnalyzer
from modules.reconnaissance.github_recon import GitHubRecon
from modules.vulnerabilites.sql_injection import ScannerSQLInjection
from modules.vulnerabilites.xss_scanner import ScannerXSS
from modules.vulnerabilites.xxe_detector import DetecteurXXE
from modules.vulnerabilites.rce_finder import ChercheurRCE
from modules.vulnerabilites.idor_checker import VerificateurIDOR
from modules.vulnerabilites.cors_miscfg import AnalyseurCORS
from modules.vulnerabilites.header_analysis import AnalyseurHeaders
from modules.vulnerabilites.cve_scanner import ScannerCVE
from modules.vulnerabilites.config_analyzer import AnalyseurConfiguration
from modules.vulnerabilites.auth_bypass import TesteurAuthBypass
from modules.vulnerabilites.csrf_detector import DetecteurCSRF
from modules.vulnerabilites.file_upload_scanner import ScannerFileUpload
from modules.vulnerabilites.api_fuzzer import ApiFuzzer
from modules.vulnerabilites.lfi_scanner import LFIScanner  # ⭐ NOUVEAU: LFI Scanner AutoPWN
from modules.vulnerabilites.graphql_fuzzer import GraphQLFuzzer
# ⭐ NOUVEAUX MODULES v4.3 (comblent les lacunes critiques)
from modules.vulnerabilites.ssrf_detector import DetecteurSSRF
from modules.vulnerabilites.ssti_scanner import ScannerSSTI
from modules.vulnerabilites.nosql_injection import ScannerNoSQLInjection
from modules.vulnerabilites.deserialization_detector import DetecteurDeserialization
from modules.vulnerabilites.waf_detector import DetecteurWAF
# ⭐ NOUVEAUX MODULES v4.4 (couverture complète)
from modules.vulnerabilites.prototype_pollution import DetecteurPrototypePollution
from modules.vulnerabilites.ldap_injection import DetecteurLDAPInjection
from modules.vulnerabilites.open_redirect import DetecteurOpenRedirect
from modules.vulnerabilites.clickjacking import DetecteurClickjacking
from modules.vulnerabilites.websocket_scanner import DetecteurWebSocket
from modules.vulnerabilites.race_conditions import DetecteurRaceConditions
from modules.vulnerabilites.business_logic import DetecteurBusinessLogic
from modules.intelligence.chain_builder import ConstructeurChaines
from modules.intelligence.ml_detector import DetecteurML
from modules.intelligence.risk_scorer import ScorerRisqueIntelligent
from modules.intelligence.ai_payload_generator import GenerateurPayloadsIA
from modules.intelligence.nist_cve_searcher import NISTCVESearcher  # ⭐ NOUVEAU: NIST CVE
from utilitaires.logger import ConfigurerLogger
from urllib.parse import urljoin


class MoteurScanIntelligent:
    """
    Moteur de scan principal qui coordonne toutes les phases
    d'analyse et utilise l'IA pour améliorer la détection
    """

    def __init__(self, config: Dict):
        """
        Initialise le moteur de scan
        
        Args:
            config: Configuration du scan (clés API, intensité, etc.)
        """
        self.config = config
        self.modules_cibles = config.get('modules_cibles', [])  # ⭐ NOUVEAU: Modules à scanner (vide = tous)
        self.scan_type = config.get('scan_type', 'full')  # ⭐ NOUVEAU: 'full' ou 'specific_url'
        self.auth_config = config.get('auth', {})  # ⭐ NOUVEAU: Authentification
        self.ia_active = config.get('ia_active', True)
        self.callback_vulnerabilite = config.get('callback_vulnerabilite')  # ⭐ NOUVEAU: Callback pour le dashboard
        
        # ⭐ NOUVEAU: Contrôle de l'exécution (Pause/Resume)
        self.pause_event = asyncio.Event()
        self.pause_event.set()  # Par défaut, le scan n'est pas en pause
        self.est_en_pause = False
        
        self.client_ia = None
        if self.ia_active:
            # ⭐ NOUVEAU: Système Ollama principal + Claude fallback (budget 5€ max)
            ollama_model = config.get('ollama_model', 'mistral:7b')
            claude_key = config.get('anthropic_api_key')
            budget_max = float(config.get('claude_budget_max', 5.0))  # 5€ par défaut
            
            # Utiliser le système de fallback intelligent
            self.client_ia = ClientIAFallback(
                ollama_model=ollama_model,
                claude_api_key=claude_key,
                budget_max=budget_max
            )
            
            if self.client_ia.disponible:
                logger.info(
                    f"🤖 IA configurée: Ollama principal ({ollama_model})"
                    + (f" + Claude fallback (budget: {budget_max}€)" if claude_key else " (Claude non configuré)")
                )
            else:
                logger.warning("⚠️  Ollama non disponible - Mode sans IA activé")
                logger.info("💡 Installez Ollama: brew install ollama && ollama pull mistral:7b")
        else:
            logger.info("🤖 IA désactivée - utilisation des payloads intégrés (scan plus rapide)")
        
        # ⭐ AMÉLIORATION: Validateur très permissif pour détecter TOUTES les vulnérabilités
        # Mode maximum: accepter toutes les vulnérabilités détectées
        self.validateur = ValidateurVulnerabilites(
            min_confirmations=2,  # ⭐ 2 confirmations requises pour filtrer drastiquement le bruit (182 -> ~20)
            tester_exploitation=True,  # ⭐ Tests d'exploitation réels activés
            client_ia=self.client_ia,  # ⭐ IA pour génération d'exploits personnalisés
            mode_rapide=True  # ⭐ Toujours en mode rapide pour accepter plus
        )
        self.generateur_exploits = GenerateurExploits(self.client_ia)
        
        # Initialiser les modules de reconnaissance
        self.enum_sousdomaines = EnumerateurSousdomaines()
        self.scanner_ports = ScannerPorts()
        self.detecteur_tech = DetecteurTechnologies()
        self.fuzzer_rep = FuzzerRepertoires()
        self.decouvreur_params = DecouvreurParametres(self.auth_config)  # ⭐ NOUVEAU: Découverte automatique de paramètres
        
        # Initialiser les scanners de vulnérabilités
        self.scanner_sql = ScannerSQLInjection(self.client_ia, self.auth_config)
        self.scanner_xss = ScannerXSS(self.client_ia, self.auth_config)
        self.detecteur_xxe = DetecteurXXE()
        self.chercheur_rce = ChercheurRCE(self.client_ia)
        self.verif_idor = VerificateurIDOR()
        self.analyseur_cors = AnalyseurCORS()
        self.analyseur_headers = AnalyseurHeaders()
        self.scanner_cve = ScannerCVE(client_ia=self.client_ia)  # ⭐ IA pour exploits 0-day
        self.analyseur_config = AnalyseurConfiguration(self.client_ia)
        self.testeur_auth = TesteurAuthBypass(self.client_ia)
        self.detecteur_csrf = DetecteurCSRF()
        self.scanner_upload = ScannerFileUpload()  # ⭐ NOUVEAU: Scanner File Upload
        self.api_fuzzer = ApiFuzzer(self.client_ia, self.auth_config)  # ⭐ NOUVEAU: API Fuzzer
        self.graphql_fuzzer = GraphQLFuzzer(None, self.auth_config)  # ⭐ NOUVEAU: GraphQL Fuzzer (session initialisée plus tard)
        self.lfi_scanner = LFIScanner(self.auth_config)  # ⭐ NOUVEAU: LFI Scanner AutoPWN (50+ payloads)
        
        # ⭐ MODULES v4.3: Combler les lacunes critiques
        self.ssrf_detector = DetecteurSSRF(self.auth_config)  # ⭐ SSRF (OWASP Top 10)
        self.ssti_scanner = ScannerSSTI(self.auth_config)  # ⭐ SSTI (RCE critique)
        self.nosql_scanner = ScannerNoSQLInjection(self.auth_config)  # ⭐ NoSQL Injection
        self.deserialization_detector = DetecteurDeserialization(self.auth_config)  # ⭐ Deserialization (Java/Python/PHP)
        self.waf_detector = DetecteurWAF()  # ⭐ WAF Detection
        
        # ⭐ MODULES v4.4: Couverture complète (100%)
        self.prototype_pollution_detector = DetecteurPrototypePollution(self.auth_config)  # ⭐ Prototype Pollution (Node.js)
        self.ldap_injection_detector = DetecteurLDAPInjection(self.auth_config)  # ⭐ LDAP Injection (Active Directory)
        self.open_redirect_detector = DetecteurOpenRedirect(self.auth_config)  # ⭐ Open Redirect (Phishing)
        self.clickjacking_detector = DetecteurClickjacking()  # ⭐ Clickjacking (X-Frame-Options)
        self.websocket_detector = DetecteurWebSocket(self.auth_config)  # ⭐ WebSocket Security
        self.race_conditions_detector = DetecteurRaceConditions(self.auth_config)  # ⭐ Race Conditions (TOCTOU)
        self.business_logic_detector = DetecteurBusinessLogic(self.auth_config)  # ⭐ Business Logic Flaws
        
        # Module d'intelligence
        self.constructeur_chaines = ConstructeurChaines(self.client_ia)
        self.detecteur_ml = DetecteurML()
        self.scorer_risque = ScorerRisqueIntelligent()
        self.generateur_payloads_ia = GenerateurPayloadsIA(self.client_ia)
        self.nist_cve = NISTCVESearcher(api_key=os.getenv('NIST_API_KEY'))  # ⭐ NOUVEAU: NIST CVE Database
        
        # Statistiques
        self.stats = {
            'requetes_totales': 0,
            'vulnerabilites_trouvees': 0,
            'faux_positifs_elimines': 0,
            'temps_par_phase': {}
        }
        
        logger.info("Moteur de scan initialisé avec succès")

    def pauser(self):
        """Met le scan en pause"""
        self.pause_event.clear()
        self.est_en_pause = True
        logger.info("⏸️  Scan mis en pause")

    def reprendre(self):
        """Reprend le scan"""
        self.pause_event.set()
        self.est_en_pause = False
        logger.info("▶️  Scan repris")

    async def scanner_complet(self, url_cible: str) -> RapportScan:
        """
        Exécute un scan complet sur la cible
        
        Args:
            url_cible: URL de la cible à scanner
            
        Returns:
            RapportScan: Rapport complet avec toutes les vulnérabilités
        """
        date_debut = datetime.now()
        logger.info(f"🎯 Démarrage du scan complet sur : {url_cible}")
        
        try:
            # ⭐ Phase 0: Reconnaissance Passive (NOUVEAU)
            import os
            if os.getenv('ENABLE_PASSIVE_RECON', 'true').lower() == 'true':
                logger.info("🕵️  Phase 0: Reconnaissance Passive...")
                passive_data = await self.phase_reconnaissance_passive(url_cible)
                
                # Ajouter les subdomains découverts à la reconnaissance active
                if passive_data.github_subdomains:
                    logger.info(
                        f"📋 {len(passive_data.github_subdomains)} subdomains GitHub ajoutés"
                    )
            else:
                passive_data = None
                logger.info("⏭️  Reconnaissance passive désactivée")
            
            # ⭐ Phase 0.5: Détection WAF (NOUVEAU v4.3)
            logger.info("🛡️  Phase 0.5: Détection de WAF...")
            waf_info = await self.waf_detector.detecter(url_cible)
            if waf_info and waf_info.get('waf_detected'):
                logger.warning(
                    f"⚠️  WAF détecté: {waf_info['waf_type']} "
                    f"(confiance: {waf_info['confidence']}%)"
                )
                logger.info("💡 Suggestions de bypass:")
                for suggestion in waf_info.get('suggestions', [])[:3]:
                    logger.info(f"   - {suggestion}")
            else:
                logger.success("✅ Aucun WAF détecté - scan optimal")
            
            # Phase 1: Reconnaissance
            if self.scan_type == 'specific_url':
                logger.info(f"🎯 Mode ciblé: Scan uniquement sur {url_cible}")
                # Créer des données de reconnaissance minimales
                donnees_recon = DonneesReconnaissance(url_cible=url_cible)
                donnees_recon.repertoires = []  # Pas de crawling
                donnees_recon.technologies = [] # On pourrait détecter, mais on reste simple
                donnees_recon.ports_ouverts = []
                donnees_recon.sousdomaines = []
            else:
                logger.info("📡 Phase 1: Reconnaissance en cours...")
                donnees_recon = await self.phase_reconnaissance(url_cible)
            
            # Phase 2: Détection de vulnérabilités
            logger.info("🔍 Phase 2: Détection de vulnérabilités...")
            vulnerabilites = await self.phase_detection_vulnerabilites(
                url_cible, donnees_recon
            )
            
            # Phase 3: Validation (éliminer les faux positifs)
            logger.info("✅ Phase 3: Validation des découvertes...")
            vulns_validees = await self.phase_validation(vulnerabilites)
            
            # Phase 4: Génération d'exploits
            logger.info("⚡ Phase 4: Génération d'exploits...")
            await self.phase_generation_exploits(vulns_validees)
            
            # Phase 5: Construction de chaînes d'exploit
            logger.info("🔗 Phase 5: Construction de chaînes d'exploit...")
            chaines = await self.phase_chaines_exploit(vulns_validees)
            
            # Phase 6: Évaluation du risque global
            logger.info("📊 Phase 6: Évaluation du risque...")
            score_risque = self.calculer_score_risque_global(vulns_validees)
            
            date_fin = datetime.now()
            duree = (date_fin - date_debut).total_seconds()
            
            # ⭐ Calculer les statistiques par sévérité
            stats_severite = {}
            for vuln in vulns_validees:
                severite = vuln.severite
                stats_severite[severite] = stats_severite.get(severite, 0) + 1
            
            self.stats['par_severite'] = stats_severite
            self.stats['total_vulnerabilites'] = len(vulns_validees)
            
            # Créer le rapport final
            rapport = RapportScan(
                url_cible=url_cible,
                date_debut=date_debut,
                date_fin=date_fin,
                duree=duree,
                vulnerabilites=vulns_validees,
                donnees_recon=donnees_recon,
                score_risque_global=score_risque,
                chaines_exploit=chaines,
                statistiques=self.stats
            )
            
            logger.success(
                f"✨ Scan terminé ! {len(vulns_validees)} vulnérabilités validées "
                f"en {duree:.2f}s"
            )
            
            return rapport
            
        except Exception as e:
            logger.error(f"❌ Erreur lors du scan: {str(e)}")
            raise


    async def phase_reconnaissance_passive(
        self, url_cible: str
    ) -> 'PassiveReconData':
        """
        Phase 0: Reconnaissance Passive
        Utilise sources publiques pour découvrir assets sans être détecté
        
        Args:
            url_cible: URL de la cible
            
        Returns:
            PassiveReconData: Résultats de la reconnaissance passive
        """
        from core.models import PassiveReconData, WaybackResult, GitHubAsset
        import os
        
        debut = time.time()
        logger.info("🕵️  Début reconnaissance passive...")
        
        # Initialiser les modules
        wayback = WaybackAnalyzer()
        github_tokens = os.getenv('GITHUB_TOKENS', '').split(',')
        github_tokens = [t.strip() for t in github_tokens if t.strip()]
        github = GitHubRecon(github_tokens if github_tokens else None)
        
        # Extraire le domaine
        from urllib.parse import urlparse
        parsed = urlparse(url_cible)
        domain = parsed.netloc or parsed.path
        
        try:
            # Wayback Machine
            logger.info("📚 Wayback Machine: Analyse en cours...")
            wayback_urls = wayback.wayback_urls(domain, include_subdomains=False)
            wayback_robots = wayback.wayback_robots(domain)
            wayback_hidden = wayback.find_hidden_endpoints(domain)
            wayback_params = wayback.analyze_parameters(domain)
            
            wayback_result = WaybackResult(
                urls_discovered=wayback_urls,
                robots_paths=wayback_robots,
                hidden_endpoints=wayback_hidden,
                parameters=wayback_params,
                total_urls=len(wayback_urls)
            )
            
            # GitHub Recon
            github_subdomains = []
            github_creds = []
            github_keys = []
            
            if github_tokens:
                logger.info("🔍 GitHub: Recherche d'assets...")
                github_subdomains = github.search_subdomains(domain, max_pages=3)
                github_creds = github.search_credentials(domain, max_pages=2)
                github_keys = github.search_api_keys(domain)
                
                # Convertir en GitHubAsset
                cred_assets = [
                    GitHubAsset(
                        type='credential',
                        value=cred['value'],
                        source=cred['source'],
                        repository=cred.get('repository', ''),
                        path=cred.get('path', ''),
                        severity='CRITICAL'
                    )
                    for cred in github_creds
                ]
                
                key_assets = [
                    GitHubAsset(
                        type='api_key',
                        value=key['key'],
                        source=key['source'],
                        repository=key.get('repository', ''),
                        severity='CRITICAL'
                    )
                    for key in github_keys
                ]
                
                github_creds = cred_assets
                github_keys = key_assets
            else:
                logger.warning("⚠️  Pas de tokens GitHub - Reconnaissance GitHub skip")
            
            # Calculer totaux
            total_assets = (
                len(wayback_urls) + 
                len(wayback_robots) +
                len(github_subdomains) +
                len(github_creds) +
                len(github_keys)
            )
            
            duree = time.time() - debut
            
            passive_data = PassiveReconData(
                wayback_result=wayback_result,
                github_subdomains=github_subdomains,
                github_credentials=github_creds,
                github_api_keys=github_keys,
                total_assets_discovered=total_assets,
                execution_time=duree
            )
            
            logger.success(
                f"✅ Passive Recon terminée: {total_assets} assets en {duree:.2f}s"
            )
            
            # Alerter si credentials trouvés
            if github_creds or github_keys:
                logger.critical(
                    f"🚨 {len(github_creds + github_keys)} CREDENTIALS EXPOSÉS TROUVÉS!"
                )
            
            return passive_data
            
        except Exception as e:
            logger.error(f"❌ Erreur reconnaissance passive: {str(e)}")
            # Retourner données vides en cas d'erreur
            return PassiveReconData(
                total_assets_discovered=0,
                execution_time=time.time() - debut
            )

    async def phase_reconnaissance(
        self, url_cible: str
    ) -> DonneesReconnaissance:
        """
        Phase de reconnaissance : collecter un maximum d'informations sur la cible
        
        Args:
            url_cible: URL de la cible
            
        Returns:
            DonneesReconnaissance: Toutes les données collectées
        """
        debut = time.time()
        donnees = DonneesReconnaissance(url_cible=url_cible)
        
        # Exécuter toutes les tâches de reconnaissance en parallèle
        taches = [
            self.enum_sousdomaines.enumerer(url_cible),
            self.scanner_ports.scanner(url_cible),
            self.detecteur_tech.detecter(url_cible),
            self.fuzzer_rep.fuzzer(url_cible)
        ]
        
        resultats = await asyncio.gather(*taches, return_exceptions=True)
        
        # Traiter les résultats
        if not isinstance(resultats[0], Exception):
            donnees.sousdomaines = resultats[0]
        if not isinstance(resultats[1], Exception):
            donnees.ports_ouverts = resultats[1]
        if not isinstance(resultats[2], Exception):
            donnees.technologies = resultats[2]
        if not isinstance(resultats[3], Exception):
            donnees.repertoires = resultats[3]
        
        self.stats['temps_par_phase']['reconnaissance'] = time.time() - debut
        logger.info(
            f"Reconnaissance terminée: {len(donnees.sousdomaines)} sous-domaines, "
            f"{len(donnees.ports_ouverts)} ports, "
            f"{len(donnees.technologies)} technologies"
        )
        
        return donnees

    async def phase_detection_vulnerabilites(
        self, url_cible: str, donnees_recon: DonneesReconnaissance
    ) -> List[Vulnerabilite]:
        """
        Phase de détection : scanner toutes les vulnérabilités possibles
        
        Args:
            url_cible: URL de la cible
            donnees_recon: Données de la reconnaissance
            
        Returns:
            List[Vulnerabilite]: Liste des vulnérabilités détectées
        """
        debut = time.time()
        vulnerabilites = []
        
        # ⭐ LOGIQUE CIBLAGE MANUEL
        if self.scan_type == 'specific_url':
            logger.info(f"🎯 Scan ciblé sur l'URL unique: {url_cible}")
            endpoints = [url_cible]
        else:
            # ⭐ AMÉLIORATION: Tester TOUS les endpoints découverts, pas seulement ceux qui passent le filtre strict
            # Le filtre est moins strict maintenant, mais on teste aussi les endpoints "suspects"
            logger.info(f"🔍 Filtrage des {len(donnees_recon.repertoires)} URLs découvertes...")
            endpoints_existants = await self._filtrer_endpoints_existants([url_cible] + donnees_recon.repertoires)
            
            # ⭐ NOUVEAU: Ajouter les pages connues de testphp.vulnweb.com et autres sites vulnérables
            pages_connues = self._get_pages_connues(url_cible)
            endpoints_connus = [urljoin(url_cible, page) for page in pages_connues]
            
            # ⭐ NOUVEAU: Ajouter aussi les endpoints découverts même s'ils n'ont pas passé le filtre strict
            # (pour tester les pages qui pourraient être vulnérables mais rejetées par le filtre)
            tous_endpoints = list(set(endpoints_existants + endpoints_connus + donnees_recon.repertoires[:30]))  # ⭐ Augmenté de 20 à 30
            endpoints = tous_endpoints[:self.config.get('max_urls', 80)]  # ⭐ Augmenté de 50 à 80
            
            logger.info(f"✅ {len(endpoints)} endpoints à tester ({len(endpoints_existants)} validés + {len(tous_endpoints) - len(endpoints_existants)} supplémentaires)")
        
        # ⭐ NOUVEAU: Découvrir automatiquement les paramètres pour chaque endpoint
        logger.info(f"🔍 Découverte automatique des paramètres pour {len(endpoints)} endpoints...")
        parametres_par_endpoint = await self.decouvreur_params.decouvrir_pour_endpoints(
            endpoints
        )
        logger.info(f"✅ Paramètres découverts pour {len(parametres_par_endpoint)} endpoints")
        
        # Créer les tâches de scan pour chaque type de vulnérabilité
        taches = []
        
        for endpoint in endpoints:
            # Récupérer les paramètres découverts pour cet endpoint
            params_endpoint = parametres_par_endpoint.get(endpoint, {})
            
            # ⭐ AMÉLIORATION: Tester plus de vulnérabilités par endpoint (avec filtrage par modules)
            modules_vides = not self.modules_cibles or len(self.modules_cibles) == 0
            
            if modules_vides or 'sql' in self.modules_cibles or 'all' in self.modules_cibles:
                taches.append(self.scanner_sql.scanner(endpoint, params_endpoint))
            
            if modules_vides or 'xss' in self.modules_cibles or 'all' in self.modules_cibles:
                taches.append(self.scanner_xss.scanner(endpoint, params_endpoint))
            
            if modules_vides or 'xxe' in self.modules_cibles or 'all' in self.modules_cibles:
                taches.append(self.detecteur_xxe.detecter(endpoint))
            
            if modules_vides or 'rce' in self.modules_cibles or 'all' in self.modules_cibles:
                taches.append(self.chercheur_rce.chercher(endpoint, params_endpoint))
            
            if modules_vides or 'idor' in self.modules_cibles or 'all' in self.modules_cibles:
                taches.append(self.verif_idor.verifier(endpoint))
            
            if modules_vides or 'upload' in self.modules_cibles or 'all' in self.modules_cibles:
                taches.append(self.scanner_upload.scanner(endpoint))

            if modules_vides or 'api' in self.modules_cibles or 'all' in self.modules_cibles:
                # Détecter si c'est une API (JSON)
                # Pour l'instant on passe un dictionnaire vide, le fuzzer devra peut-être découvrir le format
                # Ou on utilise les paramètres découverts s'ils sont au format JSON (à implémenter)
                taches.append(self.api_fuzzer.scanner(endpoint, method="POST", data={"test": "test"})) # Placeholder
            
            # ⭐ NOUVEAU: GraphQL Fuzzing
            if modules_vides or 'graphql' in self.modules_cibles or 'api' in self.modules_cibles or 'all' in self.modules_cibles:
                # Initialiser la session pour GraphQL fuzzer (utilise la session aiohttp du scanner)
                # On ne peut pas initialiser dans __init__ car la session n'existe pas encore
                if not hasattr(self.graphql_fuzzer, 'session') or self.graphql_fuzzer.session is None:
                    # On récupère la session depuis le contexte
                    import aiohttp
                    async def _init_graphql_session():
                        timeout = aiohttp.ClientTimeout(total=30)
                        connector = aiohttp.TCPConnector(limit=20, ssl=False)
                        session = aiohttp.ClientSession(timeout=timeout, connector=connector)
                        self.graphql_fuzzer.session = session
                        return await self.graphql_fuzzer.scanner(endpoint, params_endpoint)
                    
                    taches.append(_init_graphql_session())
                else:
                    taches.append(self.graphql_fuzzer.scanner(endpoint, params_endpoint))
            
            # ⭐ NOUVEAUX MODULES v4.3 (combler les lacunes critiques)
            if modules_vides or 'ssrf' in self.modules_cibles or 'all' in self.modules_cibles:
                taches.append(self.ssrf_detector.detecter(endpoint, params_endpoint))
            
            if modules_vides or 'ssti' in self.modules_cibles or 'all' in self.modules_cibles:
                taches.append(self.ssti_scanner.scanner(endpoint, params_endpoint))
            
            if modules_vides or 'nosql' in self.modules_cibles or 'all' in self.modules_cibles:
                taches.append(self.nosql_scanner.scanner(endpoint, params_endpoint))
            
            if modules_vides or 'deserialization' in self.modules_cibles or 'all' in self.modules_cibles:
                taches.append(self.deserialization_detector.detecter(endpoint, params_endpoint))
            
            # ⭐ NOUVEAUX MODULES v4.4 (couverture complète 100%)
            if modules_vides or 'prototype_pollution' in self.modules_cibles or 'all' in self.modules_cibles:
                taches.append(self.prototype_pollution_detector.detecter(endpoint, params_endpoint))
            
            if modules_vides or 'ldap' in self.modules_cibles or 'all' in self.modules_cibles:
                taches.append(self.ldap_injection_detector.detecter(endpoint, params_endpoint))
            
            if modules_vides or 'open_redirect' in self.modules_cibles or 'all' in self.modules_cibles:
                taches.append(self.open_redirect_detector.detecter(endpoint, params_endpoint))
            
            if modules_vides or 'websocket' in self.modules_cibles or 'all' in self.modules_cibles:
                taches.append(self.websocket_detector.detecter(endpoint))
            
            if modules_vides or 'race_conditions' in self.modules_cibles or 'all' in self.modules_cibles:
                taches.append(self.race_conditions_detector.detecter(endpoint, params_endpoint))
            
            if modules_vides or 'business_logic' in self.modules_cibles or 'all' in self.modules_cibles:
                taches.append(self.business_logic_detector.detecter(endpoint, params_endpoint))
        
        # Scans globaux (avec filtrage par modules)
        modules_vides = not self.modules_cibles or len(self.modules_cibles) == 0
        
        if modules_vides or 'cors' in self.modules_cibles or 'all' in self.modules_cibles:
            taches.append(self.analyseur_cors.analyser(url_cible))
        
        if modules_vides or 'headers' in self.modules_cibles or 'all' in self.modules_cibles:
            taches.append(self.analyseur_headers.analyser(url_cible))
        
        if modules_vides or 'cve' in self.modules_cibles or 'all' in self.modules_cibles:
            taches.append(self.scanner_cve.scanner(url_cible, donnees_recon.technologies))
        
        if modules_vides or 'config' in self.modules_cibles or 'all' in self.modules_cibles:
            taches.append(self.analyseur_config.analyser(url_cible, donnees_recon.technologies))
        
        # ⭐ NOUVEAU v4.4: Clickjacking (scan global)
        if modules_vides or 'clickjacking' in self.modules_cibles or 'all' in self.modules_cibles:
            taches.append(self.clickjacking_detector.detecter(url_cible))
        
        if modules_vides or 'auth' in self.modules_cibles or 'all' in self.modules_cibles:
            taches.append(self.testeur_auth.tester(url_cible))
        
        if modules_vides or 'csrf' in self.modules_cibles or 'all' in self.modules_cibles:
            taches.append(self.detecteur_csrf.detecter(url_cible))
        
        # Exécuter tous les scans en parallèle avec limite de concurrence
        semaphore = asyncio.Semaphore(self.config.get('threads', 10))
        
        async def scanner_avec_limite(tache):
            # ⭐ NOUVEAU: Vérifier la pause avant de lancer la tâche
            await self.pause_event.wait()
            
            async with semaphore:
                try:
                    # ⭐ OPTIMISATION: Timeout par module pour éviter les blocages
                    # 5 minutes max par module (sauf si c'est un scan long connu)
                    return await asyncio.wait_for(tache, timeout=300)
                except asyncio.TimeoutError:
                    logger.warning("⚠️  Timeout module (5min) - passage au suivant")
                    return None
                except Exception as e:
                    logger.warning(f"Erreur dans un scanner: {str(e)}")
                    return None
        
        resultats = await asyncio.gather(
            *[scanner_avec_limite(t) for t in taches],
            return_exceptions=True
        )
        
        # Collecter toutes les vulnérabilités trouvées
        for resultat in resultats:
            if resultat and not isinstance(resultat, Exception):
                if isinstance(resultat, list):
                    vulnerabilites.extend(resultat)
                    # ⭐ NOUVEAU: Notifier le dashboard pour chaque vulnérabilité trouvée
                    if self.callback_vulnerabilite:
                        for v in resultat:
                            self.callback_vulnerabilite(v)
                else:
                    vulnerabilites.append(resultat)
                    # ⭐ NOUVEAU: Notifier le dashboard
                    if self.callback_vulnerabilite:
                        self.callback_vulnerabilite(resultat)
        
        self.stats['temps_par_phase']['detection'] = time.time() - debut
        self.stats['vulnerabilites_trouvees'] = len(vulnerabilites)
        
        logger.info(f"Détection terminée: {len(vulnerabilites)} vulnérabilités potentielles")

        return vulnerabilites

    async def _filtrer_endpoints_existants(self, urls: List[str]) -> List[str]:
        """
        Filtre les URLs pour ne garder que celles qui existent réellement
        Évite les faux positifs sur des pages qui n'existent pas

        Version améliorée pour les apps modernes (React, SPA, etc.)
        """
        urls_existantes = []
        url_base = urls[0] if urls else ""  # URL principale pour référence

        # Récupérer le contenu de la page principale pour comparer
        contenu_principal = ""
        try:
            async with aiohttp.ClientSession(cookies=self.auth_config.get('cookies'), headers=self.auth_config.get('headers')) as session:
                async with session.get(url_base, timeout=aiohttp.ClientTimeout(total=5)) as response:
                    if response.status == 200:
                        contenu_principal = await response.text()
        except:
            pass

        async with aiohttp.ClientSession(cookies=self.auth_config.get('cookies'), headers=self.auth_config.get('headers')) as session:
            for url in urls:
                # L'URL principale existe toujours
                if url == url_base:
                    urls_existantes.append(url)
                    logger.debug(f"✅ URL principale conservée: {url}")
                    continue

                try:
                    async with session.get(
                        url,
                        timeout=aiohttp.ClientTimeout(total=3),
                        allow_redirects=False
                    ) as response:
                        if response.status == 200:
                            contenu = await response.text()
                            contenu_lower = contenu.lower()

                            # ⭐ FILTRE AMÉLIORÉ : Moins strict pour accepter plus de pages
                            # 1. Détection des pages d'erreur classiques (patterns plus spécifiques)
                            indicateurs_erreur_stricts = [
                                '404 not found', 'page not found', 'error 404',
                                'file not found', 'does not exist',
                                'cannot find the page', 'the page you requested',
                                'page unavailable', 'resource not found',
                                'document not found', 'requested url was not found'
                            ]
                            
                            # Ne pas rejeter si juste "error" ou "not found" (trop générique)
                            contient_erreur = any(
                                indicateur in contenu_lower 
                                for indicateur in indicateurs_erreur_stricts
                            ) and (
                                '404' in contenu_lower or 
                                'not found' in contenu_lower or
                                len(contenu.strip()) < 200  # Contenu très court = probable erreur
                            )

                            # 2. Détection des Single Page Applications (SPA)
                            # Si le contenu est identique à la page principale, c'est probablement du routing côté client
                            contenu_identique_principal = (
                                contenu_principal and
                                contenu.strip() == contenu_principal.strip() and
                                len(contenu.strip()) > 500  # Contenu substantiel
                            )

                            # 3. Vérifier si c'est une vraie API ou page
                            # Les vraies pages/API ont généralement du contenu différent ou spécifique
                            est_api_endpoint = any(pattern in url.lower() for pattern in [
                                '/api/', '/rest/', '/graphql', '/v1/', '/v2/', '/v3/',
                                '.json', '.xml', '/data/', '/endpoint'
                            ])

                            # 4. Contenu trop court = probablement une erreur (seuil plus bas)
                            contenu_trop_court = len(contenu.strip()) < 30  # Réduit de 50 à 30

                            # ⭐ LOGIQUE AMÉLIORÉE : Accepter plus de pages
                            # Accepter si :
                            # - Pas d'erreur claire OU
                            # - Contenu différent de la page principale OU
                            # - C'est une API endpoint OU
                            # - Contenu substantiel (>30 caractères)
                            
                            if contient_erreur and len(contenu.strip()) < 200:
                                logger.debug(f"❌ Page d'erreur exclue: {url}")
                            elif contenu_identique_principal and not est_api_endpoint and len(contenu.strip()) > 1000:
                                # Seulement exclure si contenu identique ET très long (SPA probable)
                                logger.debug(f"❌ SPA routing exclu: {url}")
                            elif contenu_trop_court:
                                logger.debug(f"❌ Contenu trop court exclu: {url}")
                            else:
                                urls_existantes.append(url)
                                logger.debug(f"✅ URL existante validée: {url}")

                        elif response.status in [301, 302, 303, 307, 308]:
                            # ⭐ NOUVEAU: Accepter les redirections (peuvent être vulnérables)
                            urls_existantes.append(url)
                            logger.debug(f"✅ Redirection acceptée: {url} (status {response.status})")
                        elif response.status == 403:
                            # ⭐ NOUVEAU: Accepter les 403 (peuvent indiquer des endpoints existants protégés)
                            urls_existantes.append(url)
                            logger.debug(f"✅ 403 accepté (endpoint protégé): {url}")
                        else:
                            logger.debug(f"❌ URL non accessible ({response.status}): {url}")

                except Exception as e:
                    logger.debug(f"❌ Erreur vérification {url}: {str(e)}")

        # Log final
        logger.info(f"📊 Filtrage terminé: {len(urls)} URLs testées → {len(urls_existantes)} URLs valides")
        return urls_existantes

    def _get_pages_connues(self, url_base: str) -> List[str]:
        """
        Retourne une liste de pages connues à tester pour les sites vulnérables courants
        (testphp.vulnweb.com, etc.)
        
        Args:
            url_base: URL de base du site
            
        Returns:
            List[str]: Liste de chemins relatifs à tester
        """
        # Pages communes sur testphp.vulnweb.com et sites similaires
        pages_communes = [
            # Pages principales avec paramètres
            'artists.php',
            'listproducts.php',
            'listart.php',
            'showproduct.php',
            'product.php',
            'categories.php',
            'category.php',
            'search.php',
            'comment.php',
            'comments.php',
            'guestbook.php',
            'contact.php',
            'gallery.php',
            'pictures.php',
            'showimage.php',
            # Upload
            'upload.php',
            'fileupload.php',
            'upload_file.php',
            # Auth
            'login.php',
            'register.php',
            'signup.php',
            'signin.php',
            # Admin
            'admin.php',
            'admin',
            'dashboard.php',
            # API
            'api.php',
            'api',
            # Autres
            'user.php',
            'users.php',
            'profile.php',
            'account.php',
        ]
        
        return pages_communes

    async def phase_validation(
        self, vulnerabilites: List[Vulnerabilite]
    ) -> List[Vulnerabilite]:
        """
        Phase de validation : éliminer les faux positifs
        
        Args:
            vulnerabilites: Liste des vulnérabilités à valider
            
        Returns:
            List[Vulnerabilite]: Vulnérabilités validées
        """
        debut = time.time()
        vulns_validees = []
        faux_positifs = 0
        
        # Validation avec tests d'exploitation réels (toujours activée)
        logger.info(f"🔍 Validation de {len(vulnerabilites)} vulnérabilités avec tests d'exploitation...")
        
        taches_validation = [
            self.validateur.valider(vuln) for vuln in vulnerabilites
        ]
        
        resultats = await asyncio.gather(*taches_validation, return_exceptions=True)
        
        for vuln, est_valide in zip(vulnerabilites, resultats):
            if not isinstance(est_valide, Exception) and est_valide:
                vuln.validee = True
                vulns_validees.append(vuln)
                logger.success(f"✅ {vuln.type} confirmée comme exploitable")
            else:
                faux_positifs += 1
                logger.warning(f"❌ {vuln.type} rejetée (faux positif ou non exploitable)")
        
        self.stats['temps_par_phase']['validation'] = time.time() - debut
        self.stats['faux_positifs_elimines'] = faux_positifs
        
        # Dédupliquer les vulnérabilités identiques
        vulns_uniques = self._dedupliquer_vulnerabilites(vulns_validees)
        nb_duplications = len(vulns_validees) - len(vulns_uniques)
        
        if nb_duplications > 0:
            logger.info(f"🔄 {nb_duplications} duplication(s) éliminée(s)")
        
        logger.info(
            f"Validation terminée: {len(vulns_uniques)} confirmées, "
            f"{faux_positifs} faux positifs éliminés"
        )
        
        return vulns_uniques

    async def phase_generation_exploits(
        self, vulnerabilites: List[Vulnerabilite]
    ) -> None:
        """
        Phase de génération d'exploits avec l'IA
        
        Args:
            vulnerabilites: Liste des vulnérabilités validées
        """
        debut = time.time()
        
        taches = [
            self.generateur_exploits.generer(vuln) for vuln in vulnerabilites
        ]
        
        exploits = await asyncio.gather(*taches, return_exceptions=True)
        
        for vuln, exploit in zip(vulnerabilites, exploits):
            if exploit and not isinstance(exploit, Exception):
                vuln.exploit_disponible = True
                vuln.exploit_code = exploit
        
        self.stats['temps_par_phase']['generation_exploits'] = time.time() - debut
        logger.info("Exploits générés avec succès")

    async def phase_chaines_exploit(
        self, vulnerabilites: List[Vulnerabilite]
    ) -> List[Dict]:
        """
        Phase de construction de chaînes d'exploit
        
        Args:
            vulnerabilites: Liste des vulnérabilités
            
        Returns:
            List[Dict]: Chaînes d'exploit possibles
        """
        debut = time.time()
        
        chaines = await self.constructeur_chaines.construire_chaines(
            vulnerabilites
        )
        
        self.stats['temps_par_phase']['chaines_exploit'] = time.time() - debut
        logger.info(f"{len(chaines)} chaînes d'exploit identifiées")
        
        return chaines

    def calculer_score_risque_global(
        self, vulnerabilites: List[Vulnerabilite]
    ) -> float:
        """
        Calcule un score de risque global intelligent avec ML

        Args:
            vulnerabilites: Liste des vulnérabilités

        Returns:
            float: Score de risque entre 0 et 10
        """
        try:
            # Utiliser le système ML de scoring intelligent
            contexte = {
                'production': True,  # Par défaut on considère production
                'internet_facing': True
            }

            # Pour l'instant on n'a pas les anomalies, mais on peut les ajouter plus tard
            anomalies = []

            # Calculer le score avec ML
            resultats_scoring = self.scorer_risque.calculer_score_global(
                vulnerabilites,
                getattr(self, '_technologies_detectees', {}),
                contexte,
                anomalies
            )

            return resultats_scoring.get('score_global', 5.0)

        except Exception as e:
            logger.debug(f"Erreur scoring ML, fallback simple: {str(e)}")

            # Fallback vers le calcul simple en cas d'erreur
            if not vulnerabilites:
                return 0.0

            scores_severite = {
                'CRITIQUE': 10.0, 'ÉLEVÉ': 7.5, 'MOYEN': 5.0,
                'FAIBLE': 2.5, 'INFO': 0.5
            }

            score_total = sum(
                vuln.cvss_score or scores_severite.get(vuln.severite, 0)
                for vuln in vulnerabilites
            )

            score_moyen = score_total / len(vulnerabilites)

            # Bonus si beaucoup de vulnérabilités critiques
            critiques = sum(1 for v in vulnerabilites if v.severite == 'CRITIQUE')
            bonus = min(critiques * 0.5, 2.0)

            return min(score_moyen + bonus, 10.0)

    def _dedupliquer_vulnerabilites(self, vulnerabilites: List[Vulnerabilite]) -> List[Vulnerabilite]:
        """
        Élimine les vulnérabilités en double basées sur type + URL + paramètre
        
        Une même faille SQL avec 20 payloads différents = 1 seule vulnérabilité
        Pour les vulnérabilités FAIBLES/INFO (ex: headers manquants): grouper par type seulement
        
        Args:
            vulnerabilites: Liste des vulnérabilités
            
        Returns:
            List[Vulnerabilite]: Liste dédupliquée
        """
        from urllib.parse import urlparse, parse_qs
        
        vues = {}  # Dict pour garder la meilleure vulnérabilité par type+page
        params_par_vuln = {}  # ⭐ NOUVEAU: Collecter les paramètres affectés par type+page
        
        for vuln in vulnerabilites:
            # Extraire l'URL de base (sans query string)
            parsed = urlparse(vuln.url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            # ⭐ NOUVEAU: Clé = TYPE + PAGE (ignorer le paramètre pour grouper)
            # Exemple: "XSS:/search.php" regroupe tous les XSS de cette page
            cle = f"{vuln.type}:{base_url}"
            
            # Extraire le paramètre pour le comptage
            parametre = self._extraire_parametre_vulnerable(vuln)
            
            if cle not in vues:
                # Première occurrence de ce type sur cette page
                vues[cle] = vuln
                params_par_vuln[cle] = {parametre} if parametre != 'unknown' else set()
                logger.debug(f"✅ Nouvelle vulnérabilité: {vuln.type} sur {base_url}")
            else:
                # Ajouter le paramètre à la liste des paramètres affectés
                if parametre != 'unknown':
                    params_par_vuln[cle].add(parametre)
                
                # Garder la vulnérabilité avec le meilleur score CVSS ou la meilleure preuve
                vuln_existante = vues[cle]
                if vuln.cvss_score > vuln_existante.cvss_score:
                    vues[cle] = vuln
                elif self._est_meilleure_preuve(vuln, vuln_existante):
                    vues[cle] = vuln
                
                logger.debug(f"🔄 Groupé: {vuln.type} sur {base_url} (paramètre: {parametre})")
        
        # ⭐ NOUVEAU: Mettre à jour les descriptions avec le nombre de paramètres affectés
        for cle, vuln in vues.items():
            params = params_par_vuln.get(cle, set())
            if len(params) > 1:
                vuln.description = f"{vuln.description} (affecte {len(params)} paramètres: {', '.join(list(params)[:5])}{'...' if len(params) > 5 else ''})"
        
        vulns_uniques = list(vues.values())
        
        logger.info(f"📊 Déduplication: {len(vulnerabilites)} → {len(vulns_uniques)} vulnérabilités uniques")
        
        return vulns_uniques
    
    def _extraire_parametre_vulnerable(self, vuln: Vulnerabilite) -> str:
        """
        Extrait le nom du paramètre vulnérable depuis la description
        
        Args:
            vuln: Vulnérabilité
            
        Returns:
            str: Nom du paramètre ou 'unknown'
        """
        import re
        
        # Chercher "paramètre 'xxx'" dans la description
        match = re.search(r"paramètre\s+'([^']+)'", vuln.description, re.IGNORECASE)
        if match:
            return match.group(1)
        
        # Chercher "dans 'xxx'" dans la description
        match = re.search(r"dans\s+'([^']+)'", vuln.description, re.IGNORECASE)
        if match:
            return match.group(1)
        
        # Extraire depuis l'URL si possible
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(vuln.url)
        params = parse_qs(parsed.query)
        if params:
            # Retourner le premier paramètre
            return list(params.keys())[0]
        
        # Par défaut, utiliser le type + partie de l'URL pour différencier
        return parsed.path.split('/')[-1] or 'root'
    
    def _est_meilleure_preuve(self, nouvelle: Vulnerabilite, existante: Vulnerabilite) -> bool:
        """
        Détermine si une nouvelle vulnérabilité a une meilleure preuve que l'existante
        
        Args:
            nouvelle: Nouvelle vulnérabilité
            existante: Vulnérabilité existante
            
        Returns:
            bool: True si la nouvelle est meilleure
        """
        # Ordre de priorité pour les preuves SQL Injection
        priorites = {
            'UNION SELECT': 10,  # Le meilleur
            'réussie avec': 9,
            'colonnes': 8,
            'SQL syntax': 5,     # Erreur basique
            'error': 4,
            'syntax': 3,
            'database': 2,
        }
        
        score_nouvelle = 0
        score_existante = 0
        
        # Calculer le score de la nouvelle
        for mot_cle, points in priorites.items():
            if mot_cle.lower() in (nouvelle.preuve or '').lower():
                score_nouvelle = max(score_nouvelle, points)
            if mot_cle.lower() in (nouvelle.description or '').lower():
                score_nouvelle = max(score_nouvelle, points - 1)
        
        # Calculer le score de l'existante
        for mot_cle, points in priorites.items():
            if mot_cle.lower() in (existante.preuve or '').lower():
                score_existante = max(score_existante, points)
            if mot_cle.lower() in (existante.description or '').lower():
                score_existante = max(score_existante, points - 1)
        
        # La nouvelle est meilleure si elle a un score supérieur
        return score_nouvelle > score_existante

