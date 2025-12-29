"""
NIST CVE Database Searcher
Recherche CVEs basée sur versions de logiciels détectés
Inspiré d'AutoPWN-Suite avec améliorations IA
"""

import requests
import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from loguru import logger
from datetime import datetime


@dataclass
class CVEVulnerability:
    """Représente une CVE trouvée dans NIST database"""
    cve_id: str
    title: str
    description: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    cvss_score: float
    exploitability_score: float
    details_url: str
    published_date: Optional[datetime] = None
    references: List[str] = field(default_factory=list)
    
    def __str__(self) -> str:
        return (
            f"CVE: {self.cve_id}\n"
            f"Title: {self.title}\n"
            f"Severity: {self.severity} (CVSS: {self.cvss_score})\n"
            f"Exploitability: {self.exploitability_score}\n"
            f"Description: {self.description[:200]}...\n"
            f"Details: {self.details_url}"
        )


class NISTCVESearcher:
    """
    Client pour rechercher CVEs dans la base NIST
    Utilise l'API NVD 2.0
    """
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Args:
            api_key: Clé API NIST (optionnel)
                    Sans clé: 5 requêtes max toutes les 30s
                    Avec clé: 50 requêtes max toutes les 30s
        """
        self.api_key = api_key
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.cache = {}  # Cache pour éviter requêtes dupliquées
        self.last_request_time = 0
        
        if self.api_key:
            self.rate_limit_delay = 0.6  # 0.6s entre requêtes avec API key
            logger.info("✅ NIST API key configurée - Rate limit: 50 req/30s")
        else:
            self.rate_limit_delay = 6.0  # 6s entre requêtes sans API key
            logger.warning(
                "⚠️  Pas d'API key NIST - Rate limit: 5 req/30s. "
                "Obtenir une clé: https://nvd.nist.gov/developers/request-an-api-key"
            )
    
    def _respect_rate_limit(self):
        """Respecte les rate limits de l'API NIST"""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.rate_limit_delay:
            sleep_time = self.rate_limit_delay - elapsed
            time.sleep(sleep_time)
        self.last_request_time = time.time()
    
    def search_cve(
        self, 
        keyword: str,
        max_results: int = 20
    ) -> List[CVEVulnerability]:
        """
        Recherche CVEs par keyword
        
        Args:
            keyword: Keyword de recherche (ex: "nginx 1.18", "OpenSSH 8.2")
            max_results: Nombre max de résultats
            
        Returns:
            Liste de CVEVulnerability trouvées
        """
        # Vérifier cache
        cache_key = f"{keyword}:{max_results}"
        if cache_key in self.cache:
            logger.debug(f"🎯 Cache hit pour: {keyword}")
            return self.cache[cache_key]
        
        logger.info(f"🔍 NIST: Recherche CVEs pour '{keyword}'...")
        
        # Respecter rate limit
        self._respect_rate_limit()
        
        # Préparer requête
        headers = {}
        if self.api_key:
            headers['apiKey'] = self.api_key
        
        params = {
            'keywordSearch': keyword,
            'resultsPerPage': max_results
        }
        
        try:
            response = requests.get(
                self.base_url,
                params=params,
                headers=headers,
                timeout=30
            )
            
            # Gérer rate limiting
            if response.status_code == 403:
                logger.error(
                    "❌ Rate limit NIST atteint. "
                    "Attendez 30s ou configurez une API key."
                )
                return []
            
            response.raise_for_status()
            data = response.json()
            
        except requests.RequestException as e:
            logger.error(f"❌ Erreur requête NIST: {str(e)}")
            return []
        
        # Parser résultats
        vulnerabilities = self._parse_vulnerabilities(data, keyword)
        
        # Cache results
        self.cache[cache_key] = vulnerabilities
        
        if vulnerabilities:
            logger.success(
                f"✅ {len(vulnerabilities)} CVEs trouvées pour {keyword}"
            )
        else:
            logger.info(f"ℹ️  Aucune CVE trouvée pour {keyword}")
        
        return vulnerabilities
    
    def _parse_vulnerabilities(
        self, 
        data: Dict, 
        keyword: str
    ) -> List[CVEVulnerability]:
        """
        Parse la réponse JSON de NIST
        
        Args:
            data: Réponse JSON de l'API
            keyword: Keyword recherché
            
        Returns:
            Liste de CVEVulnerability
        """
        vulnerabilities = []
        
        if not data or 'vulnerabilities' not in data:
            return []
        
        for vuln_item in data.get('vulnerabilities', []):
            try:
                cve = vuln_item.get('cve', {})
                
                # Extraire ID
                cve_id = cve.get('id', 'UNKNOWN')
                
                # Extraire description
                descriptions = cve.get('descriptions', [])
                description = ""
                if descriptions:
                    description = descriptions[0].get('value', '')
                
                # Extraire métriques CVSS
                metrics = cve.get('metrics', {})
                severity, cvss_score, exploitability = self._extract_metrics(metrics)
                
                # Extraire date publication
                published = cve.get('published')
                published_date = None
                if published:
                    try:
                        published_date = datetime.fromisoformat(
                            published.replace('Z', '+00:00')
                        )
                    except:
                        pass
                
                # Extraire références
                references = []
                refs = cve.get('references', [])
                for ref in refs[:5]:  # Limiter à 5
                    url = ref.get('url', '')
                    if url:
                        references.append(url)
                
                # Créer URL détails
                details_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                
                # Créer objet CVE
                vuln_obj = CVEVulnerability(
                    cve_id=cve_id,
                    title=keyword,  # Utiliser keyword comme titre
                    description=description,
                    severity=severity,
                    cvss_score=cvss_score,
                    exploitability_score=exploitability,
                    details_url=details_url,
                    published_date=published_date,
                    references=references
                )
                
                vulnerabilities.append(vuln_obj)
                
            except Exception as e:
                logger.debug(f"Erreur parsing CVE: {str(e)}")
                continue
        
        # Trier par exploitabilité descendante
        vulnerabilities.sort(
            key=lambda x: x.exploitability_score,
            reverse=True
        )
        
        return vulnerabilities
    
    def _extract_metrics(self, metrics: Dict) -> tuple:
        """
        Extrait métriques CVSS des données
        
        Args:
            metrics: Dict contenant cvssMetricV31, cvssMetricV2, etc.
            
        Returns:
            (severity, cvss_score, exploitability_score)
        """
        severity = "UNKNOWN"
        cvss_score = 0.0
        exploitability = 0.0
        
        if not metrics:
            return severity, cvss_score, exploitability
        
        # Priorité V3.1 > V3.0 > V2
        metric_types = sorted(metrics.keys(), reverse=True)
        
        for metric_type in metric_types:
            metric_data = metrics[metric_type]
            if not metric_data or not isinstance(metric_data, list):
                continue
            
            first_metric = metric_data[0]
            
            # Extraire exploitabilité si pas déjà trouvée
            if exploitability == 0.0:
                exploitability = first_metric.get('exploitabilityScore', 0.0)
            
            # Extraire CVSS et sévérité
            cvss_data = first_metric.get('cvssData', {})
            if cvss_score == 0.0:
                cvss_score = cvss_data.get('baseScore', 0.0)
            if severity == "UNKNOWN":
                severity = cvss_data.get('baseSeverity', 'UNKNOWN')
            
            # Si tout trouvé, on peut sortir
            if exploitability > 0 and cvss_score > 0 and severity != "UNKNOWN":
                break
        
        return severity, cvss_score, exploitability
    
    def search_multiple(
        self, 
        technologies: Dict[str, str]
    ) -> Dict[str, List[CVEVulnerability]]:
        """
        Recherche CVEs pour plusieurs technologies
        
        Args:
            technologies: Dict {nom_tech: version}
                         Ex: {"nginx": "1.18.0", "OpenSSH": "8.2"}
        
        Returns:
            Dict {keyword: [CVEs]}
        """
        results = {}
        
        logger.info(f"🔍 Recherche CVEs pour {len(technologies)} technologies")
        
        for tech_name, version in technologies.items():
            keyword = f"{tech_name} {version}"
            cves = self.search_cve(keyword)
            
            if cves:
                results[keyword] = cves
        
        total_cves = sum(len(cves) for cves in results.values())
        logger.success(f"✅ Total: {total_cves} CVEs trouvées")
        
        return results
    
    def get_critical_cves(
        self,
        cves: List[CVEVulnerability],
        min_cvss: float = 7.0,
        min_exploitability: float = 0.0
    ) -> List[CVEVulnerability]:
        """
        Filtre les CVEs critiques
        
        Args:
            cves: Liste de CVEs
            min_cvss: Score CVSS minimum
            min_exploitability: Score exploitabilité minimum
            
        Returns:
            CVEs filtrées
        """
        critical = [
            cve for cve in cves
            if cve.cvss_score >= min_cvss 
            and cve.exploitability_score >= min_exploitability
        ]
        
        logger.warning(
            f"🚨 {len(critical)}/{len(cves)} CVEs critiques "
            f"(CVSS≥{min_cvss}, Exploit≥{min_exploitability})"
        )
        
        return critical
