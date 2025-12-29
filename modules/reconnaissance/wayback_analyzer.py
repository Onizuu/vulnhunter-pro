"""
Wayback Machine Analyzer - Reconnaissance Passive
Exploite les archives Wayback Machine pour découvrir URLs et endpoints cachés
"""

import requests
import re
from typing import List, Dict, Set, Optional
from loguru import logger
from urllib.parse import urlparse, urljoin
from collections import defaultdict


class WaybackAnalyzer:
    """
    Analyseur Wayback Machine pour reconnaissance passive
    Découvre URLs historiques, robots.txt anciens, endpoints oubliés
    """
    
    def __init__(self):
        self.base_url = "http://web.archive.org/cdx/search/cdx"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'VulnHunter-Pro/1.0 (Security Research)'
        })
    
    def wayback_urls(
        self, 
        domain: str, 
        include_subdomains: bool = False,
        limit: int = 1000
    ) -> List[str]:
        """
        Récupère les URLs historiques depuis Wayback Machine
        
        Args:
            domain: Domaine cible (ex: example.com)
            include_subdomains: Inclure les sous-domaines
            limit: Nombre max d'URLs à retourner
            
        Returns:
            Liste d'URLs uniques découvertes
        """
        try:
            logger.info(f"🔍 Wayback Machine: Recherche URLs pour {domain}")
            
            # Construire la requête CDX
            if include_subdomains:
                url_pattern = f"*.{domain}/*"
            else:
                url_pattern = f"{domain}/*"
            
            params = {
                'url': url_pattern,
                'output': 'json',
                'fl': 'original',
                'collapse': 'urlkey',
                'limit': limit
            }
            
            response = self.session.get(
                self.base_url,
                params=params,
                timeout=30
            )
            response.raise_for_status()
            
            # Parser les résultats JSON
            results = response.json()
            
            if not results or len(results) <= 1:
                logger.warning(f"Aucune URL trouvée dans Wayback pour {domain}")
                return []
            
            # Première ligne = headers, on la skip
            urls = [result[0] for result in results[1:]]
            unique_urls = list(set(urls))
            
            logger.success(
                f"✅ Wayback: {len(unique_urls)} URLs uniques découvertes"
            )
            
            return unique_urls
            
        except requests.RequestException as e:
            logger.error(f"❌ Erreur Wayback Machine: {str(e)}")
            return []
        except Exception as e:
            logger.error(f"❌ Erreur parsing Wayback: {str(e)}")
            return []
    
    def wayback_robots(self, domain: str) -> List[str]:
        """
        Analyse les fichiers robots.txt historiques
        Découvre chemins et endpoints anciens/oubliés
        
        Args:
            domain: Domaine cible
            
        Returns:
            Liste de chemins découverts dans robots.txt
        """
        try:
            logger.info(f"🤖 Wayback: Analyse robots.txt historiques pour {domain}")
            
            # Récupérer les snapshots de robots.txt
            params = {
                'url': f"{domain}/robots.txt",
                'output': 'json',
                'fl': 'timestamp,original',
                'filter': 'statuscode:200',
                'collapse': 'digest'
            }
            
            response = self.session.get(
                self.base_url,
                params=params,
                timeout=15
            )
            response.raise_for_status()
            
            snapshots = response.json()
            
            if len(snapshots) <= 1:
                logger.warning(f"Aucun robots.txt historique pour {domain}")
                return []
            
            # Skip la première ligne (headers)
            snapshots = snapshots[1:]
            
            logger.info(f"📸 {len(snapshots)} snapshots robots.txt trouvés")
            
            # Extraire les chemins de chaque snapshot
            all_paths = set()
            
            for snapshot in snapshots[:10]:  # Limiter à 10 pour performance
                timestamp, original_url = snapshot
                paths = self._extract_robots_paths(timestamp, original_url)
                all_paths.update(paths)
            
            unique_paths = sorted(list(all_paths))
            
            logger.success(
                f"✅ Wayback robots.txt: {len(unique_paths)} chemins découverts"
            )
            
            return unique_paths
            
        except Exception as e:
            logger.error(f"❌ Erreur analyse robots.txt: {str(e)}")
            return []
    
    def _extract_robots_paths(
        self, 
        timestamp: str, 
        original_url: str
    ) -> Set[str]:
        """
        Extrait les chemins d'un snapshot robots.txt
        
        Args:
            timestamp: Timestamp du snapshot
            original_url: URL originale
            
        Returns:
            Set de chemins trouvés
        """
        try:
            # Construire l'URL du snapshot
            wayback_url = f"https://web.archive.org/web/{timestamp}/{original_url}"
            
            response = self.session.get(wayback_url, timeout=10)
            robots_text = response.text
            
            # Vérifier que c'est bien un robots.txt
            if 'Disallow:' not in robots_text and 'Allow:' not in robots_text:
                return set()
            
            # Extraire tous les chemins
            paths = set()
            
            # Pattern pour Disallow et Allow
            patterns = [
                r'Disallow:\s*(/[^\s]*)',
                r'Allow:\s*(/[^\s]*)',
                r'Sitemap:\s*(.*)',
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, robots_text, re.IGNORECASE)
                paths.update(matches)
            
            return paths
            
        except Exception:
            return set()
    
    def find_hidden_endpoints(
        self, 
        domain: str,
        patterns: Optional[List[str]] = None
    ) -> Dict[str, List[str]]:
        """
        Recherche des endpoints spécifiques dans l'historique
        
        Args:
            domain: Domaine cible
            patterns: Patterns à rechercher (ex: ['.env', 'admin', 'api'])
            
        Returns:
            Dict avec patterns comme clés et URLs correspondantes
        """
        if patterns is None:
            patterns = [
                '.env',
                'admin',
                'api',
                'backup',
                'config',
                'test',
                'dev',
                'staging',
                '.git',
                '.sql',
                '.zip',
                '.tar',
                'phpinfo',
                'debug'
            ]
        
        logger.info(f"🔎 Recherche endpoints sensibles dans Wayback")
        
        results = defaultdict(list)
        
        # Récupérer toutes les URLs
        all_urls = self.wayback_urls(domain, include_subdomains=True, limit=5000)
        
        # Filtrer par patterns
        for url in all_urls:
            url_lower = url.lower()
            for pattern in patterns:
                if pattern.lower() in url_lower:
                    results[pattern].append(url)
        
        # Log résultats
        for pattern, urls in results.items():
            if urls:
                logger.warning(
                    f"⚠️  Pattern '{pattern}': {len(urls)} URLs trouvées"
                )
        
        return dict(results)
    
    def analyze_parameters(self, domain: str) -> Dict[str, int]:
        """
        Analyse les paramètres GET utilisés historiquement
        Utile pour découvrir des vecteurs d'injection
        
        Args:
            domain: Domaine cible
            
        Returns:
            Dict des paramètres avec leur fréquence
        """
        logger.info("📊 Analyse paramètres GET historiques")
        
        urls = self.wayback_urls(domain, include_subdomains=False, limit=2000)
        
        # Extraire tous les paramètres
        parameters = defaultdict(int)
        
        for url in urls:
            if '?' in url:
                query_string = url.split('?')[1]
                params = query_string.split('&')
                
                for param in params:
                    if '=' in param:
                        param_name = param.split('=')[0]
                        parameters[param_name] += 1
        
        # Trier par fréquence
        sorted_params = dict(
            sorted(
                parameters.items(),
                key=lambda x: x[1],
                reverse=True
            )
        )
        
        logger.success(
            f"✅ {len(sorted_params)} paramètres uniques découverts"
        )
        
        return sorted_params
