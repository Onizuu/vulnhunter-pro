"""
GitHub Reconnaissance - OSINT via GitHub API
Recherche subdomains, credentials leakés, API keys dans repositories publics
"""

import re
import time
import requests
from typing import List, Dict, Optional, Set
from loguru import logger
from urllib.parse import urlparse
import random


class GitHubRecon:
    """
    Reconnaissance via GitHub API
    Découvre assets non documentés, credentials exposés, subdomains
    """
    
    def __init__(self, tokens: Optional[List[str]] = None):
        """
        Args:
            tokens: Liste de tokens GitHub pour rate limiting
                    Format: ['ghp_xxxxx', 'ghp_yyyyy']
        """
        self.tokens = tokens or []
        self.session = requests.Session()
        self.api_base = "https://api.github.com"
        
        if not self.tokens:
            logger.warning(
                "⚠️  Aucun token GitHub fourni - Rate limit: 60 req/h"
            )
        else:
            logger.info(f"✅ {len(self.tokens)} token(s) GitHub configurés")
    
    def _get_headers(self) -> Dict[str, str]:
        """Retourne headers avec token aléatoire"""
        headers = {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'VulnHunter-Pro/1.0'
        }
        
        if self.tokens:
            token = random.choice(self.tokens)
            headers['Authorization'] = f'token {token}'
        
        return headers
    
    def search_subdomains(
        self, 
        domain: str,
        max_pages: int = 5
    ) -> List[str]:
        """
        Recherche sous-domaines dans le code GitHub
        
        Args:
            domain: Domaine cible (ex: example.com)
            max_pages: Nombre max de pages à parcourir
            
        Returns:
            Liste de sous-domaines découverts
        """
        logger.info(f"🔍 GitHub: Recherche subdomains pour {domain}")
        
        subdomains = set()
        
        try:
            # Extraire le domaine principal
            import tldextract
            parsed = tldextract.extract(domain)
            main_domain = parsed.domain
            
            # Pattern de recherche
            search_query = f'"{main_domain}"'
            
            # Pattern regex pour matcher subdomains
            # Exemple: sub.example.com, api.example.co.uk
            pattern = re.compile(
                rf'([0-9a-z_\-\.]+\.({main_domain})([0-9a-z_\-\.]+)?\.([a-z]{{2,5}}))',
                re.IGNORECASE
            )
            
            for page in range(1, max_pages + 1):
                results = self._search_code(search_query, page)
                
                if not results or 'items' not in results:
                    break
                
                for item in results['items']:
                    # Récupérer le code source
                    raw_url = self._get_raw_url(item)
                    code = self._fetch_code(raw_url)
                    
                    if code:
                        # Extraire subdomains
                        matches = pattern.findall(code)
                        for match in matches:
                            subdomain = match[0].lower().strip()
                            if subdomain and len(subdomain) > 5:
                                subdomains.add(subdomain)
                
                # Rate limiting
                time.sleep(1)
            
            unique_subdomains = sorted(list(subdomains))
            
            logger.success(
                f"✅ GitHub: {len(unique_subdomains)} subdomains découverts"
            )
            
            return unique_subdomains
            
        except Exception as e:
            logger.error(f"❌ Erreur GitHub search subdomains: {str(e)}")
            return []
    
    def search_credentials(
        self, 
        domain: str,
        max_pages: int = 3
    ) -> List[Dict]:
        """
        Recherche credentials et secrets leakés
        
        Args:
            domain: Domaine cible
            max_pages: Nombre de pages à scanner
            
        Returns:
            Liste de credentials trouvés avec contexte
        """
        logger.info(f"🔐 GitHub: Recherche credentials pour {domain}")
        
        credentials = []
        
        # Patterns à rechercher
        patterns = {
            'API Keys': r'api[_-]?key[\"\']?\s*[:=]\s*[\"\']([a-zA-Z0-9_\-]{20,})',
            'Passwords': r'password[\"\']?\s*[:=]\s*[\"\']([^\"\'\s]{6,})',
            'Tokens': r'token[\"\']?\s*[:=]\s*[\"\']([a-zA-Z0-9_\-]{20,})',
            'AWS Keys': r'AKIA[0-9A-Z]{16}',
            'Private Keys': r'-----BEGIN (?:RSA |)PRIVATE KEY-----',
            'Database URLs': r'(?:mysql|postgres|mongodb):\/\/[^\s]+',
        }
        
        try:
            search_query = f'"{domain}" password OR api_key OR token'
            
            for page in range(1, max_pages + 1):
                results = self._search_code(search_query, page)
                
                if not results or 'items' not in results:
                    break
                
                for item in results['items']:
                    raw_url = self._get_raw_url(item)
                    code = self._fetch_code(raw_url)
                    
                    if code:
                        # Chercher patterns
                        for cred_type, pattern in patterns.items():
                            matches = re.findall(pattern, code, re.IGNORECASE)
                            
                            for match in matches:
                                credentials.append({
                                    'type': cred_type,
                                    'value': match if isinstance(match, str) else match[0],
                                    'source': item.get('html_url', ''),
                                    'repository': item.get('repository', {}).get('full_name', ''),
                                    'path': item.get('path', '')
                                })
                
                time.sleep(1)
            
            if credentials:
                logger.warning(
                    f"⚠️  ATTENTION: {len(credentials)} credentials trouvés sur GitHub!"
                )
            else:
                logger.info("✅ Aucun credential exposé trouvé")
            
            return credentials
            
        except Exception as e:
            logger.error(f"❌ Erreur GitHub search credentials: {str(e)}")
            return []
    
    def search_api_keys(self, domain: str) -> List[Dict]:
        """
        Recherche spécifique d'API keys exposées
        
        Args:
            domain: Domaine cible
            
        Returns:
            Liste d'API keys trouvées
        """
        logger.info(f"🔑 GitHub: Recherche API keys pour {domain}")
        
        api_keys = []
        
        # Patterns API keys courants
        key_patterns = {
            'Google API': r'AIza[0-9A-Za-z\-_]{35}',
            'Stripe': r'sk_live_[0-9a-zA-Z]{24}',
            'AWS Access Key': r'AKIA[0-9A-Z]{16}',
            'Slack Token': r'xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}',
            'GitHub Token': r'ghp_[a-zA-Z0-9]{36}',
            'Twilio': r'SK[a-z0-9]{32}',
        }
        
        try:
            for key_type, pattern in key_patterns.items():
                search_query = f'"{domain}" {key_type}'
                results = self._search_code(search_query, page=1)
                
                if results and 'items' in results:
                    for item in results['items']:
                        raw_url = self._get_raw_url(item)
                        code = self._fetch_code(raw_url)
                        
                        if code:
                            matches = re.findall(pattern, code)
                            for match in matches:
                                api_keys.append({
                                    'type': key_type,
                                    'key': match,
                                    'source': item.get('html_url', ''),
                                    'repository': item.get('repository', {}).get('full_name', '')
                                })
                
                time.sleep(1)
            
            if api_keys:
                logger.critical(
                    f"🚨 CRITIQUE: {len(api_keys)} API keys exposées!"
                )
            
            return api_keys
            
        except Exception as e:
            logger.error(f"❌ Erreur search API keys: {str(e)}")
            return []
    
    def _search_code(self, query: str, page: int = 1) -> Optional[Dict]:
        """
        Recherche dans le code GitHub
        
        Args:
            query: Requête de recherche
            page: Numéro de page
            
        Returns:
            Résultats JSON de l'API
        """
        try:
            url = f"{self.api_base}/search/code"
            params = {
                's': 'indexed',
                'type': 'Code',
                'o': 'desc',
                'q': query,
                'page': page
            }
            
            response = self.session.get(
                url,
                headers=self._get_headers(),
                params=params,
                timeout=10
            )
            
            # Vérifier rate limit
            if response.status_code == 403:
                logger.warning("⚠️  Rate limit GitHub atteint")
                return None
            
            response.raise_for_status()
            return response.json()
            
        except Exception as e:
            logger.debug(f"Erreur GitHub API: {str(e)}")
            return None
    
    def _get_raw_url(self, search_result: Dict) -> str:
        """
        Convertit URL GitHub en raw URL
        
        Args:
            search_result: Résultat de recherche GitHub
            
        Returns:
            URL raw du fichier
        """
        html_url = search_result.get('html_url', '')
        raw_url = html_url.replace(
            'https://github.com/', 
            'https://raw.githubusercontent.com/'
        )
        raw_url = raw_url.replace('/blob/', '/')
        return raw_url
    
    def _fetch_code(self, url: str) -> Optional[str]:
        """
        Récupère le code source d'une URL
        
        Args:
            url: URL du fichier
            
        Returns:
            Contenu du fichier
        """
        try:
            response = self.session.get(url, timeout=5)
            response.raise_for_status()
            return response.text
        except Exception:
            return None
    
    def get_rate_limit_status(self) -> Dict:
        """
        Vérifie le statut du rate limit
        
        Returns:
            Info sur remaining requests
        """
        try:
            url = f"{self.api_base}/rate_limit"
            response = self.session.get(
                url,
                headers=self._get_headers(),
                timeout=5
            )
            
            data = response.json()
            core = data.get('resources', {}).get('core', {})
            
            logger.info(
                f"📊 GitHub Rate Limit: {core.get('remaining', 0)}/{core.get('limit', 0)}"
            )
            
            return core
            
        except Exception as e:
            logger.error(f"Erreur check rate limit: {str(e)}")
            return {}
