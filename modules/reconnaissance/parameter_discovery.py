"""
Module de découverte automatique de paramètres GET/POST
Analyse le HTML pour extraire tous les paramètres possibles à tester
"""

import asyncio
import re
from typing import List, Dict, Set, Tuple
from urllib.parse import urlparse, parse_qs, urljoin
from loguru import logger
import aiohttp
from bs4 import BeautifulSoup


class DecouvreurParametres:
    """
    Découvre automatiquement tous les paramètres GET/POST d'une page
    Analyse les formulaires, liens, et JavaScript pour trouver les paramètres
    """

    def __init__(self, auth_config=None):
        self.auth_config = auth_config or {}
        self.cookies = self.auth_config.get('cookies', {})
        self.headers = self.auth_config.get('headers', {})
        # ⭐ PHASE 1: Paramètres courants étendus (id, product_id, etc.)
        self.parametres_communs = [
            'id', 'user', 'username', 'email', 'password', 'pass', 'pwd',
            'q', 'search', 'query', 'keyword', 'term', 's',
            'page', 'p', 'offset', 'limit', 'start', 'count',
            'cat', 'category', 'cat_id', 'category_id',
            'product', 'product_id', 'item', 'item_id', 'article', 'article_id',
            'artist', 'author', 'user_id', 'uid',
            'file', 'filename', 'path', 'dir', 'folder',
            'action', 'cmd', 'command', 'exec', 'do',
            'name', 'title', 'desc', 'description', 'text', 'content', 'message',
            'comment', 'msg', 'feedback', 'review',
            'sort', 'order', 'orderby', 'order_by',
            'filter', 'f', 'where', 'condition',
            'lang', 'language', 'locale',
            'token', 'key', 'api_key', 'access_token',
            'redirect', 'return', 'return_url', 'callback',
            'date', 'time', 'timestamp', 'year', 'month', 'day'
        ]

    async def decouvrir_parametres(self, url: str) -> Dict[str, List[str]]:
        """
        Découvre tous les paramètres possibles pour une URL
        
        Args:
            url: URL à analyser
            
        Returns:
            Dict avec 'get' et 'post' contenant les listes de paramètres
        """
        resultats = {
            'get': set(),
            'post': set(),
            'urls_avec_params': []  # URLs trouvées avec paramètres
        }
        
        try:
            async with aiohttp.ClientSession(cookies=self.cookies, headers=self.headers) as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=10),
                    allow_redirects=True
                ) as response:
                    if response.status != 200:
                        logger.debug(f"Page non accessible ({response.status}): {url}")
                        return self._resultat_par_defaut()
                    
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')
                    
                    # 1. Extraire les paramètres de l'URL actuelle
                    parsed = urlparse(url)
                    params_existants = parse_qs(parsed.query)
                    resultats['get'].update(params_existants.keys())
                    
                    # 2. Analyser les formulaires (POST)
                    formulaires = soup.find_all('form')
                    for form in formulaires:
                        params_form = self._extraire_params_formulaire(form, url)
                        if form.get('method', 'GET').upper() == 'POST':
                            resultats['post'].update(params_form)
                        else:
                            resultats['get'].update(params_form)
                    
                    # 3. ⭐ PHASE 1: Analyser les liens avec paramètres (GET) - amélioré
                    liens = soup.find_all('a', href=True)
                    for lien in liens:
                        href = lien.get('href')
                        if href:
                            url_complete = urljoin(url, href)
                            params_liens = self._extraire_params_url(url_complete)
                            resultats['get'].update(params_liens)
                            if params_liens:
                                resultats['urls_avec_params'].append(url_complete)
                            
                            # ⭐ NOUVEAU: Extraire aussi depuis le texte du lien (ex: "showproduct.php?id=123")
                            if '?' in href or '&' in href:
                                # Parser directement depuis le href
                                params_directs = self._extraire_params_url(href)
                                resultats['get'].update(params_directs)
                    
                    # 4. ⭐ PHASE 1: Analyser les inputs dans les formulaires - amélioré
                    inputs = soup.find_all(['input', 'select', 'textarea'])
                    for input_elem in inputs:
                        name = input_elem.get('name')
                        if name:
                            method = input_elem.find_parent('form')
                            if method and method.get('method', 'GET').upper() == 'POST':
                                resultats['post'].add(name)
                            else:
                                resultats['get'].add(name)
                        
                        # ⭐ NOUVEAU: Extraire aussi depuis les inputs cachés (type="hidden")
                        if input_elem.get('type') == 'hidden':
                            value = input_elem.get('value', '')
                            # Si la valeur ressemble à un ID, ajouter 'id' aux paramètres
                            if value.isdigit() or 'id' in name.lower():
                                resultats['get'].add('id')
                                resultats['get'].add(name)
                    
                    # 5. ⭐ PHASE 1: Analyser JavaScript pour trouver des paramètres dynamiques - amélioré
                    scripts = soup.find_all('script')
                    for script in scripts:
                        if script.string:
                            params_js = self._extraire_params_javascript(script.string)
                            resultats['get'].update(params_js)
                        
                        # ⭐ NOUVEAU: Analyser aussi les scripts inline et externes
                        if script.get('src'):
                            # Analyser l'URL du script externe
                            script_url = urljoin(url, script.get('src'))
                            params_script = self._extraire_params_url(script_url)
                            resultats['get'].update(params_script)
                    
                    # 6. ⭐ PHASE 1: Ajouter les paramètres courants (même si non trouvés) - amélioré
                    # Mais seulement pour les pages qui semblent dynamiques
                    if self._page_semble_dynamique(html, url):
                        resultats['get'].update(self.parametres_communs[:30])  # ⭐ Augmenté de 20 à 30
                    
                    # ⭐ NOUVEAU: Ajouter des paramètres spécifiques selon le nom de la page
                    url_lower = url.lower()
                    if 'showproduct' in url_lower or 'product' in url_lower:
                        resultats['get'].add('id')
                        resultats['get'].add('product_id')
                        resultats['get'].add('item_id')
                    if 'listart' in url_lower or 'artist' in url_lower:
                        resultats['get'].add('artist')
                        resultats['get'].add('id')
                    if 'listproduct' in url_lower:
                        resultats['get'].add('cat')
                        resultats['get'].add('category')
                        resultats['get'].add('id')
                    
                    logger.debug(
                        f"🔍 Paramètres découverts pour {url}: "
                        f"{len(resultats['get'])} GET, {len(resultats['post'])} POST"
                    )
                    
        except Exception as e:
            logger.debug(f"Erreur découverte paramètres {url}: {str(e)}")
        
        # ⭐ PHASE 1: Convertir les sets en listes et limiter - augmenté
        return {
            'get': list(resultats['get'])[:50],  # ⭐ Augmenté de 30 à 50 paramètres GET
            'post': list(resultats['post'])[:30],  # ⭐ Augmenté de 20 à 30 paramètres POST
            'urls_avec_params': resultats['urls_avec_params'][:15]  # ⭐ Augmenté de 10 à 15 URLs supplémentaires
        }

    def _extraire_params_formulaire(self, form, base_url: str) -> Set[str]:
        """Extrait les paramètres d'un formulaire"""
        params = set()
        
        # Action du formulaire peut contenir des paramètres
        action = form.get('action', '')
        if action:
            url_complete = urljoin(base_url, action)
            params.update(self._extraire_params_url(url_complete))
        
        # Tous les inputs, selects, textareas
        for elem in form.find_all(['input', 'select', 'textarea']):
            name = elem.get('name')
            if name:
                params.add(name)
        
        return params

    def _extraire_params_url(self, url: str) -> Set[str]:
        """Extrait les paramètres d'une URL"""
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            return set(params.keys())
        except:
            return set()

    def _extraire_params_javascript(self, code_js: str) -> Set[str]:
        """⭐ PHASE 1: Extrait les paramètres potentiels depuis le JavaScript - amélioré"""
        params = set()
        
        # Patterns communs: ?param=, &param=, ['param'], ["param"]
        patterns = [
            r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)=',
            r"['\"]([a-zA-Z_][a-zA-Z0-9_]*)['\"]\s*[:=]",
            r'getParameter\(["\']([^"\']+)["\']\)',
            r'get\(["\']([^"\']+)["\']\)',
            r'params\[["\']([^"\']+)["\']\]',
            # ⭐ NOUVEAU: Patterns supplémentaires
            r'window\.location\.[\w.]+["\']([^"\']+)["\']',  # window.location.search
            r'fetch\(["\']([^"\']+)\?([^"\']+)=',  # fetch avec paramètres
            r'\.get\(["\']([^"\']+)["\']',  # jQuery .get()
            r'\.post\(["\']([^"\']+)["\']',  # jQuery .post()
            r'url\s*[=:]\s*["\']([^"\']+)\?([^"\']+)=',  # url = "...?param="
            r'showproduct\.php\?id=',  # Pattern spécifique pour showproduct.php
            r'listart\.php\?artist=',  # Pattern spécifique pour listart.php
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, code_js, re.IGNORECASE)
            params.update(matches)
            # Si on trouve un pattern avec plusieurs groupes, extraire tous
            if isinstance(matches, list) and matches:
                for match in matches:
                    if isinstance(match, tuple):
                        params.update(match)
        
        # ⭐ NOUVEAU: Extraire explicitement 'id' si on trouve showproduct.php ou listart.php
        if 'showproduct' in code_js.lower() or 'product' in code_js.lower():
            params.add('id')
            params.add('product_id')
        if 'listart' in code_js.lower() or 'artist' in code_js.lower():
            params.add('artist')
            params.add('id')
        
        return params

    def _page_semble_dynamique(self, html: str, url: str) -> bool:
        """Détermine si une page semble dynamique (nécessite des paramètres)"""
        # Indicateurs de page dynamique
        indicateurs = [
            r'\.php', r'\.asp', r'\.aspx', r'\.jsp', r'\.do', r'\.action',
            r'\?', r'&',  # Déjà des paramètres
            r'search', r'filter', r'sort', r'page',  # Mots-clés communs
        ]
        
        url_lower = url.lower()
        html_lower = html.lower()
        
        for pattern in indicateurs:
            if re.search(pattern, url_lower + html_lower, re.IGNORECASE):
                return True
        
        return False

    def _resultat_par_defaut(self) -> Dict[str, List[str]]:
        """Retourne des paramètres par défaut si la page n'est pas accessible"""
        return {
            'get': self.parametres_communs[:15],  # 15 paramètres courants
            'post': [],
            'urls_avec_params': []
        }

    async def decouvrir_pour_endpoints(
        self, endpoints: List[str]
    ) -> Dict[str, Dict[str, List[str]]]:
        """
        Découvre les paramètres pour plusieurs endpoints
        
        Args:
            endpoints: Liste d'URLs à analyser
            
        Returns:
            Dict {url: {get: [...], post: [...]}}
        """
        resultats = {}
        
        # ⭐ PHASE 1: Limiter à 40 endpoints (augmenté de 20)
        endpoints_limites = endpoints[:40]
        
        taches = [
            self.decouvrir_parametres(endpoint)
            for endpoint in endpoints_limites
        ]
        
        resultats_list = await asyncio.gather(*taches, return_exceptions=True)
        
        for endpoint, resultat in zip(endpoints_limites, resultats_list):
            if not isinstance(resultat, Exception):
                resultats[endpoint] = resultat
            else:
                # En cas d'erreur, utiliser les paramètres par défaut
                resultats[endpoint] = self._resultat_par_defaut()
        
        return resultats

