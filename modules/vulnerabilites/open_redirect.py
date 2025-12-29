"""
Détecteur d'Open Redirect
Redirections malveillantes pour phishing
"""

import asyncio
from typing import Optional, List, Dict
from urllib.parse import urlparse, parse_qs
from loguru import logger
import aiohttp

from core.models import Vulnerabilite


class DetecteurOpenRedirect:
    """
    Détecte les vulnérabilités Open Redirect
    Utilisé pour phishing et bypass de whitelist
    """

    def __init__(self, auth_config: Dict = None):
        """
        Initialise le détecteur
        
        Args:
            auth_config: Configuration d'authentification
        """
        self.auth_config = auth_config or {}
        
        # Payloads Open Redirect
        self.payloads_redirect = [
            # Absolute URLs
            "https://evil.com",
            "http://attacker.com",
            "//evil.com",
            "//evil.com/phishing",
            
            # Protocol-relative
            "///evil.com",
            "////evil.com",
            
            # JavaScript redirect
            "javascript:alert(document.domain)",
            "javascript:window.location='http://evil.com'",
            
            # Data URI redirect
            "data:text/html,<script>location='http://evil.com'</script>",
            
            # URL encoding bypass
            "https%3A%2F%2Fevil.com",
            "%2F%2Fevil.com",
            
            # @ bypass
            "https://trusted.com@evil.com",
            "https://evil.com@trusted.com",
            
            # Unicode bypass
            "https://evil。com",  # Unicode dot
            
            # Whitespace bypass
            "https://evil.com%20",
            " https://evil.com",
            
            # Backslash bypass
            "https:\\\\evil.com",
            
            # Null byte bypass  
            "https://evil.com%00.trusted.com",
            
            # CRLF injection dans redirect
            "%0d%0aLocation:https://evil.com",
        ]
        
        # Paramètres communs pour redirections
        self.redirect_params = [
            'url', 'redirect', 'redir', 'next', 'target',
            'return', 'returnUrl', 'redirect_uri', 'continue',
            'dest', 'destination', 'go', 'out', 'view',
            'to', 'returnTo', 'return_to', 'checkout_url',
            'success_url', 'failure_url', 'callback'
        ]

    async def detecter(self, url: str, params: Dict = None) -> List[Vulnerabilite]:
        """
        Détecte les vulnérabilités Open Redirect
        
        Args:
            url: URL à tester  
            params: Paramètres découverts
            
        Returns:
            List[Vulnerabilite]: Vulnérabilités trouvées
        """
        vulnerabilites = []
        
        logger.info(f"🔍 Test Open Redirect: {url}")
        
        try:
            async with aiohttp.ClientSession(
                cookies=self.auth_config.get('cookies'),
                headers=self.auth_config.get('headers')
            ) as session:
                # Extraire paramètres de l'URL
                parsed = urlparse(url)
                url_params = parse_qs(parsed.query)
                
                # Combiner avec params découverts
                all_params = {**url_params, **(params or {})}
                
                # Tester les paramètres connus de redirect
                for param_name in self.redirect_params:
                    for payload in self.payloads_redirect:
                        vuln = await self._test_redirect_payload(
                            session, url, param_name, payload
                        )
                        if vuln:
                            vulnerabilites.append(vuln)
                            logger.success(f"✅ Open Redirect trouvé: {param_name}")
                            break
                    
                    await asyncio.sleep(0.05)
        
        except Exception as e:
            logger.debug(f"Erreur test Open Redirect: {str(e)}")
        
        return vulnerabilites

    async def _test_redirect_payload(
        self,
        session: aiohttp.ClientSession,
        url: str,
        param_name: str,
        payload: str
    ) -> Optional[Vulnerabilite]:
        """Teste un payload de redirect"""
        try:
            # Ajouter payload au paramètre
            test_url = f"{url}?{param_name}={payload}"
            
            async with session.get(
                test_url,
                allow_redirects=False,  # Important: ne pas suivre
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                # Vérifier si redirection
                if response.status in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location', '')
                    
                    # Vérifier si redirection vers domaine externe
                    if self._is_open_redirect(location, payload):
                        return Vulnerabilite(
                            type="Open_Redirect",
                            severite="MOYENNE",
                            url=url,
                            description=f"Open Redirect via '{param_name}'. Permet phishing et bypass de whitelist.",
                            payload=f"{param_name}={payload}",
                            preuve=f"Location: {location}",
                            cvss_score=6.5,
                            remediation=self._get_remediation()
                        )
                
                # Vérifier aussi dans le contenu HTML (meta refresh, JS)
                contenu = await response.text()
                if self._check_client_side_redirect(contenu, payload):
                    return Vulnerabilite(
                        type="Open_Redirect_ClientSide",
                        severite="MOYENNE",
                        url=url,
                        description=f"Client-Side Redirect via '{param_name}' (meta refresh ou JavaScript)",
                        payload=f"{param_name}={payload}",
                        preuve=contenu[:300],
                        cvss_score=5.5,
                        remediation=self._get_remediation()
                    )
        
        except Exception as e:
            logger.debug(f"Erreur payload redirect: {str(e)}")
        
        return None

    def _is_open_redirect(self, location: str, payload: str) -> bool:
        """Vérifie si c'est une vraie open redirect"""
        if not location:
            return False
        
        # Parser location
        parsed = urlparse(location)
        
        # Vérifier si domaine externe (evil.com, attacker.com)
        external_domains = ['evil.com', 'attacker.com', 'malicious.com']
        if any(domain in parsed.netloc for domain in external_domains):
            return True
        
        # Vérifier si location contient le payload
        if payload.replace('https://', '').replace('http://', '') in location:
            return True
        
        return False

    def _check_client_side_redirect(self, contenu: str, payload: str) -> bool:
        """Vérifie les redirections côté client"""
        contenu_lower = contenu.lower()
        
        # Meta refresh
        if 'meta' in contenu_lower and 'refresh' in contenu_lower:
            if any(domain in contenu for domain in ['evil.com', 'attacker.com']):
                return True
        
        # JavaScript location
        js_patterns = [
            'window.location',
            'document.location',
            'location.href',
            'location.replace',
        ]
        if any(pattern in contenu_lower for pattern in js_patterns):
            if payload in contenu or 'evil.com' in contenu:
                return True
        
        return False

    def _get_remediation(self) -> str:
        """Recommandations de remediation"""
        return """
Remediation Open Redirect:

1. Utiliser une whitelist stricte de domaines autorisés
2. Valider que l'URL de redirection est relative
3. Ne jamais rediriger vers des URLs absolues externes
4. Utiliser des tokens de redirection au lieu d'URLs
5. Valider le schéma (protocol): HTTPS uniquement
6. Échapper les URLs dans le HTML
7. Implémenter un avertissement avant redirect externe
8. Logs des redirections suspectes
9. CSP avec trusted-types
10. Ne pas inclure le domaine de destination dans l'URL

Exemple sécurisé (Python/Flask):
```python
from urllib.parse import urlparse
from flask import redirect, abort

ALLOWED_HOSTS = ['trusted.com', 'app.trusted.com']

def safe_redirect(url):
    parsed = urlparse(url)
    
    # 1. Vérifier si URL relative
    if not parsed.netloc:
        return redirect(url)  # ✅ Relative URL OK
    
    # 2. Vérifier whitelist
    if parsed.netloc in ALLOWED_HOSTS:
        return redirect(url)  # ✅ Whitelist OK
    
    # 3. Rejeter
    abort(400, "Invalid redirect")  # ❌ Bloquer
```

Alternative: Token-based redirect
```python
import secrets

redirect_tokens = {}

def create_redirect_token(url):
    token = secrets.token_urlsafe(32)
    redirect_tokens[token] = url
    return token

def redirect_by_token(token):
    url = redirect_tokens.get(token)
    if url:
        return redirect(url)
    abort(400)
```

Références:
- OWASP Open Redirect
- CWE-601: URL Redirection to Untrusted Site
"""


# Test
async def test_open_redirect():
    """Test du détecteur"""
    detector = DetecteurOpenRedirect()
    test_url = "http://testphp.vulnweb.com/login"
    
    vulns = await detector.detecter(test_url)
    print(f"{'✅' if vulns else '❌'} {len(vulns)} vulnérabilités Open Redirect trouvées")


if __name__ == "__main__":
    asyncio.run(test_open_redirect())
