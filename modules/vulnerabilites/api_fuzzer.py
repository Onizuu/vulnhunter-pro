"""
Module de fuzzing d'API (JSON/GraphQL)
"""

import asyncio
import json
from typing import List, Dict, Any, Optional
from loguru import logger
import aiohttp

from core.models import Vulnerabilite

class ApiFuzzer:
    """
    Fuzzer pour APIs (REST/JSON et GraphQL)
    Teste les injections dans les valeurs JSON
    """

    def __init__(self, client_ia=None, auth_config=None):
        self.client_ia = client_ia
        self.auth_config = auth_config or {}
        self.cookies = self.auth_config.get('cookies', {})
        self.headers = self.auth_config.get('headers', {})
        
        # Payloads génériques pour APIs
        self.payloads = [
            "'", "\"", 
            "' OR '1'='1", 
            "<script>alert(1)</script>",
            "{{7*7}}",
            "${7*7}",
            "../../etc/passwd",
            "| ls -la",
            "<!--", 
            "\n",
            "true", "false", "null"
        ]

    async def scanner(self, url: str, method: str = "POST", data: Dict = None) -> List[Vulnerabilite]:
        """
        Scan un endpoint API
        """
        vulnerabilites = []
        
        if not data:
            return []

        logger.info(f"🔍 Fuzzing API sur {url}")
        
        async with aiohttp.ClientSession(cookies=self.cookies, headers=self.headers) as session:
            # Tester chaque champ du JSON
            for key, value in self._flatten_json(data).items():
                for payload in self.payloads:
                    try:
                        # Injecter le payload
                        fuzzed_data = self._inject_json(data, key, payload)
                        
                        async with session.request(
                            method, 
                            url, 
                            json=fuzzed_data,
                            timeout=aiohttp.ClientTimeout(total=10)
                        ) as response:
                            content = await response.text()
                            
                            # Analyse basique des erreurs
                            if response.status == 500 or "error" in content.lower() or "exception" in content.lower():
                                # Ignorer les erreurs standard JSON
                                if "json parse error" in content.lower():
                                    continue
                                    
                                logger.warning(f"⚠️  Anomalie API détectée sur {key} avec {payload}")
                                
                                vuln = Vulnerabilite(
                                    type="API Fuzzing Anomaly",
                                    severite="MOYEN",
                                    url=url,
                                    description=f"Anomalie détectée dans le champ '{key}'",
                                    payload=str(payload),
                                    preuve=content[:200],
                                    cvss_score=5.0,
                                    remediation="Vérifier la validation des entrées API"
                                )
                                vulnerabilites.append(vuln)
                                
                        await asyncio.sleep(0.1)
                        
                    except Exception as e:
                        logger.debug(f"Erreur fuzzing {key}: {e}")
                        continue
                        
        return vulnerabilites

    def _flatten_json(self, y: Dict) -> Dict:
        """Aplatit un JSON imbriqué pour itérer sur les clés"""
        out = {}
        def flatten(x, name=''):
            if type(x) is dict:
                for a in x:
                    flatten(x[a], name + a + '.')
            elif type(x) is list:
                pass # On ne fuzz pas les listes pour l'instant
            else:
                out[name[:-1]] = x
        flatten(y)
        return out

    def _inject_json(self, data: Dict, key_path: str, payload: Any) -> Dict:
        """Injecte un payload dans une structure JSON imbriquée"""
        import copy
        new_data = copy.deepcopy(data)
        keys = key_path.split('.')
        
        curr = new_data
        for k in keys[:-1]:
            curr = curr[k]
        
        curr[keys[-1]] = payload
        return new_data
