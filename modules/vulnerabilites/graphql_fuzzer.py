"""
Module de fuzzing GraphQL
Détecte les vulnérabilités spécifiques aux API GraphQL
"""

import json
import asyncio
from typing import List, Dict, Any, Optional
from loguru import logger
import aiohttp

from core.models import Vulnerabilite


class GraphQLFuzzer:
    """
    Fuzzer spécialisé pour les API GraphQL
    """
    
    def __init__(self, session: aiohttp.ClientSession, auth_config: Dict = None):
        self.session = session
        self.auth_config = auth_config or {}
        
        # Requête d'introspection GraphQL standard
        self.introspection_query = """
        query IntrospectionQuery {
          __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
              ...FullType
            }
            directives {
              name
              description
              locations
              args {
                ...InputValue
              }
            }
          }
        }
        
        fragment FullType on __Type {
          kind
          name
          description
          fields(includeDeprecated: true) {
            name
            description
            args {
              ...InputValue
            }
            type {
              ...TypeRef
            }
            isDeprecated
            deprecationReason
          }
          inputFields {
            ...InputValue
          }
          interfaces {
            ...TypeRef
          }
          enumValues(includeDeprecated: true) {
            name
            description
            isDeprecated
            deprecationReason
          }
          possibleTypes {
            ...TypeRef
          }
        }
        
        fragment InputValue on __InputValue {
          name
          description
          type { ...TypeRef }
          defaultValue
        }
        
        fragment TypeRef on __Type {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                    ofType {
                      kind
                      name
                      ofType {
                        kind
                        name
                      }
                    }
                  }
                }
              }
            }
          }
        }
        """

    async def detect_graphql_endpoint(self, url: str) -> bool:
        """
        Détecte si l'URL est un endpoint GraphQL
        """
        # Endpoints GraphQL courants
        graphql_paths = ['/graphql', '/api/graphql', '/v1/graphql', '/query', '/api']
        
        for path in graphql_paths:
            test_url = url.rstrip('/') + path
            try:
                # Test avec une simple query
                simple_query = {"query": "{__typename}"}
                async with self.session.post(
                    test_url,
                    json=simple_query,
                    headers=self._get_headers(),
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        if 'data' in data or 'errors' in data:
                            logger.info(f"Endpoint GraphQL détecté: {test_url}")
                            return True
            except Exception:
                continue
        
        return False

    async def test_introspection(self, url: str) -> Optional[Dict]:
        """
        Test si l'introspection GraphQL est activée
        """
        try:
            payload = {"query": self.introspection_query}
            
            async with self.session.post(
                url,
                json=payload,
                headers=self._get_headers(),
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    # Vérifier si l'introspection a renvoyé des données
                    if 'data' in data and data['data'] and '__schema' in data['data']:
                        schema = data['data']['__schema']
                        logger.success(f"Introspection GraphQL activée sur {url}")
                        return schema
                    elif 'errors' in data:
                        # Introspection désactivée
                        logger.info(f"Introspection GraphQL désactivée: {data['errors']}")
                        return None
                        
        except Exception as e:
            logger.debug(f"Erreur lors du test d'introspection: {str(e)}")
        
        return None

    async def test_batching_attack(self, url: str, schema: Optional[Dict] = None) -> List[Vulnerabilite]:
        """
        Test les attaques par batching (requêtes multiples)
        """
        vulnerabilites = []
        
        # Créer une requête simple pour le batching
        simple_query = "{__typename}"
        if schema and 'queryType' in schema:
            # Utiliser un type de query du schéma si disponible
            query_type = schema.get('queryType', {}).get('name', '__typename')
            simple_query = f"{{{query_type}}}"
        
        # Tester avec un grand nombre de requêtes en batch
        batch_sizes = [10, 50, 100]
        
        for batch_size in batch_sizes:
            try:
                # Créer un batch de requêtes identiques
                batched_queries = [{"query": simple_query} for _ in range(batch_size)]
                
                async with self.session.post(
                    url,
                    json=batched_queries,
                    headers=self._get_headers(),
                    timeout=aiohttp.ClientTimeout(total=15)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        # Si le serveur accepte le batch sans erreur
                        if isinstance(data, list) and len(data) == batch_size:
                            vulnerabilites.append(Vulnerabilite(
                                type="GraphQL Batching Attack",
                                url=url,
                                severite="MOYEN",
                                description=f"Le serveur accepte les requêtes en batch ({batch_size} requêtes). "
                                           f"Cela peut être exploité pour contourner les rate limits.",
                                payload=json.dumps(batched_queries[:3]) + f"... (x{batch_size})",
                                remediation="Implémenter des limites sur le nombre de requêtes par batch. "
                                           "Utiliser un rate limiting basé sur la complexité des queries.",
                                preuve=f"Batch de {batch_size} requêtes accepté"
                            ))
                            logger.warning(f"Batching attack possible: {batch_size} requêtes acceptées")
                            break  # Pas besoin de tester des tailles plus grandes
                            
            except asyncio.TimeoutError:
                logger.debug(f"Timeout pour batch de {batch_size} requêtes")
            except Exception as e:
                logger.debug(f"Erreur test batching {batch_size}: {str(e)}")
        
        return vulnerabilites

    async def test_depth_limits(self, url: str, schema: Optional[Dict] = None) -> List[Vulnerabilite]:
        """
        Test les limites de profondeur des requêtes (Depth Limit Bypass)
        """
        vulnerabilites = []
        
        # Créer des requêtes avec différentes profondeurs
        depths = [10, 20, 50]
        
        for depth in depths:
            try:
                # Créer une query profonde avec __typename imbriqué
                nested_query = self._create_nested_query(depth)
                payload = {"query": nested_query}
                
                async with self.session.post(
                    url,
                    json=payload,
                    headers=self._get_headers(),
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        # Si la requête profonde est acceptée
                        if 'data' in data and not ('errors' in data):
                            vulnerabilites.append(Vulnerabilite(
                                type="GraphQL Depth Limit Bypass",
                                url=url,
                                severite="ÉLEVÉ",
                                description=f"Le serveur accepte des requêtes avec une profondeur de {depth}. "
                                           f"Cela peut causer une charge CPU excessive (DoS).",
                                payload=nested_query[:200] + "..." if len(nested_query) > 200 else nested_query,
                                remediation="Implémenter une limite de profondeur (max 5-10 niveaux). "
                                           "Utiliser graphql-depth-limit ou équivalent.",
                                preuve=f"Requête de profondeur {depth} acceptée"
                            ))
                            logger.warning(f"Depth limit bypass: profondeur {depth} acceptée")
                            break  # Pas besoin de tester des profondeurs plus grandes
                            
            except asyncio.TimeoutError:
                logger.debug(f"Timeout pour profondeur {depth}")
            except Exception as e:
                logger.debug(f"Erreur test profondeur {depth}: {str(e)}")
        
        return vulnerabilites

    async def test_field_duplication(self, url: str, schema: Optional[Dict] = None) -> List[Vulnerabilite]:
        """
        Test la duplication de champs (Field Duplication Attack)
        """
        vulnerabilites = []
        
        # Nombre de duplications à tester
        duplication_counts = [100, 500, 1000]
        
        for count in duplication_counts:
            try:
                # Créer une query avec des champs dupliqués
                duplicated_query = self._create_duplicated_query(count)
                payload = {"query": duplicated_query}
                
                async with self.session.post(
                    url,
                    json=payload,
                    headers=self._get_headers(),
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        if 'data' in data:
                            vulnerabilites.append(Vulnerabilite(
                                type="GraphQL Field Duplication Attack",
                                url=url,
                                severite="MOYEN",
                                description=f"Le serveur accepte {count} champs dupliqués dans une requête. "
                                           f"Cela peut causer une charge mémoire excessive.",
                                payload=duplicated_query[:200] + "...",
                                remediation="Limiter le nombre de champs par requête. "
                                           "Implémenter une validation de complexité des queries.",
                                preuve=f"{count} champs dupliqués acceptés"
                            ))
                            logger.warning(f"Field duplication: {count} champs acceptés")
                            break
                            
            except asyncio.TimeoutError:
                logger.debug(f"Timeout pour {count} duplications")
            except Exception as e:
                logger.debug(f"Erreur test duplication {count}: {str(e)}")
        
        return vulnerabilites

    async def test_directive_injection(self, url: str, schema: Optional[Dict] = None) -> List[Vulnerabilite]:
        """
        Test l'injection de directives malveillantes
        """
        vulnerabilites = []
        
        # Tester différentes directives
        malicious_directives = [
            # Directive @skip avec condition toujours vraie
            "{__typename @skip(if: true)}",
            # Directive @include avec condition
            "{__typename @include(if: true)}",
            # Multiples directives
            "{__typename @skip(if: false) @include(if: true)}",
        ]
        
        for directive_query in malicious_directives:
            try:
                payload = {"query": directive_query}
                
                async with self.session.post(
                    url,
                    json=payload,
                    headers=self._get_headers(),
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        # Les directives devraient être gérées correctement
                        # On cherche des comportements anormaux
                        if 'errors' in data:
                            error_msg = str(data['errors'])
                            if 'directive' in error_msg.lower():
                                logger.debug(f"Directive rejetée correctement: {directive_query}")
                                
            except Exception as e:
                logger.debug(f"Erreur test directive: {str(e)}")
        
        return vulnerabilites

    async def scanner(self, url: str, params: Dict = None) -> List[Vulnerabilite]:
        """
        Point d'entrée principal du fuzzer GraphQL
        """
        vulnerabilites = []
        
        logger.info(f"Démarrage du scan GraphQL sur {url}")
        
        # 1. Détecter si c'est un endpoint GraphQL
        is_graphql = await self.detect_graphql_endpoint(url)
        
        if not is_graphql:
            # Tester directement l'URL fournie
            logger.debug("Test de l'URL comme endpoint GraphQL direct")
        
        # 2. Tester l'introspection
        schema = await self.test_introspection(url)
        
        if schema:
            vulnerabilites.append(Vulnerabilite(
                type="GraphQL Introspection Enabled",
                url=url,
                severite="MOYEN",
                description="L'introspection GraphQL est activée. Un attaquant peut récupérer "
                           "l'intégralité du schéma de l'API, incluant les types, champs, "
                           "mutations et leurs descriptions.",
                payload=json.dumps({"query": self.introspection_query[:100] + "..."}),
                remediation="Désactiver l'introspection en production. "
                           "Pour Apollo Server: introspection: false. "
                           "Pour GraphQL.js: validationRules: [NoIntrospection]",
                preuve=f"Schéma récupéré: {len(schema.get('types', []))} types détectés"
            ))
        
        # 3. Tester les attaques par batching
        batching_vulns = await self.test_batching_attack(url, schema)
        vulnerabilites.extend(batching_vulns)
        
        # 4. Tester les limites de profondeur
        depth_vulns = await self.test_depth_limits(url, schema)
        vulnerabilites.extend(depth_vulns)
        
        # 5. Tester la duplication de champs
        duplication_vulns = await self.test_field_duplication(url, schema)
        vulnerabilites.extend(duplication_vulns)
        
        # 6. Tester l'injection de directives
        directive_vulns = await self.test_directive_injection(url, schema)
        vulnerabilites.extend(directive_vulns)
        
        logger.info(f"Scan GraphQL terminé: {len(vulnerabilites)} vulnérabilité(s) trouvée(s)")
        
        return vulnerabilites

    def _get_headers(self) -> Dict[str, str]:
        """Construit les headers avec authentification"""
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'VulnHunter-GraphQL/1.0'
        }
        
        # Ajouter les headers d'authentification
        if self.auth_config and 'headers' in self.auth_config:
            headers.update(self.auth_config['headers'])
        
        return headers

    def _create_nested_query(self, depth: int) -> str:
        """
        Crée une requête GraphQL avec une profondeur spécifique
        """
        # Utiliser __typename pour créer une requête profonde
        query = "__typename"
        
        # Alternative avec des fragments pour augmenter la profondeur
        fragment = """
        fragment DeepFragment on Query {
          __typename
          __schema {
            types {
              name
              fields {
                name
                type {
                  name
                }
              }
            }
          }
        }
        """
        
        if depth <= 5:
            # Pour des profondeurs faibles, simple imbrication
            nested = "__typename"
            for _ in range(depth):
                nested = f"{{__schema{{types{{{nested}}}}}}}"
            return f"query {{{nested}}}"
        else:
            # Pour des profondeurs élevées, utiliser une structure répétitive
            nested = "__typename"
            for _ in range(depth):
                nested = f"__schema{{queryType{{name fields{{{nested}}}}}}}"
            return f"query {{{nested}}}"

    def _create_duplicated_query(self, count: int) -> str:
        """
        Crée une requête avec des champs dupliqués
        """
        # Créer des alias pour les champs dupliqués
        fields = [f"alias{i}: __typename" for i in range(count)]
        return f"query {{{' '.join(fields)}}}"
