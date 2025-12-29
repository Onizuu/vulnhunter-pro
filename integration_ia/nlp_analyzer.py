"""
Analyseur NLP pour détecter les anomalies dans les réponses HTTP
"""

import re
from typing import Dict, List
from loguru import logger


class AnalyseurNLP:
    """
    Utilise le traitement du langage naturel pour analyser les réponses
    """

    def __init__(self):
        """
        Initialise l'analyseur NLP
        """
        # Mots-clés suspects par catégorie
        self.keywords = {
            'sql_errors': [
                'sql syntax', 'mysql', 'postgresql', 'ora-', 'sqlite',
                'sqlstate', 'db2', 'odbc', 'jdbc', 'microsoft sql'
            ],
            'php_errors': [
                'parse error', 'fatal error', 'warning:', 'notice:',
                'deprecated:', 'undefined variable', 'call to undefined'
            ],
            'sensitive_info': [
                'password', 'passwd', 'pwd', 'api_key', 'secret',
                'token', 'private_key', 'access_token', 'credentials'
            ],
            'system_info': [
                'root:x:', '/etc/passwd', 'c:\\windows', 'uid=', 'gid=',
                'apache/', 'nginx/', 'microsoft-iis/'
            ],
            'debug_info': [
                'debug', 'trace', 'stack trace', 'backtrace',
                'exception in', 'line number'
            ]
        }

    def analyser_reponse(self, reponse_http: str, headers: Dict) -> Dict:
        """
        Analyse une réponse HTTP pour détecter des anomalies
        
        Args:
            reponse_http: Contenu de la réponse
            headers: Headers HTTP
            
        Returns:
            Dict: Résultats de l'analyse
        """
        resultats = {
            'anomalies': [],
            'score_risque': 0.0,
            'categories_detectees': []
        }
        
        try:
            # Analyser le contenu
            anomalies_contenu = self._analyser_contenu(reponse_http)
            resultats['anomalies'].extend(anomalies_contenu)
            
            # Analyser les headers
            anomalies_headers = self._analyser_headers(headers)
            resultats['anomalies'].extend(anomalies_headers)
            
            # Calculer le score de risque
            resultats['score_risque'] = self._calculer_score_risque(resultats['anomalies'])
            
            # Extraire les catégories
            resultats['categories_detectees'] = list(set(
                a['categorie'] for a in resultats['anomalies']
            ))
            
            if resultats['anomalies']:
                logger.debug(f"NLP: {len(resultats['anomalies'])} anomalies détectées")
        
        except Exception as e:
            logger.error(f"Erreur analyse NLP: {str(e)}")
        
        return resultats

    def _analyser_contenu(self, contenu: str) -> List[Dict]:
        """
        Analyse le contenu pour détecter des anomalies
        
        Args:
            contenu: Contenu à analyser
            
        Returns:
            List[Dict]: Anomalies détectées
        """
        anomalies = []
        contenu_lower = contenu.lower()
        
        for categorie, keywords in self.keywords.items():
            for keyword in keywords:
                if keyword in contenu_lower:
                    # Extraire le contexte
                    pos = contenu_lower.find(keyword)
                    contexte = contenu[max(0, pos-50):min(len(contenu), pos+50)]
                    
                    anomalies.append({
                        'categorie': categorie,
                        'keyword': keyword,
                        'contexte': contexte,
                        'severite': self._determiner_severite(categorie)
                    })
        
        return anomalies

    def _analyser_headers(self, headers: Dict) -> List[Dict]:
        """
        Analyse les headers HTTP
        
        Args:
            headers: Dictionnaire des headers
            
        Returns:
            List[Dict]: Anomalies détectées
        """
        anomalies = []
        
        # Headers qui révèlent des informations
        headers_sensibles = ['Server', 'X-Powered-By', 'X-AspNet-Version']
        
        for header in headers_sensibles:
            if header in headers:
                anomalies.append({
                    'categorie': 'information_disclosure',
                    'keyword': header,
                    'contexte': f"{header}: {headers[header]}",
                    'severite': 'FAIBLE'
                })
        
        # Détecter erreurs dans headers
        for key, value in headers.items():
            if isinstance(value, str):
                value_lower = value.lower()
                if any(err in value_lower for err in ['error', 'exception', 'debug']):
                    anomalies.append({
                        'categorie': 'debug_info',
                        'keyword': key,
                        'contexte': f"{key}: {value[:100]}",
                        'severite': 'MOYEN'
                    })
        
        return anomalies

    def _determiner_severite(self, categorie: str) -> str:
        """
        Détermine la sévérité selon la catégorie
        
        Args:
            categorie: Catégorie d'anomalie
            
        Returns:
            str: Sévérité
        """
        severites = {
            'sql_errors': 'CRITIQUE',
            'php_errors': 'MOYEN',
            'sensitive_info': 'CRITIQUE',
            'system_info': 'ÉLEVÉ',
            'debug_info': 'MOYEN'
        }
        
        return severites.get(categorie, 'FAIBLE')

    def _calculer_score_risque(self, anomalies: List[Dict]) -> float:
        """
        Calcule un score de risque global
        
        Args:
            anomalies: Liste des anomalies
            
        Returns:
            float: Score entre 0 et 10
        """
        if not anomalies:
            return 0.0
        
        scores_severite = {
            'CRITIQUE': 10.0,
            'ÉLEVÉ': 7.0,
            'MOYEN': 5.0,
            'FAIBLE': 2.0
        }
        
        score_total = sum(
            scores_severite.get(a['severite'], 0)
            for a in anomalies
        )
        
        # Normaliser sur 10
        score_moyen = score_total / len(anomalies)
        
        return min(10.0, score_moyen)

    def extraire_endpoints(self, contenu: str) -> List[str]:
        """
        Extrait les endpoints d'API du contenu JavaScript
        
        Args:
            contenu: Contenu à analyser
            
        Returns:
            List[str]: Endpoints trouvés
        """
        endpoints = []
        
        # Patterns pour trouver des URLs
        patterns = [
            r'["\']([/][a-zA-Z0-9/_-]+)["\']',
            r'url:\s*["\']([^"\']+)["\']',
            r'endpoint:\s*["\']([^"\']+)["\']',
            r'api["\']:\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, contenu)
            for match in matches:
                endpoint = match.group(1)
                if len(endpoint) > 3 and endpoint not in endpoints:
                    endpoints.append(endpoint)
        
        return endpoints[:50]  # Limiter à 50

    def extraire_secrets(self, contenu: str) -> List[Dict]:
        """
        Extrait les secrets potentiels (clés API, tokens, etc.)
        
        Args:
            contenu: Contenu à analyser
            
        Returns:
            List[Dict]: Secrets trouvés
        """
        secrets = []
        
        # Patterns pour différents types de secrets
        patterns = {
            'AWS Key': r'AKIA[0-9A-Z]{16}',
            'API Key': r'api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']',
            'Token': r'token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']',
            'Password': r'password["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            'Private Key': r'-----BEGIN [A-Z ]+ PRIVATE KEY-----'
        }
        
        for type_secret, pattern in patterns.items():
            matches = re.finditer(pattern, contenu, re.IGNORECASE)
            for match in matches:
                secrets.append({
                    'type': type_secret,
                    'valeur': match.group(0)[:50] + '...',  # Tronquer
                    'position': match.start()
                })
        
        return secrets

