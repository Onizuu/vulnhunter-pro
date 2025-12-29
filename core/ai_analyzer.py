"""
Analyseur IA pour détecter les vulnérabilités et générer des payloads
Utilise GPT-4/Claude pour l'analyse avancée
"""

from typing import List, Dict, Optional
from loguru import logger


class AnalyseurIA:
    """
    Utilise l'IA pour analyser les réponses HTTP et identifier
    des vulnérabilités que les scanners traditionnels pourraient manquer
    """

    def __init__(self, client_ia):
        """
        Initialise l'analyseur IA
        
        Args:
            client_ia: Client OpenAI/Claude
        """
        self.client_ia = client_ia

    async def analyser_reponse_http(
        self, 
        url: str, 
        reponse: str, 
        headers: Dict[str, str],
        status_code: int
    ) -> List[Dict]:
        """
        Analyse une réponse HTTP pour détecter des anomalies
        
        Args:
            url: URL testée
            reponse: Contenu de la réponse
            headers: Headers HTTP
            status_code: Code de statut
            
        Returns:
            List[Dict]: Liste d'anomalies/vulnérabilités potentielles
        """
        try:
            # Limiter la taille de la réponse pour l'IA
            reponse_tronquee = reponse[:5000] if len(reponse) > 5000 else reponse
            
            prompt = f"""Analyse cette réponse HTTP et identifie toute vulnérabilité ou anomalie de sécurité.

URL: {url}
Status: {status_code}

Headers:
{self._formatter_headers(headers)}

Corps de la réponse (premiers 5000 caractères):
{reponse_tronquee}

Recherche spécifiquement:
1. Fuites d'informations sensibles (tokens, clés API, mots de passe)
2. Messages d'erreur détaillés révélant des informations système
3. Commentaires HTML contenant des informations sensibles
4. Configurations mal sécurisées
5. Headers de sécurité manquants
6. Indices d'injection SQL, XSS, ou autres vulnérabilités
7. Endpoints ou paramètres cachés dans le code JavaScript
8. Chemins de fichiers système exposés

Retourne un JSON avec ce format:
{{
    "vulnerabilites": [
        {{
            "type": "Type de vulnérabilité",
            "severite": "CRITIQUE|ÉLEVÉ|MOYEN|FAIBLE",
            "description": "Description détaillée",
            "preuve": "Extrait de code prouvant la vulnérabilité",
            "recommandation": "Comment corriger"
        }}
    ]
}}"""

            reponse_ia = await self.client_ia.generer_completion(prompt, json_mode=True)
            
            if reponse_ia:
                logger.debug(f"Analyse IA terminée pour {url}")
                return reponse_ia.get('vulnerabilites', [])
            
            return []
            
        except Exception as e:
            logger.error(f"Erreur analyse IA: {str(e)}")
            return []

    async def generer_payloads_personnalises(
        self,
        type_vuln: str,
        contexte: str,
        filtres_detectes: Optional[List[str]] = None
    ) -> List[str]:
        """
        Génère des payloads personnalisés avec l'IA
        
        Args:
            type_vuln: Type de vulnérabilité (SQLi, XSS, etc.)
            contexte: Contexte de l'injection (HTML, JS, SQL, etc.)
            filtres_detectes: Liste des filtres WAF détectés
            
        Returns:
            List[str]: Liste de payloads personnalisés
        """
        try:
            filtres_str = ", ".join(filtres_detectes) if filtres_detectes else "Aucun"
            
            prompt = f"""Génère 20 payloads {type_vuln} innovants et efficaces.

Contexte d'injection: {contexte}
Filtres WAF détectés: {filtres_str}

Les payloads doivent:
1. Contourner les filtres WAF modernes
2. Être adaptés au contexte spécifique
3. Utiliser des techniques d'obfuscation variées
4. Inclure des variantes avec encodages multiples
5. Être fonctionnels et testés

Retourne un JSON:
{{
    "payloads": [
        {{
            "payload": "le payload",
            "technique": "technique utilisée",
            "description": "comment ça fonctionne"
        }}
    ]
}}"""

            reponse_ia = await self.client_ia.generer_completion(prompt, json_mode=True)
            
            if reponse_ia and 'payloads' in reponse_ia:
                payloads = [p['payload'] for p in reponse_ia['payloads']]
                logger.info(f"Généré {len(payloads)} payloads {type_vuln} avec l'IA")
                return payloads
            
            return []
            
        except Exception as e:
            logger.error(f"Erreur génération payloads IA: {str(e)}")
            return []

    async def analyser_code_javascript(self, code_js: str, url: str) -> List[Dict]:
        """
        Analyse du code JavaScript pour trouver des endpoints cachés,
        clés API, et autres vulnérabilités
        
        Args:
            code_js: Code JavaScript à analyser
            url: URL source du JS
            
        Returns:
            List[Dict]: Découvertes intéressantes
        """
        try:
            # Limiter la taille
            code_tronque = code_js[:10000] if len(code_js) > 10000 else code_js
            
            prompt = f"""Analyse ce code JavaScript et extrais toutes les informations sensibles et endpoints.

URL: {url}

Code JavaScript:
{code_tronque}

Recherche:
1. Clés API, tokens, secrets
2. Endpoints d'API cachés
3. Chemins de fichiers sensibles
4. Paramètres de requêtes
5. Logique d'authentification
6. Commentaires révélateurs
7. URLs de services backend
8. Vulnérabilités côté client (XSS DOM, etc.)

Retourne un JSON:
{{
    "decouvertes": [
        {{
            "type": "type de découverte",
            "valeur": "la valeur trouvée",
            "impact": "impact potentiel",
            "ligne": "extrait de code"
        }}
    ]
}}"""

            reponse_ia = await self.client_ia.generer_completion(prompt, json_mode=True)
            
            if reponse_ia:
                return reponse_ia.get('decouvertes', [])
            
            return []
            
        except Exception as e:
            logger.error(f"Erreur analyse JS: {str(e)}")
            return []

    async def suggerer_chaine_exploit(
        self, 
        vulnerabilites: List
    ) -> List[Dict]:
        """
        Utilise l'IA pour suggérer comment combiner des vulnérabilités
        en chaînes d'exploitation plus puissantes
        
        Args:
            vulnerabilites: Liste des vulnérabilités trouvées
            
        Returns:
            List[Dict]: Chaînes d'exploit suggérées
        """
        try:
            # Préparer le résumé des vulnérabilités
            resume_vulns = []
            for v in vulnerabilites:
                resume_vulns.append({
                    'type': v.type,
                    'url': v.url,
                    'severite': v.severite,
                    'description': v.description[:200]
                })
            
            prompt = f"""Analyse ces vulnérabilités et suggère des chaînes d'exploitation.

Vulnérabilités trouvées:
{resume_vulns}

Pour chaque chaîne possible:
1. Explique comment combiner les vulnérabilités
2. Décris l'impact de la chaîne complète
3. Donne les étapes d'exploitation
4. Évalue la sévérité globale

Retourne un JSON:
{{
    "chaines": [
        {{
            "nom": "nom de la chaîne",
            "vulnerabilites_utilisees": ["type1", "type2"],
            "etapes": ["étape 1", "étape 2"],
            "impact": "description de l'impact",
            "severite": "CRITIQUE|ÉLEVÉ|MOYEN",
            "poc": "proof of concept en pseudo-code"
        }}
    ]
}}"""

            reponse_ia = await self.client_ia.generer_completion(prompt, json_mode=True)
            
            if reponse_ia:
                chaines = reponse_ia.get('chaines', [])
                logger.info(f"IA a suggéré {len(chaines)} chaînes d'exploit")
                return chaines
            
            return []
            
        except Exception as e:
            logger.error(f"Erreur suggestion chaînes: {str(e)}")
            return []

    async def generer_recommandations(self, vulnerabilite) -> str:
        """
        Génère des recommandations de correction détaillées
        
        Args:
            vulnerabilite: Objet Vulnerabilite
            
        Returns:
            str: Recommandations détaillées
        """
        try:
            prompt = f"""Génère des recommandations de correction détaillées pour cette vulnérabilité.

Type: {vulnerabilite.type}
URL: {vulnerabilite.url}
Description: {vulnerabilite.description}
Payload: {vulnerabilite.payload}

Fournis:
1. Explication de la cause racine
2. Corrections spécifiques avec exemples de code
3. Bonnes pratiques de sécurité
4. Tests pour valider la correction
5. Ressources additionnelles

Format en Markdown."""

            recommendations = await self.client_ia.generer_completion(prompt)
            
            return recommendations or "Aucune recommandation générée"
            
        except Exception as e:
            logger.error(f"Erreur génération recommandations: {str(e)}")
            return "Erreur lors de la génération des recommandations"

    def _formatter_headers(self, headers: Dict[str, str]) -> str:
        """
        Formate les headers pour l'affichage
        
        Args:
            headers: Dictionnaire des headers
            
        Returns:
            str: Headers formatés
        """
        return "\n".join(f"{k}: {v}" for k, v in headers.items())

