"""
Client OpenAI pour génération de payloads et analyse
"""

import os
import json
from typing import Optional, Dict, List, Union
from loguru import logger
import openai


class ClientOpenAI:
    """
    Client pour interagir avec l'API OpenAI (GPT-4)
    """

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialise le client OpenAI
        
        Args:
            api_key: Clé API OpenAI
        """
        self.api_key = api_key or os.getenv('OPENAI_API_KEY')
        
        if not self.api_key or self.api_key == 'sk-your-key-here':
            logger.warning("⚠️  Clé API OpenAI non configurée - Mode sans IA activé")
            logger.info("💡 Les scans de base fonctionneront sans génération de payloads IA")
            self.disponible = False
        else:
            try:
                openai.api_key = self.api_key
                self.disponible = True
                logger.info("✅ Client OpenAI initialisé")
            except Exception as e:
                logger.warning(f"⚠️  Impossible d'initialiser OpenAI: {str(e)}")
                self.disponible = False
        
        self.modele = "gpt-4-turbo-preview"
        self.temperature = 0.7
        self.max_tokens = 4000

    async def generer_completion(
        self, 
        prompt: str, 
        json_mode: bool = False,
        temperature: Optional[float] = None
    ) -> Optional[Union[str, Dict]]:
        """
        Génère une completion avec GPT-4
        
        Args:
            prompt: Le prompt à envoyer
            json_mode: Si True, force la réponse en JSON
            temperature: Température de génération (créativité)
            
        Returns:
            str|Dict: Réponse générée ou None si erreur
        """
        if not self.disponible:
            logger.warning("Client OpenAI non disponible")
            return None
        
        try:
            messages = [
                {
                    "role": "system",
                    "content": "Tu es un expert en cybersécurité spécialisé dans "
                               "les tests de pénétration web. Tu fournis des réponses "
                               "précises, techniques et actionnables."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ]
            
            params = {
                "model": self.modele,
                "messages": messages,
                "temperature": temperature or self.temperature,
                "max_tokens": self.max_tokens
            }
            
            if json_mode:
                params["response_format"] = {"type": "json_object"}
            
            response = openai.chat.completions.create(**params)
            
            contenu = response.choices[0].message.content
            
            # Si mode JSON, parser la réponse
            if json_mode:
                try:
                    return json.loads(contenu)
                except json.JSONDecodeError:
                    logger.error("Réponse JSON invalide de l'IA")
                    return None
            
            return contenu
            
        except Exception as e:
            logger.error(f"Erreur lors de l'appel OpenAI: {str(e)}")
            return None

    async def generer_payloads_sqli(
        self, 
        contexte: str,
        dbms: Optional[str] = None,
        filtres: Optional[List[str]] = None
    ) -> List[str]:
        """
        Génère des payloads d'injection SQL personnalisés
        
        Args:
            contexte: Contexte de l'injection
            dbms: Type de SGBD (MySQL, PostgreSQL, etc.)
            filtres: Filtres WAF détectés
            
        Returns:
            List[str]: Payloads générés
        """
        dbms_str = dbms or "inconnu"
        filtres_str = ", ".join(filtres) if filtres else "aucun"
        
        prompt = f"""Génère 30 payloads d'injection SQL avancés pour contourner les WAF modernes.

Contexte: {contexte}
SGBD: {dbms_str}
Filtres WAF: {filtres_str}

Les payloads doivent:
1. Contourner les filtres WAF (Cloudflare, AWS WAF, ModSecurity)
2. Utiliser des techniques d'obfuscation variées
3. Inclure des payloads temporels et basés sur erreur
4. Tester l'extraction de données
5. Être fonctionnels

Techniques à utiliser:
- Encodage multiple (URL, hex, unicode)
- Commentaires SQL variés
- Variations de casse
- Espaces alternatifs
- Opérateurs logiques alternatifs
- Fonctions SQL alternatives

Retourne uniquement un JSON:
{{
    "payloads": ["payload1", "payload2", ...]
}}"""

        resultat = await self.generer_completion(prompt, json_mode=True)
        
        if resultat and 'payloads' in resultat:
            return resultat['payloads']
        
        return []

    async def generer_payloads_xss(
        self,
        contexte: str,
        filtres: Optional[List[str]] = None
    ) -> List[str]:
        """
        Génère des payloads XSS personnalisés
        
        Args:
            contexte: Contexte (HTML, JavaScript, attribut, etc.)
            filtres: Filtres détectés
            
        Returns:
            List[str]: Payloads XSS
        """
        filtres_str = ", ".join(filtres) if filtres else "aucun"
        
        prompt = f"""Génère 30 payloads XSS innovants pour contourner les filtres modernes.

Contexte: {contexte}
Filtres: {filtres_str}

Les payloads doivent:
1. Contourner CSP (Content Security Policy)
2. Fonctionner dans différents contextes
3. Utiliser l'obfuscation avancée
4. Éviter les mots-clés courants bloqués
5. Inclure des variantes DOM-based

Techniques:
- Encodages multiples
- Event handlers alternatifs
- Vecteurs sans parenthèses
- Template literals
- Payloads polyglot
- Mutation XSS

Retourne uniquement un JSON:
{{
    "payloads": ["payload1", "payload2", ...]
}}"""

        resultat = await self.generer_completion(prompt, json_mode=True)
        
        if resultat and 'payloads' in resultat:
            return resultat['payloads']
        
        return []

    async def analyser_reponse_pour_vuln(
        self,
        url: str,
        requete: str,
        reponse: str,
        headers: Dict[str, str]
    ) -> Dict:
        """
        Analyse une réponse HTTP pour détecter des vulnérabilités
        
        Args:
            url: URL testée
            requete: Requête envoyée
            reponse: Réponse reçue
            headers: Headers de la réponse
            
        Returns:
            Dict: Analyse des vulnérabilités
        """
        # Tronquer pour rester dans les limites
        reponse_tronquee = reponse[:3000]
        
        prompt = f"""Analyse cette interaction HTTP et identifie toute vulnérabilité de sécurité.

URL: {url}

Requête:
{requete[:500]}

Réponse (premiers 3000 caractères):
{reponse_tronquee}

Headers:
{json.dumps(headers, indent=2)}

Identifie:
1. Injections SQL (messages d'erreur, comportement anormal)
2. XSS (réflexion non échappée)
3. Fuites d'informations
4. Erreurs révélatrices
5. Configuration non sécurisée
6. Headers de sécurité manquants

Retourne un JSON:
{{
    "vulnerabilites_detectees": [
        {{
            "type": "type de vuln",
            "confiance": "haute|moyenne|faible",
            "preuve": "extrait prouvant la vuln",
            "description": "description détaillée"
        }}
    ],
    "recommandations": ["rec1", "rec2"]
}}"""

        resultat = await self.generer_completion(prompt, json_mode=True)
        
        return resultat or {"vulnerabilites_detectees": [], "recommandations": []}

    async def generer_rapport_executif(
        self,
        vulnerabilites: List,
        statistiques: Dict
    ) -> str:
        """
        Génère un résumé exécutif pour le rapport
        
        Args:
            vulnerabilites: Liste des vulnérabilités
            statistiques: Statistiques du scan
            
        Returns:
            str: Résumé exécutif en markdown
        """
        # Résumer les vulnérabilités
        resume_vulns = []
        for v in vulnerabilites[:20]:  # Limiter à 20
            resume_vulns.append({
                'type': v.type,
                'severite': v.severite,
                'url': v.url
            })
        
        prompt = f"""Génère un résumé exécutif professionnel pour ce rapport de sécurité.

Statistiques:
{json.dumps(statistiques, indent=2, ensure_ascii=False)}

Vulnérabilités (échantillon):
{json.dumps(resume_vulns, indent=2, ensure_ascii=False)}

Le résumé doit:
1. Être compréhensible pour des non-techniques
2. Mettre en avant les risques business
3. Prioriser les actions à prendre
4. Être concis (300-500 mots)
5. Utiliser un ton professionnel

Format: Markdown avec sections:
- Vue d'ensemble
- Risques principaux
- Recommandations prioritaires
- Prochaines étapes"""

        resume = await self.generer_completion(prompt)
        
        return resume or "Erreur lors de la génération du résumé"

    def set_modele(self, modele: str):
        """
        Change le modèle OpenAI utilisé
        
        Args:
            modele: Nom du modèle (gpt-4, gpt-3.5-turbo, etc.)
        """
        self.modele = modele
        logger.info(f"Modèle changé pour: {modele}")

    def set_temperature(self, temperature: float):
        """
        Change la température de génération
        
        Args:
            temperature: Valeur entre 0 et 2
        """
        self.temperature = max(0.0, min(2.0, temperature))
        logger.info(f"Température réglée à: {self.temperature}")

