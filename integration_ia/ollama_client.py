"""
Client Ollama pour génération de payloads et analyse (IA locale gratuite)
"""

import os
import json
import re
import asyncio
from typing import Optional, Dict, List, Union
from loguru import logger
import aiohttp


class ClientOllama:
    """
    Client pour Ollama (IA locale gratuite)
    Utilise des modèles locaux comme Mistral 7B, CodeLlama, etc.
    """

    def __init__(self, base_url: str = "http://localhost:11434", model: str = "mistral:7b"):
        """
        Initialise le client Ollama
        
        Args:
            base_url: URL de l'API Ollama (par défaut localhost:11434)
            model: Modèle à utiliser (mistral:7b recommandé pour cybersécurité)
        """
        self.base_url = base_url
        self.model = model
        self.disponible = False
        
        # Tester la connexion
        try:
            import requests
            response = requests.get(f"{base_url}/api/tags", timeout=5)
            if response.status_code == 200:
                # Vérifier que le modèle est disponible
                models = response.json().get('models', [])
                model_names = [m.get('name', '') for m in models]
                
                if any(model in name for name in model_names):
                    self.disponible = True
                    logger.info(f"✅ Client Ollama initialisé (modèle: {model})")
                else:
                    logger.warning(f"⚠️  Modèle {model} non trouvé dans Ollama")
                    logger.info(f"💡 Modèles disponibles: {', '.join(model_names[:5]) if model_names else 'Aucun'}")
                    logger.info(f"💡 Installez le modèle: ollama pull {model}")
                    # Essayer quand même (le modèle pourrait être chargé dynamiquement)
                    self.disponible = True
                    logger.warning("⚠️  Tentative de connexion malgré modèle non trouvé")
            else:
                logger.warning(f"⚠️  Ollama non accessible (status: {response.status_code})")
        except requests.exceptions.ConnectionError as e:
            logger.warning(f"⚠️  Ollama non accessible: {str(e)}")
            logger.info("💡 Vérifiez que Ollama est démarré: ollama serve")
        except requests.exceptions.Timeout:
            logger.warning("⚠️  Timeout lors de la connexion à Ollama")
        except ImportError:
            logger.warning("⚠️  Bibliothèque 'requests' non disponible pour test Ollama")
            # Essayer quand même avec aiohttp
            self.disponible = True
            logger.info(f"✅ Client Ollama initialisé (modèle: {model}) - Test de connexion différé")
        except Exception as e:
            logger.warning(f"⚠️  Ollama non disponible: {type(e).__name__}: {str(e)}")
            logger.info("💡 Installez Ollama: brew install ollama")
            logger.info(f"💡 Puis: ollama serve && ollama pull {model}")
        
        self.temperature = 0.7
        self.max_tokens = 4000

    async def generer_completion(
        self,
        prompt: str,
        json_mode: bool = False,
        temperature: Optional[float] = None
    ) -> Optional[Union[str, Dict]]:
        """
        Génère une completion avec Ollama
        
        Args:
            prompt: Le prompt à envoyer
            json_mode: Si True, force la réponse en JSON
            temperature: Température de génération
            
        Returns:
            str|Dict: Réponse générée ou None si erreur
        """
        if not self.disponible:
            logger.warning("Client Ollama non disponible")
            return None
        
        try:
            url = f"{self.base_url}/api/generate"
            
            # Améliorer le prompt pour JSON si nécessaire
            if json_mode:
                prompt = f"""{prompt}

IMPORTANT: Réponds UNIQUEMENT avec un JSON valide, sans texte avant ou après.
Format JSON attendu: {{"payloads": ["payload1", "payload2", ...]}}"""
            
            payload = {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": temperature or self.temperature,
                    "num_predict": self.max_tokens
                }
            }
            
            async with aiohttp.ClientSession() as session:
                try:
                    # ⭐ Timeout augmenté : laisser Ollama prendre son temps (local = gratuit)
                    timeout_seconds = 90  # 90s pour laisser l'IA locale travailler
                    async with session.post(
                        url,
                        json=payload,
                        timeout=aiohttp.ClientTimeout(total=timeout_seconds)
                    ) as resp:
                        if resp.status == 200:
                            try:
                                data = await resp.json()
                            except Exception as je:
                                error_text = await resp.text()
                                logger.error(f"Erreur parsing JSON réponse Ollama: {type(je).__name__}: {str(je)}")
                                logger.debug(f"Réponse brute (200 premiers chars): {error_text[:200]}")
                                return None
                            
                            contenu = data.get('response', '').strip()
                            
                            if not contenu:
                                logger.warning("Réponse Ollama vide (pas de contenu dans 'response')")
                                logger.debug(f"Données reçues: {list(data.keys())}")
                                return None
                            
                            if json_mode:
                                try:
                                    return json.loads(contenu)
                                except json.JSONDecodeError:
                                    # Essayer d'extraire le JSON de la réponse
                                    json_match = re.search(r'\{.*\}', contenu, re.DOTALL)
                                    if json_match:
                                        try:
                                            return json.loads(json_match.group())
                                        except json.JSONDecodeError as je:
                                            logger.debug(f"JSON invalide extrait: {str(je)}")
                                    logger.debug(f"Réponse JSON invalide de Ollama (premiers 200 chars): {contenu[:200]}")
                                    return None
                            
                            return contenu
                        else:
                            error_text = await resp.text()
                            logger.error(f"Erreur HTTP Ollama: {resp.status} - {error_text[:200]}")
                            return None
                except aiohttp.ClientConnectorError as e:
                    error_msg = str(e) if str(e) else f"Connexion refusée à {self.base_url}"
                    logger.error(f"Impossible de se connecter à Ollama ({self.base_url}): {error_msg}")
                    logger.info("💡 Vérifiez que Ollama est démarré: ollama serve")
                    return None
                except asyncio.TimeoutError:
                    logger.warning(f"Timeout Ollama ({timeout_seconds}s) - Réponse très lente, utilisation de payloads de base")
                    logger.debug(f"Détails: URL={url}, Model={self.model}, Prompt length={len(prompt)}")
                    return None  # Retourner None pour utiliser les payloads de base
                except aiohttp.ClientError as e:
                    error_msg = str(e) if str(e) else f"Erreur client HTTP {type(e).__name__}"
                    logger.error(f"Erreur connexion Ollama: {type(e).__name__}: {error_msg}")
                    logger.debug(f"Détails: URL={url}, Model={self.model}")
                    if hasattr(e, 'message'):
                        logger.debug(f"Message exception: {e.message}")
                    if hasattr(e, 'status'):
                        logger.debug(f"Status: {e.status}")
                    return None
                        
        except json.JSONDecodeError as e:
            logger.error(f"Erreur parsing JSON Ollama: {str(e)}")
            return None
        except Exception as e:
            error_msg = str(e) if str(e) else f"Exception {type(e).__name__} sans message"
            logger.error(f"Erreur inattendue Ollama: {type(e).__name__}: {error_msg}")
            import traceback
            logger.debug(f"Traceback complet:\n{traceback.format_exc()}")
            # Si le message est vide, afficher plus d'infos
            if not str(e):
                logger.error(f"Détails exception: {repr(e)}")
                logger.error(f"Attributs: {dir(e)}")
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
        Change le modèle Ollama utilisé
        
        Args:
            modele: Nom du modèle (mistral:7b, codellama:7b, etc.)
        """
        self.model = modele
        logger.info(f"Modèle Ollama changé pour: {modele}")

    def set_temperature(self, temperature: float):
        """
        Change la température de génération
        
        Args:
            temperature: Valeur entre 0 et 2
        """
        self.temperature = max(0.0, min(2.0, temperature))
        logger.info(f"Température Ollama réglée à: {self.temperature}")

