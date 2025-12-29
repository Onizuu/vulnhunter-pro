"""
Client IA avec fallback intelligent Ollama → Claude
Utilise Ollama principalement (gratuit), Claude uniquement quand nécessaire (budget limité)
"""

import json
import re
from typing import Optional, Dict, List, Union
from loguru import logger

from integration_ia.ollama_client import ClientOllama
from integration_ia.budget_manager import GestionnaireBudget


class ClientIAFallback:
    """
    Client IA avec fallback intelligent Ollama → Claude
    Utilise Ollama principalement, Claude uniquement quand nécessaire (budget 5€ max)
    """
    
    def __init__(
        self,
        ollama_model: str = "mistral:7b",
        claude_api_key: Optional[str] = None,
        budget_max: float = 5.0
    ):
        """
        Initialise le client avec fallback
        
        Args:
            ollama_model: Modèle Ollama à utiliser (défaut: mistral:7b)
            claude_api_key: Clé API Claude (Anthropic) - optionnel
            budget_max: Budget maximum Claude en euros (défaut: 5€)
        """
        self.client_ollama = ClientOllama(model=ollama_model)
        self.client_claude = None
        self.budget_manager = GestionnaireBudget(budget_max_euros=budget_max)
        
        # Initialiser Claude si clé fournie
        if claude_api_key:
            try:
                import anthropic
                self.client_claude = anthropic.Anthropic(api_key=claude_api_key)
                logger.info("✅ Client Claude initialisé (fallback disponible)")
            except ImportError:
                logger.warning("⚠️  Anthropic SDK non installé - Claude désactivé")
                logger.info("💡 Installez: pip install anthropic")
            except Exception as e:
                logger.warning(f"⚠️  Erreur initialisation Claude: {str(e)}")
        else:
            logger.info("💡 Claude non configuré - Utilisation Ollama uniquement (gratuit)")
        
        self.disponible = self.client_ollama.disponible
        
        # Compteurs pour décision de fallback
        self.echecs_ollama = {}  # {contexte: nombre_échecs}
        self.waf_sophistiques_detectes = set()
    
    def _doit_utiliser_claude(
        self,
        contexte: str,
        waf_detecte: Optional[str] = None,
        est_zeroday: bool = False,
        est_exploit_final: bool = False
    ) -> bool:
        """
        Détermine si on doit utiliser Claude au lieu d'Ollama
        
        Critères pour utiliser Claude:
        1. WAF sophistiqué détecté (Cloudflare, AWS WAF, ModSecurity)
        2. 0-day critique
        3. Exploit final pour vulnérabilité confirmée
        4. Échecs répétés avec Ollama (>3)
        5. Budget disponible
        
        Args:
            contexte: Contexte de la requête
            waf_detecte: Type de WAF détecté
            est_zeroday: Si c'est une 0-day
            est_exploit_final: Si c'est un exploit final
            
        Returns:
            True si Claude doit être utilisé
        """
        # Si Claude non disponible, utiliser Ollama
        if not self.client_claude:
            return False
        
        # Vérifier le budget d'abord
        if not self.budget_manager.peut_utiliser_claude():
            return False
        
        # Critère 1: WAF sophistiqué
        waf_sophistiques = ['cloudflare', 'aws waf', 'modsecurity', 'akamai', 'imperva', 'f5']
        if waf_detecte and any(waf in waf_detecte.lower() for waf in waf_sophistiques):
            logger.info(f"🎯 WAF sophistiqué détecté ({waf_detecte}) → Utilisation Claude")
            return True
        
        # Critère 2: 0-day critique
        if est_zeroday:
            logger.info("🎯 0-day critique → Utilisation Claude")
            return True
        
        # Critère 3: Exploit final
        if est_exploit_final:
            logger.info("🎯 Exploit final → Utilisation Claude")
            return True
        
        # Critère 4: Échecs répétés Ollama
        echecs = self.echecs_ollama.get(contexte, 0)
        if echecs >= 3:
            logger.info(f"🎯 {echecs} échecs Ollama pour {contexte} → Utilisation Claude")
            return True
        
        # Sinon, utiliser Ollama (gratuit)
        return False
    
    async def generer_completion(
        self,
        prompt: str,
        json_mode: bool = False,
        temperature: Optional[float] = None,
        contexte: str = "",
        waf_detecte: Optional[str] = None,
        est_zeroday: bool = False,
        est_exploit_final: bool = False
    ) -> Optional[Union[str, Dict]]:
        """
        Génère une completion avec fallback intelligent
        
        Args:
            prompt: Prompt à envoyer
            json_mode: Si True, force JSON
            temperature: Température
            contexte: Contexte pour décision de fallback
            waf_detecte: WAF détecté
            est_zeroday: Si 0-day
            est_exploit_final: Si exploit final
            
        Returns:
            Réponse générée
        """
        # Décider quel client utiliser
        utiliser_claude = self._doit_utiliser_claude(
            contexte, waf_detecte, est_zeroday, est_exploit_final
        )
        
        if utiliser_claude and self.client_claude:
            # Utiliser Claude
            try:
                logger.debug("🤖 Utilisation Claude (fallback intelligent)")
                response = await self._appel_claude(prompt, json_mode, temperature)
                
                if response:
                    # Estimer les tokens (approximation: ~1.3 tokens par mot)
                    tokens_input = len(prompt.split()) * 1.3
                    tokens_output = len(str(response).split()) * 1.3
                    tokens_totaux = int(tokens_input + tokens_output)
                    
                    self.budget_manager.enregistrer_appel_claude(tokens_totaux)
                    return response
                else:
                    # Si Claude échoue, essayer Ollama
                    logger.warning("⚠️  Claude échoué, basculement vers Ollama")
                    return await self._appel_ollama(prompt, json_mode, temperature, contexte)
                    
            except Exception as e:
                logger.error(f"Erreur Claude: {str(e)}, basculement vers Ollama")
                return await self._appel_ollama(prompt, json_mode, temperature, contexte)
        else:
            # Utiliser Ollama (gratuit)
            return await self._appel_ollama(prompt, json_mode, temperature, contexte)
    
    async def _appel_ollama(
        self,
        prompt: str,
        json_mode: bool,
        temperature: Optional[float],
        contexte: str
    ) -> Optional[Union[str, Dict]]:
        """Appel Ollama avec gestion d'échecs"""
        try:
            resultat = await self.client_ollama.generer_completion(prompt, json_mode, temperature)
            self.budget_manager.enregistrer_appel_ollama()
            
            if resultat:
                # Réinitialiser les échecs si succès
                if contexte in self.echecs_ollama:
                    del self.echecs_ollama[contexte]
                return resultat
            else:
                # Enregistrer l'échec
                self.echecs_ollama[contexte] = self.echecs_ollama.get(contexte, 0) + 1
                logger.debug(f"Échec Ollama pour {contexte} (tentative {self.echecs_ollama[contexte]})")
                return None
                
        except Exception as e:
            logger.error(f"Erreur Ollama: {str(e)}")
            self.echecs_ollama[contexte] = self.echecs_ollama.get(contexte, 0) + 1
            return None
    
    async def _appel_claude(
        self,
        prompt: str,
        json_mode: bool,
        temperature: Optional[float]
    ) -> Optional[Union[str, Dict]]:
        """Appel Claude API"""
        try:
            messages = [
                {
                    "role": "user",
                    "content": prompt
                }
            ]
            
            # Utiliser Claude 3.5 Sonnet (bon équilibre qualité/coût)
            response = self.client_claude.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=4000,
                temperature=temperature or 0.7,
                messages=messages
            )
            
            contenu = response.content[0].text
            
            if json_mode:
                try:
                    return json.loads(contenu)
                except json.JSONDecodeError:
                    # Essayer d'extraire le JSON
                    json_match = re.search(r'\{.*\}', contenu, re.DOTALL)
                    if json_match:
                        return json.loads(json_match.group())
                    return None
            
            return contenu
            
        except Exception as e:
            logger.error(f"Erreur appel Claude: {str(e)}")
            return None
    
    async def generer_payloads_sqli(
        self,
        contexte: str,
        dbms: Optional[str] = None,
        filtres: Optional[List[str]] = None
    ) -> List[str]:
        """
        Génère des payloads SQL avec fallback intelligent
        
        Args:
            contexte: Contexte de l'injection
            dbms: Type de SGBD
            filtres: Filtres WAF détectés
            
        Returns:
            List[str]: Payloads générés
        """
        waf_detecte = None
        if filtres:
            waf_detecte = filtres[0] if filtres else None
        
        prompt = f"""Génère 30 payloads d'injection SQL avancés pour contourner les WAF modernes.

Contexte: {contexte}
SGBD: {dbms or 'inconnu'}
Filtres WAF: {', '.join(filtres) if filtres else 'aucun'}

Les payloads doivent:
1. Contourner les filtres WAF (Cloudflare, AWS WAF, ModSecurity)
2. Utiliser des techniques d'obfuscation variées
3. Inclure des payloads temporels et basés sur erreur
4. Tester l'extraction de données
5. Être fonctionnels

Retourne uniquement un JSON:
{{
    "payloads": ["payload1", "payload2", ...]
}}"""
        
        resultat = await self.generer_completion(
            prompt,
            json_mode=True,
            contexte=f"SQLi: {contexte}",
            waf_detecte=waf_detecte
        )
        
        if resultat and 'payloads' in resultat:
            return resultat['payloads']
        
        return []
    
    async def generer_payloads_xss(
        self,
        contexte: str,
        filtres: Optional[List[str]] = None
    ) -> List[str]:
        """
        Génère des payloads XSS avec fallback intelligent
        
        Args:
            contexte: Contexte (HTML, JavaScript, attribut, etc.)
            filtres: Filtres détectés
            
        Returns:
            List[str]: Payloads XSS
        """
        waf_detecte = None
        if filtres:
            waf_detecte = filtres[0] if filtres else None
        
        prompt = f"""Génère 30 payloads XSS innovants pour contourner les filtres modernes.

Contexte: {contexte}
Filtres: {', '.join(filtres) if filtres else 'aucun'}

Les payloads doivent:
1. Contourner CSP (Content Security Policy)
2. Fonctionner dans différents contextes
3. Utiliser l'obfuscation avancée
4. Éviter les mots-clés courants bloqués
5. Inclure des variantes DOM-based

Retourne uniquement un JSON:
{{
    "payloads": ["payload1", "payload2", ...]
}}"""
        
        resultat = await self.generer_completion(
            prompt,
            json_mode=True,
            contexte=f"XSS: {contexte}",
            waf_detecte=waf_detecte
        )
        
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
        """
        return await self.client_ollama.analyser_reponse_pour_vuln(url, requete, reponse, headers)
    
    async def generer_rapport_executif(
        self,
        vulnerabilites: List,
        statistiques: Dict
    ) -> str:
        """
        Génère un résumé exécutif pour le rapport
        """
        return await self.client_ollama.generer_rapport_executif(vulnerabilites, statistiques)
    
    def get_statistiques_budget(self) -> Dict:
        """
        Retourne les statistiques de budget
        
        Returns:
            Dict avec statistiques
        """
        return self.budget_manager.get_statistiques()
    
    def reset_budget(self):
        """Réinitialise le budget pour un nouveau scan"""
        self.budget_manager.reset()

