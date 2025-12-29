"""
Gestionnaire de budget pour Claude API
Limite les coûts à 5€ maximum par scan
"""

from typing import Dict
from loguru import logger


class GestionnaireBudget:
    """
    Gère le budget Claude API (5€ max par scan par défaut)
    """
    
    def __init__(self, budget_max_euros: float = 5.0):
        """
        Initialise le gestionnaire de budget
        
        Args:
            budget_max_euros: Budget maximum en euros (défaut: 5€)
        """
        self.budget_max = budget_max_euros
        self.budget_utilise = 0.0
        self.appels_claude = 0
        self.appels_ollama = 0
        
        # Coût estimé par token Claude (moyenne)
        # Claude 3.5 Sonnet: ~$0.003-0.015 par 1K tokens (input/output)
        # On prend une moyenne conservatrice
        self.cout_par_1k_tokens = 0.015  # $0.015 = ~0.014€
        
        logger.info(f"💰 Budget Claude configuré: {budget_max_euros}€ max par scan")
    
    def estimer_cout(self, tokens_estimes: int) -> float:
        """
        Estime le coût d'un appel Claude
        
        Args:
            tokens_estimes: Nombre de tokens estimés (input + output)
            
        Returns:
            Coût estimé en euros
        """
        return (tokens_estimes / 1000) * self.cout_par_1k_tokens
    
    def peut_utiliser_claude(self, tokens_estimes: int = 1500) -> bool:
        """
        Vérifie si on peut utiliser Claude dans le budget
        
        Args:
            tokens_estimes: Tokens estimés pour l'appel (input + output)
            
        Returns:
            True si dans le budget, False sinon
        """
        cout_estime = self.estimer_cout(tokens_estimes)
        
        if (self.budget_utilise + cout_estime) <= self.budget_max:
            return True
        
        logger.warning(
            f"⚠️  Budget Claude dépassé: {self.budget_utilise:.2f}€ / {self.budget_max}€ "
            f"(coût estimé: {cout_estime:.2f}€)"
        )
        return False
    
    def enregistrer_appel_claude(self, tokens_reels: int):
        """
        Enregistre un appel Claude et met à jour le budget
        
        Args:
            tokens_reels: Nombre de tokens réellement utilisés (input + output)
        """
        cout = self.estimer_cout(tokens_reels)
        self.budget_utilise += cout
        self.appels_claude += 1
        
        logger.debug(
            f"💰 Budget Claude: {self.budget_utilise:.2f}€ / {self.budget_max}€ "
            f"({self.appels_claude} appels, ~{int(tokens_reels)} tokens)"
        )
        
        # Avertissement si on approche de la limite
        pourcentage = (self.budget_utilise / self.budget_max) * 100
        if pourcentage >= 80:
            logger.warning(
                f"⚠️  Budget Claude à {pourcentage:.1f}%: {self.budget_utilise:.2f}€ / {self.budget_max}€"
            )
    
    def enregistrer_appel_ollama(self):
        """Enregistre un appel Ollama (gratuit)"""
        self.appels_ollama += 1
    
    def get_statistiques(self) -> Dict:
        """
        Retourne les statistiques d'utilisation
        
        Returns:
            Dict avec statistiques de budget
        """
        budget_restant = max(0, self.budget_max - self.budget_utilise)
        pourcentage = (self.budget_utilise / self.budget_max) * 100 if self.budget_max > 0 else 0
        
        return {
            'budget_utilise': round(self.budget_utilise, 2),
            'budget_max': self.budget_max,
            'budget_restant': round(budget_restant, 2),
            'appels_claude': self.appels_claude,
            'appels_ollama': self.appels_ollama,
            'pourcentage_budget': round(pourcentage, 1),
            'total_appels': self.appels_claude + self.appels_ollama
        }
    
    def reset(self):
        """Réinitialise le budget pour un nouveau scan"""
        stats_avant = self.get_statistiques()
        self.budget_utilise = 0.0
        self.appels_claude = 0
        self.appels_ollama = 0
        logger.info(
            f"💰 Budget réinitialisé pour nouveau scan "
            f"(précédent: {stats_avant['appels_claude']} Claude, {stats_avant['appels_ollama']} Ollama)"
        )

