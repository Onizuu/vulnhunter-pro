"""
Système de notifications (Discord, Slack, Telegram)
"""

import os
import aiohttp
from typing import Optional
from loguru import logger


class GestionnaireNotifications:
    """
    Envoie des notifications sur différentes plateformes
    """

    def __init__(self):
        self.discord_webhook = os.getenv('DISCORD_WEBHOOK')
        self.slack_webhook = os.getenv('SLACK_WEBHOOK')
        self.telegram_token = os.getenv('TELEGRAM_BOT_TOKEN')
        self.telegram_chat_id = os.getenv('TELEGRAM_CHAT_ID')

    async def envoyer_discord(self, message: str, urgent: bool = False):
        """
        Envoie une notification Discord
        
        Args:
            message: Message à envoyer
            urgent: Si True, marque comme urgent
        """
        if not self.discord_webhook:
            return
        
        try:
            prefix = "🚨 **URGENT** 🚨\n" if urgent else ""
            payload = {
                "content": f"{prefix}{message}",
                "username": "VulnHunter Pro"
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.discord_webhook,
                    json=payload
                ) as response:
                    if response.status == 204:
                        logger.debug("Notification Discord envoyée")
        
        except Exception as e:
            logger.error(f"Erreur notification Discord: {str(e)}")

    async def envoyer_slack(self, message: str, urgent: bool = False):
        """
        Envoie une notification Slack
        
        Args:
            message: Message à envoyer
            urgent: Si True, marque comme urgent
        """
        if not self.slack_webhook:
            return
        
        try:
            prefix = "🚨 *URGENT* 🚨\n" if urgent else ""
            payload = {
                "text": f"{prefix}{message}"
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.slack_webhook,
                    json=payload
                ) as response:
                    if response.status == 200:
                        logger.debug("Notification Slack envoyée")
        
        except Exception as e:
            logger.error(f"Erreur notification Slack: {str(e)}")

    async def envoyer_telegram(self, message: str, urgent: bool = False):
        """
        Envoie une notification Telegram
        
        Args:
            message: Message à envoyer
            urgent: Si True, marque comme urgent
        """
        if not self.telegram_token or not self.telegram_chat_id:
            return
        
        try:
            url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
            
            prefix = "🚨 URGENT 🚨\n" if urgent else ""
            payload = {
                "chat_id": self.telegram_chat_id,
                "text": f"{prefix}{message}",
                "parse_mode": "Markdown"
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload) as response:
                    if response.status == 200:
                        logger.debug("Notification Telegram envoyée")
        
        except Exception as e:
            logger.error(f"Erreur notification Telegram: {str(e)}")

    async def notifier_vulnerabilite_critique(self, vulnerabilite):
        """
        Notifie une vulnérabilité critique sur toutes les plateformes
        
        Args:
            vulnerabilite: Objet Vulnerabilite
        """
        message = f"""
🎯 **Vulnérabilité Critique Détectée**

Type: {vulnerabilite.type}
Sévérité: {vulnerabilite.severite}
URL: {vulnerabilite.url}
CVSS: {vulnerabilite.cvss_score}

Description: {vulnerabilite.description}

Payload: `{vulnerabilite.payload[:100]}`
"""
        
        await self.envoyer_discord(message, urgent=True)
        await self.envoyer_slack(message, urgent=True)
        await self.envoyer_telegram(message, urgent=True)
        
        logger.info("Notifications envoyées pour vulnérabilité critique")

