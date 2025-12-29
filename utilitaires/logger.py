"""
Configuration du système de logging
"""

import sys
from pathlib import Path
from loguru import logger


def ConfigurerLogger(niveau="INFO", fichier_log="logs/vulnhunter.log", sink=None):
    """
    Configure le système de logging avec loguru
    
    Args:
        niveau: Niveau de log (DEBUG, INFO, WARNING, ERROR)
        fichier_log: Chemin du fichier de log
        sink: Sink personnalisé optionnel (ex: pour WebSocket)
    """
    # Supprimer les handlers par défaut
    logger.remove()
    
    # Console avec couleurs
    logger.add(
        sys.stdout,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan> - <level>{message}</level>",
        level=niveau,
        colorize=True
    )
    
    # Fichier de log
    Path(fichier_log).parent.mkdir(parents=True, exist_ok=True)
    logger.add(
        fichier_log,
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function} - {message}",
        level=niveau,
        rotation="10 MB",
        retention="7 days",
        compression="zip"
    )
    # Fichier de log d'erreurs (pour debugging facile)
    logger.add(
        "logs/errors.log",
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function} - {message}",
        level="ERROR",
        rotation="5 MB",
        retention="3 days"  # Garder seulement les récents
    )
    
    
    # Sink personnalisé (ex: WebSocket)
    if sink:
        logger.add(
            sink,
            format="{time:HH:mm:ss} | {level: <8} | {message}",
            level=niveau
        )
    
    logger.info("Logger configuré avec succès")
    
    return logger

