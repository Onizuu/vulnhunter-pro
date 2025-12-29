"""
Constructeur de chaînes d'exploitation
Combine plusieurs vulnérabilités pour des exploits plus puissants
"""

from typing import List, Dict
from loguru import logger


class ConstructeurChaines:
    """
    Construit des chaînes d'exploitation à partir de vulnérabilités individuelles
    """

    def __init__(self, client_ia):
        self.client_ia = client_ia

    async def construire_chaines(
        self,
        vulnerabilites: List
    ) -> List[Dict]:
        """
        Construit des chaînes d'exploitation
        
        Args:
            vulnerabilites: Liste des vulnérabilités trouvées
            
        Returns:
            List[Dict]: Chaînes d'exploitation possibles
        """
        chaines = []
        
        try:
            logger.info("🔗 Construction de chaînes d'exploitation...")
            
            # Utiliser l'IA pour suggérer des chaînes
            from core.ai_analyzer import AnalyseurIA
            analyseur = AnalyseurIA(self.client_ia)
            
            chaines_ia = await analyseur.suggerer_chaine_exploit(vulnerabilites)
            chaines.extend(chaines_ia)
            
            # Chaînes prédéfinies connues
            chaines_predefinies = self._identifier_chaines_predefinies(vulnerabilites)
            chaines.extend(chaines_predefinies)
            
            logger.info(f"✅ {len(chaines)} chaînes d'exploitation identifiées")
            
            return chaines
        
        except Exception as e:
            logger.error(f"Erreur construction chaînes: {str(e)}")
            return []

    def _identifier_chaines_predefinies(
        self,
        vulnerabilites: List
    ) -> List[Dict]:
        """
        Identifie les chaînes d'exploitation prédéfinies
        """
        chaines = []
        
        types_vulns = [v.type for v in vulnerabilites]
        
        # Chaîne: XSS + CSRF -> Vol de session
        if 'XSS' in types_vulns and 'CORS' not in types_vulns:
            chaines.append({
                'nom': 'XSS vers Vol de Session',
                'vulnerabilites_utilisees': ['XSS'],
                'etapes': [
                    'Injecter XSS pour voler le cookie de session',
                    'Envoyer le cookie vers serveur attaquant',
                    'Utiliser le cookie pour usurper l\'identité'
                ],
                'impact': 'Compromission totale du compte utilisateur',
                'severite': 'CRITIQUE'
            })
        
        # Chaîne: IDOR + Info Disclosure -> Élévation de privilèges
        if 'IDOR' in types_vulns:
            chaines.append({
                'nom': 'IDOR vers Élévation de Privilèges',
                'vulnerabilites_utilisees': ['IDOR'],
                'etapes': [
                    'Énumérer les IDs utilisateur via IDOR',
                    'Accéder aux comptes administrateurs',
                    'Compromettre le système'
                ],
                'impact': 'Accès administrateur complet',
                'severite': 'CRITIQUE'
            })
        
        # Chaîne: SQLi -> RCE
        if 'Injection SQL' in types_vulns:
            chaines.append({
                'nom': 'SQL Injection vers RCE',
                'vulnerabilites_utilisees': ['Injection SQL'],
                'etapes': [
                    'Exploiter SQLi pour accéder à la base',
                    'Utiliser xp_cmdshell ou INTO OUTFILE',
                    'Uploader un webshell',
                    'Exécuter des commandes système'
                ],
                'impact': 'Contrôle total du serveur',
                'severite': 'CRITIQUE'
            })
        
        return chaines

