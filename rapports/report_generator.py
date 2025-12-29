"""
Générateur de rapports PDF/HTML professionnels
"""

import os
from datetime import datetime
from pathlib import Path
from typing import Optional
from loguru import logger
from jinja2 import Environment, FileSystemLoader


class GenerateurRapports:
    """
    Génère des rapports professionnels au format PDF et HTML
    """

    def __init__(self, dossier_templates: str = "rapports/templates"):
        """
        Initialise le générateur de rapports
        
        Args:
            dossier_templates: Dossier contenant les templates Jinja2
        """
        self.dossier_templates = dossier_templates
        self.env = Environment(loader=FileSystemLoader(dossier_templates))
        
        # Créer le dossier de sortie
        self.dossier_sortie = Path("rapports/output")
        self.dossier_sortie.mkdir(parents=True, exist_ok=True)

    def generer_rapport_complet(
        self,
        rapport_scan,
        format_sortie: str = "html"
    ) -> str:
        """
        Génère un rapport complet
        
        Args:
            rapport_scan: Objet RapportScan
            format_sortie: Format (html, pdf, json)
            
        Returns:
            str: Chemin du fichier généré
        """
        try:
            logger.info(f"📊 Génération du rapport ({format_sortie})...")
            
            # Préparer les données
            donnees = self._preparer_donnees(rapport_scan)
            
            if format_sortie == "html":
                return self._generer_html(donnees, "technique.html", "rapport_technique")
            elif format_sortie == "pdf":
                return self._generer_pdf(donnees)
            elif format_sortie == "json":
                return self._generer_json(donnees)
            else:
                raise ValueError(f"Format non supporté: {format_sortie}")
        
        except Exception as e:
            logger.error(f"Erreur génération rapport: {str(e)}")
            raise

    def generer_resume_executif(self, rapport_scan) -> str:
        """
        Génère un résumé exécutif pour la direction
        
        Args:
            rapport_scan: Objet RapportScan
            
        Returns:
            str: Chemin du fichier HTML généré
        """
        try:
            logger.info("📊 Génération du résumé exécutif...")
            
            donnees = self._preparer_donnees(rapport_scan)
            donnees['type_rapport'] = 'executif'
            
            return self._generer_html(donnees, "executif.html", "resume_executif")
        
        except Exception as e:
            logger.error(f"Erreur génération résumé: {str(e)}")
            raise

    def _preparer_donnees(self, rapport_scan) -> dict:
        """
        Prépare les données pour les templates
        
        Args:
            rapport_scan: Objet RapportScan
            
        Returns:
            dict: Données formatées
        """
        # Statistiques par sévérité
        stats_severite = {
            'CRITIQUE': 0,
            'ÉLEVÉ': 0,
            'HAUTE': 0,
            'HIGH': 0,
            'MOYEN': 0,
            'MOYENNE': 0,
            'MEDIUM': 0,
            'FAIBLE': 0,
            'BASSE': 0,
            'LOW': 0,
            'INFO': 0
        }
        
        for vuln in rapport_scan.vulnerabilites:
            stats_severite[vuln.severite] = stats_severite.get(vuln.severite, 0) + 1
        
        # Statistiques par type
        stats_type = {}
        for vuln in rapport_scan.vulnerabilites:
            stats_type[vuln.type] = stats_type.get(vuln.type, 0) + 1
        
        return {
            'titre': f"Rapport de Scan - {rapport_scan.url_cible}",
            'date_generation': datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
            'url_cible': rapport_scan.url_cible,
            'date_debut': rapport_scan.date_debut.strftime("%d/%m/%Y %H:%M:%S"),
            'date_fin': rapport_scan.date_fin.strftime("%d/%m/%Y %H:%M:%S"),
            'duree': f"{rapport_scan.duree:.2f}",
            'score_risque': rapport_scan.score_risque_global,
            'nb_vulnerabilites': len(rapport_scan.vulnerabilites),
            'stats_severite': stats_severite,
            'stats_type': stats_type,
            'vulnerabilites': rapport_scan.vulnerabilites,
            'chaines_exploit': rapport_scan.chaines_exploit,
            'donnees_recon': rapport_scan.donnees_recon,
            'statistiques': rapport_scan.statistiques
        }

    def _generer_html(self, donnees: dict, template: str, prefixe: str = "rapport") -> str:
        """
        Génère un rapport HTML
        
        Args:
            donnees: Données du rapport
            template: Nom du template à utiliser
            prefixe: Préfixe pour le nom de fichier
            
        Returns:
            str: Chemin du fichier HTML
        """
        try:
            # Charger le template
            template_obj = self.env.get_template(template)
            
            # Rendre le template
            html = template_obj.render(**donnees)
            
            # Sauvegarder avec un nom unique basé sur le type
            nom_fichier = f"{prefixe}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            chemin_fichier = self.dossier_sortie / nom_fichier
            
            with open(chemin_fichier, 'w', encoding='utf-8') as f:
                f.write(html)
            
            logger.success(f"✅ Rapport HTML généré: {chemin_fichier}")
            return str(chemin_fichier)
        
        except Exception as e:
            logger.error(f"Erreur génération HTML: {str(e)}")
            raise

    def _generer_pdf(self, donnees: dict) -> str:
        """
        Génère un rapport PDF
        
        Args:
            donnees: Données du rapport
            
        Returns:
            str: Chemin du fichier PDF
        """
        try:
            # Générer d'abord le HTML
            chemin_html = self._generer_html(donnees, "technique.html", "rapport_technique")
            
            # Convertir en PDF avec weasyprint
            from weasyprint import HTML
            
            chemin_pdf = chemin_html.replace('.html', '.pdf')
            HTML(chemin_html).write_pdf(chemin_pdf)
            
            logger.success(f"✅ Rapport PDF généré: {chemin_pdf}")
            return chemin_pdf
        
        except Exception as e:
            logger.error(f"Erreur génération PDF: {str(e)}")
            # Retourner le HTML si PDF échoue
            return self._generer_html(donnees, "technique.html", "rapport_technique")

    def _generer_json(self, donnees: dict) -> str:
        """
        Génère un rapport JSON
        
        Args:
            donnees: Données du rapport
            
        Returns:
            str: Chemin du fichier JSON
        """
        import json
        
        try:
            nom_fichier = f"rapport_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            chemin_fichier = self.dossier_sortie / nom_fichier
            
            # Convertir les objets en dict
            donnees_json = self._convertir_pour_json(donnees)
            
            with open(chemin_fichier, 'w', encoding='utf-8') as f:
                json.dump(donnees_json, f, indent=2, ensure_ascii=False, default=str)
            
            logger.success(f"✅ Rapport JSON généré: {chemin_fichier}")
            return str(chemin_fichier)
        
        except Exception as e:
            logger.error(f"Erreur génération JSON: {str(e)}")
            raise

    def _convertir_pour_json(self, obj):
        """
        Convertit les objets pour sérialisation JSON
        """
        if hasattr(obj, '__dict__'):
            return {
                k: self._convertir_pour_json(v)
                for k, v in obj.__dict__.items()
                if not k.startswith('_')
            }
        elif isinstance(obj, list):
            return [self._convertir_pour_json(item) for item in obj]
        elif isinstance(obj, dict):
            return {
                k: self._convertir_pour_json(v)
                for k, v in obj.items()
            }
        elif isinstance(obj, (datetime,)):
            return obj.isoformat()
        else:
            return obj

