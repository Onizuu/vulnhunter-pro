import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from core.executive_reporting import RapportExecutif
from loguru import logger

class HTMLGenerator:
    """
    Générateur de rapports HTML basés sur des templates Jinja2
    """
    def __init__(self, template_dir: str = "interface_web/templates"):
        self.template_dir = os.path.abspath(template_dir)
        self.env = Environment(loader=FileSystemLoader(self.template_dir))
        logger.info(f"HTMLGenerator initialisé avec le dossier templates: {self.template_dir}")

    def generer_rapport(self, rapport: RapportExecutif, output_dir: str = "rapports/output") -> str:
        """
        Génère le rapport HTML à partir de l'objet RapportExecutif
        
        Args:
            rapport: L'objet RapportExecutif contenant les données
            output_dir: Le dossier de sortie pour le fichier HTML
            
        Returns:
            Le chemin absolu du fichier généré
        """
        try:
            template = self.env.get_template("report_template.html")
            
            # Rendu du template
            html_content = template.render(rapport=rapport)
            
            # Création du dossier de sortie si nécessaire
            os.makedirs(output_dir, exist_ok=True)
            
            # Nom du fichier
            filename = f"rapport_{rapport.id_rapport}.html"
            filepath = os.path.join(output_dir, filename)
            
            # Écriture du fichier
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(html_content)
                
            logger.info(f"Rapport HTML généré avec succès: {filepath}")
            return filepath
            
        except Exception as e:
            logger.error(f"Erreur lors de la génération du rapport HTML: {str(e)}")
            raise e
