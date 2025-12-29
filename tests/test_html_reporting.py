import unittest
import os
from datetime import datetime
from core.executive_reporting import RapportExecutif, MetriquesCle, ResumeExecutif, RisqueCritique, Recommandation
from core.html_generator import HTMLGenerator
from core.models import Vulnerabilite

class TestHTMLReporting(unittest.TestCase):
    def setUp(self):
        self.output_dir = "tests/output"
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Données factices pour le rapport
        self.rapport = RapportExecutif(
            id_rapport="TEST-001",
            date_generation=datetime.now(),
            url_cible="http://test.local",
            titre="Rapport de Test",
            resume_executif=ResumeExecutif(
                situation_generale="Ceci est un test de génération de rapport.",
                points_forts=["Authentification robuste"],
                points_faibles=["XSS détecté"],
                score_global=75.5
            ),
            metriques_cle=MetriquesCle(
                total_vulnerabilites=5,
                distribution_severite={'CRITIQUE': 1, 'ÉLEVÉ': 2, 'MOYEN': 1, 'FAIBLE': 1},
                top_types=[{'type': 'XSS', 'count': 2}, {'type': 'SQLi', 'count': 1}],
                score_risque_global=75.5,
                temps_scan=120.0
            ),
            risques_critiques=[
                RisqueCritique(
                    description="Injection SQL",
                    impact="Accès total à la base de données",
                    localisation="/api/login",
                    urgence="Immédiate"
                )
            ],
            recommandations_prioritaires=[
                Recommandation(
                    action="Sanitiser les entrées",
                    priorite="Haute",
                    impact="Réduit le risque d'injection",
                    difficulte="Moyenne"
                )
            ],
            vulnerabilites=[
                Vulnerabilite(
                    type="SQL Injection",
                    url="http://test.local/login",
                    severite="CRITIQUE",
                    description="Faille SQL dans le paramètre user",
                    payload="' OR 1=1 --",
                    remediation="Utiliser des requêtes préparées"
                )
            ]
        )

    def test_generation_html(self):
        generator = HTMLGenerator()
        filepath = generator.generer_rapport(self.rapport, output_dir=self.output_dir)
        
        print(f"Rapport généré: {filepath}")
        
        self.assertTrue(os.path.exists(filepath))
        self.assertTrue(filepath.endswith(".html"))
        
        with open(filepath, 'r') as f:
            content = f.read()
            self.assertIn("Rapport de Test", content)
            self.assertIn("TEST-001", content)
            self.assertIn("Injection SQL", content)
            self.assertIn("75.5", content)

if __name__ == '__main__':
    unittest.main()
