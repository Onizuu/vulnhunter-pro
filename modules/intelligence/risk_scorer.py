"""
Système de scoring de risque intelligent pour VulnHunter Pro
Utilise ML pour calculer des scores de risque précis et prédictifs
"""

import math
from typing import Dict, List, Tuple, Optional
from collections import defaultdict
from loguru import logger

from core.models import Vulnerabilite


class ScorerRisqueIntelligent:
    """
    Système ML pour scoring de risque intelligent et prédictif
    """

    def __init__(self):
        # Matrices de pondération ML
        self.matrice_vulnerabilites = self._initialiser_matrice_vulnerabilites()
        self.matrice_technologies = self._initialiser_matrice_technologies()
        self.matrice_context = self._initialiser_matrice_context()

        # Facteurs d'ajustement ML
        self.facteurs_ml = {
            'correlation_bonus': 1.2,    # Bonus pour vulnérabilités corrélées
            'chain_exploit_multiplier': 1.5,  # Multiplicateur pour chaînes d'exploitation
            'technology_risk_weight': 0.3,    # Poids des risques technologiques
            'age_factor': 0.1,               # Facteur d'ancienneté des vulnérabilités
            'exposure_factor': 1.3,          # Facteur d'exposition publique
        }

        # Cache pour optimiser les calculs
        self.cache_scores = {}
        self.cache_timeout = 600  # 10 minutes

        logger.info("🎯 Scorer de risque intelligent initialisé")

    def _initialiser_matrice_vulnerabilites(self) -> Dict[str, Dict]:
        """Initialise la matrice de pondération des vulnérabilités"""
        return {
            # Injection attacks
            'sql_injection': {
                'base_score': 9.5,
                'exploitability': 0.9,
                'impact': 0.95,
                'detection_difficulty': 0.3,
                'categories': ['injection', 'database']
            },
            'command_injection': {
                'base_score': 9.8,
                'exploitability': 0.8,
                'impact': 1.0,
                'detection_difficulty': 0.4,
                'categories': ['injection', 'system']
            },
            'xss': {
                'base_score': 7.2,
                'exploitability': 0.8,
                'impact': 0.6,
                'detection_difficulty': 0.2,
                'categories': ['injection', 'client_side']
            },
            'xxe': {
                'base_score': 8.5,
                'exploitability': 0.7,
                'impact': 0.8,
                'detection_difficulty': 0.5,
                'categories': ['injection', 'xml']
            },

            # Authentication & Authorization
            'weak_authentication': {
                'base_score': 8.0,
                'exploitability': 0.9,
                'impact': 0.8,
                'detection_difficulty': 0.3,
                'categories': ['auth', 'access_control']
            },
            'broken_access_control': {
                'base_score': 8.5,
                'exploitability': 0.8,
                'impact': 0.9,
                'detection_difficulty': 0.4,
                'categories': ['auth', 'access_control']
            },
            'csrf': {
                'base_score': 6.5,
                'exploitability': 0.7,
                'impact': 0.5,
                'detection_difficulty': 0.2,
                'categories': ['auth', 'csrf']
            },

            # Configuration issues
            'misconfiguration': {
                'base_score': 7.0,
                'exploitability': 0.8,
                'impact': 0.6,
                'detection_difficulty': 0.1,
                'categories': ['config', 'exposure']
            },
            'information_disclosure': {
                'base_score': 5.5,
                'exploitability': 0.6,
                'impact': 0.4,
                'detection_difficulty': 0.1,
                'categories': ['config', 'information']
            },
            'debug_mode_enabled': {
                'base_score': 6.0,
                'exploitability': 0.5,
                'impact': 0.5,
                'detection_difficulty': 0.1,
                'categories': ['config', 'debug']
            },

            # File system attacks
            'path_traversal': {
                'base_score': 8.0,
                'exploitability': 0.8,
                'impact': 0.7,
                'detection_difficulty': 0.3,
                'categories': ['file_system', 'traversal']
            },
            'file_upload_vulnerable': {
                'base_score': 8.5,
                'exploitability': 0.7,
                'impact': 0.9,
                'detection_difficulty': 0.4,
                'categories': ['file_system', 'upload']
            },

            # Network & Protocol
            'ssrf': {
                'base_score': 8.2,
                'exploitability': 0.7,
                'impact': 0.8,
                'detection_difficulty': 0.5,
                'categories': ['network', 'ssrf']
            },
            'cors_misconfiguration': {
                'base_score': 6.5,
                'exploitability': 0.6,
                'impact': 0.5,
                'detection_difficulty': 0.2,
                'categories': ['network', 'cors']
            }
        }

    def _initialiser_matrice_technologies(self) -> Dict[str, Dict]:
        """Initialise la matrice de risque technologique"""
        return {
            'php': {
                'risk_factor': 8.5,
                'common_vulns': ['sql_injection', 'xss', 'path_traversal'],
                'version_risks': {
                    '5.6': 9.5, '7.0': 8.0, '7.1': 7.5, '7.2': 7.0,
                    '7.3': 6.5, '7.4': 6.0, '8.0': 5.5, '8.1': 5.0
                },
                'deprecated_threshold': '7.4'
            },
            'apache': {
                'risk_factor': 6.0,
                'common_vulns': ['path_traversal', 'ssrf'],
                'version_risks': {'2.4.1': 8.0, '2.4.49': 9.0},
                'deprecated_threshold': '2.4.50'
            },
            'nginx': {
                'risk_factor': 5.5,
                'common_vulns': ['path_traversal', 'ssrf'],
                'version_risks': {'1.16': 7.5, '1.19': 8.0},
                'deprecated_threshold': '1.20'
            },
            'mysql': {
                'risk_factor': 7.5,
                'common_vulns': ['sql_injection'],
                'version_risks': {'5.7': 8.5, '8.0': 7.0},
                'deprecated_threshold': '5.7'
            },
            'wordpress': {
                'risk_factor': 9.0,
                'common_vulns': ['xss', 'sql_injection', 'path_traversal'],
                'version_risks': {'4.9': 9.5, '5.0': 8.5, '5.8': 7.5},
                'deprecated_threshold': '5.0'
            },
            'nodejs': {
                'risk_factor': 6.5,
                'common_vulns': ['command_injection', 'path_traversal'],
                'version_risks': {'14': 8.0, '16': 7.0, '18': 6.0},
                'deprecated_threshold': '16'
            },
            'react': {
                'risk_factor': 4.5,
                'common_vulns': ['xss'],
                'version_risks': {},
                'deprecated_threshold': None
            },
            'jquery': {
                'risk_factor': 7.0,
                'common_vulns': ['xss'],
                'version_risks': {'1.8': 9.0, '1.12': 8.0, '3.0': 6.0},
                'deprecated_threshold': '3.0'
            }
        }

    def _initialiser_matrice_context(self) -> Dict[str, Dict]:
        """Initialise la matrice de contexte environnemental"""
        return {
            'production': {
                'exposure_multiplier': 1.0,
                'urgency_multiplier': 1.0,
                'business_impact': 1.0
            },
            'staging': {
                'exposure_multiplier': 0.7,
                'urgency_multiplier': 0.8,
                'business_impact': 0.6
            },
            'development': {
                'exposure_multiplier': 0.5,
                'urgency_multiplier': 0.6,
                'business_impact': 0.4
            },
            'internet_facing': {
                'exposure_multiplier': 1.5,
                'urgency_multiplier': 1.3,
                'business_impact': 1.2
            },
            'internal_only': {
                'exposure_multiplier': 0.6,
                'urgency_multiplier': 0.7,
                'business_impact': 0.8
            }
        }

    def calculer_score_global(self,
                            vulnerabilites: List[Vulnerabilite],
                            technologies: Dict[str, str],
                            contexte: Dict = None,
                            anomalies: List[Dict] = None) -> Dict[str, any]:
        """
        Calcule un score de risque global intelligent

        Args:
            vulnerabilites: Liste des vulnérabilités détectées
            technologies: Technologies détectées avec versions
            contexte: Contexte environnemental (production, staging, etc.)
            anomalies: Anomalies comportementales détectées

        Returns:
            Dictionnaire avec score global et métriques détaillées
        """
        try:
            # Score de base des vulnérabilités
            vuln_score = self._calculer_score_vulnerabilites(vulnerabilites)

            # Score technologique
            tech_score = self._calculer_score_technologique(technologies)

            # Score contextuel
            context_score = self._calculer_score_contextuel(contexte or {})

            # Score d'anomalies
            anomaly_score = self._calculer_score_anomalies(anomalies or [])

            # Facteurs de corrélation
            correlation_factors = self._analyser_correlations(vulnerabilites)

            # Chaînes d'exploitation
            chain_score = self._evaluer_chaines_exploitation(vulnerabilites)

            # Score composite avec ML
            score_composite = self._calculer_score_composite(
                vuln_score, tech_score, context_score, anomaly_score,
                correlation_factors, chain_score
            )

            # Normalisation avec fonction sigmoïde pour lissage
            score_final = self._normaliser_score(score_composite)

            # Classification du risque
            classification = self._classifier_risque(score_final)

            # Prédictions et tendances
            predictions = self._generer_predictions(vulnerabilites, technologies)

            return {
                'score_global': score_final,
                'classification': classification,
                'composantes': {
                    'vulnerabilites': vuln_score,
                    'technologies': tech_score,
                    'contexte': context_score,
                    'anomalies': anomaly_score,
                    'correlations': correlation_factors,
                    'chaines_exploitation': chain_score
                },
                'predictions': predictions,
                'recommandations': self._generer_recommandations_prioritaires(
                    score_final, classification, vulnerabilites
                ),
                'metriques_detaillees': {
                    'total_vulnerabilites': len(vulnerabilites),
                    'critiques': len([v for v in vulnerabilites if v.severite == 'CRITIQUE']),
                    'technologies_risque': len([t for t, s in tech_score.items() if s > 7.0]),
                    'chaines_exploitation': len(chain_score) if isinstance(chain_score, list) else 0
                }
            }

        except Exception as e:
            logger.error(f"Erreur calcul score global: {str(e)}")
            return {
                'score_global': 5.0,
                'classification': 'MEDIUM',
                'error': str(e)
            }

    def _calculer_score_vulnerabilites(self, vulnerabilites: List[Vulnerabilite]) -> float:
        """Calcule le score basé sur les vulnérabilités détectées"""
        if not vulnerabilites:
            return 0.0

        total_score = 0.0

        for vuln in vulnerabilites:
            # Score de base selon la matrice
            vuln_type = self._normaliser_type_vulnerabilite(vuln.type)
            vuln_data = self.matrice_vulnerabilites.get(vuln_type, {
                'base_score': 5.0,
                'exploitability': 0.5,
                'impact': 0.5,
                'detection_difficulty': 0.5
            })

            # Score pondéré ML
            base_score = vuln_data['base_score']
            exploitability = vuln_data['exploitability']
            impact = vuln_data['impact']

            # Ajustement CVSS si disponible
            if vuln.cvss_score:
                cvss_adjustment = vuln.cvss_score / 10.0
                base_score = base_score * 0.7 + cvss_adjustment * 10 * 0.3

            # Score pondéré
            vuln_score = (base_score * 0.4 + exploitability * 10 * 0.3 + impact * 10 * 0.3)

            # Facteur de sévérité
            severity_multipliers = {
                'CRITIQUE': 1.5,
                'ÉLEVÉ': 1.2,
                'MOYEN': 1.0,
                'FAIBLE': 0.7,
                'INFO': 0.3
            }
            severity_mult = severity_multipliers.get(vuln.severite, 1.0)
            vuln_score *= severity_mult

            total_score += vuln_score

        # Normalisation logarithmique pour éviter les scores extrêmes
        return min(math.log(total_score + 1) * 2, 15.0)

    def _calculer_score_technologique(self, technologies: Dict[str, str]) -> Dict[str, float]:
        """Calcule le score de risque pour chaque technologie"""
        tech_scores = {}

        for tech, version in technologies.items():
            tech_lower = tech.lower()

            if tech_lower in self.matrice_technologies:
                tech_data = self.matrice_technologies[tech_lower]
                base_risk = tech_data['risk_factor']

                # Ajustement selon la version
                version_risks = tech_data.get('version_risks', {})
                if version in version_risks:
                    base_risk = version_risks[version]

                # Pénalité pour versions obsolètes
                deprecated = tech_data.get('deprecated_threshold')
                if deprecated and version and version < deprecated:
                    base_risk *= 1.3

                tech_scores[tech] = base_risk
            else:
                # Technologie inconnue - score par défaut modéré
                tech_scores[tech] = 5.0

        return tech_scores

    def _calculer_score_contextuel(self, contexte: Dict) -> float:
        """Calcule le score basé sur le contexte environnemental"""
        score = 1.0  # Score de base neutre

        for key, value in contexte.items():
            if key in self.matrice_context:
                context_data = self.matrice_context[key]
                score *= context_data.get('exposure_multiplier', 1.0)
                score *= context_data.get('business_impact', 1.0)

        return min(score, 3.0)  # Maximum 3x

    def _calculer_score_anomalies(self, anomalies: List[Dict]) -> float:
        """Calcule le score basé sur les anomalies comportementales"""
        if not anomalies:
            return 0.0

        total_score = 0.0
        severity_weights = {'HIGH': 3.0, 'MEDIUM': 2.0, 'LOW': 1.0}

        for anomaly in anomalies:
            severity = anomaly.get('severity', 'LOW')
            confidence = anomaly.get('confidence', 0.5)

            base_score = severity_weights.get(severity, 1.0)
            anomaly_score = base_score * confidence

            total_score += anomaly_score

        return min(total_score, 5.0)

    def _analyser_correlations(self, vulnerabilites: List[Vulnerabilite]) -> Dict[str, float]:
        """Analyse les corrélations entre vulnérabilités"""
        correlations = {
            'injection_correlation': 0.0,
            'auth_correlation': 0.0,
            'config_correlation': 0.0
        }

        if len(vulnerabilites) < 2:
            return correlations

        vuln_types = [self._categoriser_vulnerabilite(v.type) for v in vulnerabilites]

        # Comptage des catégories
        category_counts = {}
        for category in vuln_types:
            category_counts[category] = category_counts.get(category, 0) + 1

        # Calcul des corrélations
        total_vulns = len(vulnerabilites)

        correlations['injection_correlation'] = min(
            category_counts.get('injection', 0) / total_vulns * 2, 1.0
        )
        correlations['auth_correlation'] = min(
            category_counts.get('auth', 0) / total_vulns * 2, 1.0
        )
        correlations['config_correlation'] = min(
            category_counts.get('config', 0) / total_vulns * 2, 1.0
        )

        return correlations

    def _evaluer_chaines_exploitation(self, vulnerabilites: List[Vulnerabilite]) -> float:
        """Évalue le potentiel de chaînes d'exploitation"""
        if len(vulnerabilites) < 2:
            return 0.0

        # Grouper par URL
        par_url = defaultdict(list)
        for vuln in vulnerabilites:
            par_url[vuln.url].append(vuln)

        chain_potential = 0.0

        for url, vulns in par_url.items():
            if len(vulns) >= 2:
                # Évaluer les combinaisons dangereuses
                vuln_types = [v.type.lower() for v in vulns]

                # Injection + autre vulnérabilité = chaîne potentielle
                if any('injection' in vt for vt in vuln_types) and \
                   len(vuln_types) > 1:
                    chain_potential += 2.0

                # Auth bypass + privilege escalation
                if any('auth' in vt or 'login' in vt for vt in vuln_types) and \
                   any('idor' in vt or 'privilege' in vt for vt in vuln_types):
                    chain_potential += 3.0

        return min(chain_potential, 10.0)

    def _calculer_score_composite(self, vuln_score: float, tech_score: Dict[str, float],
                                context_score: float, anomaly_score: float,
                                correlations: Dict[str, float],
                                chain_score: float) -> float:
        """Calcule le score composite avec ML"""
        # Score de base pondéré
        base_score = vuln_score * 0.5 + sum(tech_score.values()) * 0.1 + anomaly_score

        # Application des facteurs de corrélation
        correlation_bonus = sum(correlations.values()) * self.facteurs_ml['correlation_bonus']
        base_score *= (1 + correlation_bonus * 0.1)

        # Facteur de chaînes d'exploitation
        chain_multiplier = 1 + (chain_score * self.facteurs_ml['chain_exploit_multiplier'] * 0.1)
        base_score *= chain_multiplier

        # Facteur contextuel
        base_score *= context_score

        return base_score

    def _normaliser_score(self, score_composite: float) -> float:
        """Normalise le score avec une fonction sigmoïde pour lisser"""
        # Sigmoïde centrée sur 5.0 avec pente ajustée
        sigmoid = 1 / (1 + math.exp(-score_composite / 3 + 2.5))
        return round(sigmoid * 10, 1)

    def _classifier_risque(self, score: float) -> str:
        """Classifie le niveau de risque"""
        if score >= 8.5:
            return 'CRITICAL'
        elif score >= 7.0:
            return 'HIGH'
        elif score >= 5.0:
            return 'MEDIUM'
        elif score >= 3.0:
            return 'LOW'
        else:
            return 'INFO'

    def _generer_predictions(self, vulnerabilites: List[Vulnerabilite],
                           technologies: Dict[str, str]) -> List[Dict]:
        """Génère des prédictions de risque futur"""
        predictions = []

        # Prédiction basée sur les vulnérabilités actuelles
        vuln_types = [v.type for v in vulnerabilites]
        vuln_count = len(vulnerabilites)

        if vuln_count >= 5:
            predictions.append({
                'type': 'high_vulnerability_density',
                'description': 'Densité élevée de vulnérabilités détectée',
                'risk_increase': 2.0,
                'timeframe': 'immediate'
            })

        # Prédiction basée sur les technologies
        for tech, version in technologies.items():
            tech_lower = tech.lower()
            if tech_lower in self.matrice_technologies:
                tech_data = self.matrice_technologies[tech_lower]
                if version and tech_data.get('deprecated_threshold'):
                    if version < tech_data['deprecated_threshold']:
                        predictions.append({
                            'type': 'outdated_technology',
                            'technology': tech,
                            'version': version,
                            'description': f'{tech} {version} est obsolète',
                            'risk_increase': 1.5,
                            'timeframe': '3-6 months'
                        })

        return predictions

    def _generer_recommandations_prioritaires(self, score: float, classification: str,
                                           vulnerabilites: List[Vulnerabilite]) -> List[Dict]:
        """Génère des recommandations prioritaires"""
        recommandations = []

        # Recommandations basées sur le score
        if score >= 8.0:
            recommandations.append({
                'priority': 'CRITICAL',
                'action': 'Audit de sécurité immédiat',
                'description': 'Score de risque critique - action immédiate requise',
                'effort': 'HIGH',
                'impact': 'CRITICAL'
            })

        # Recommandations basées sur les vulnérabilités critiques
        critiques = [v for v in vulnerabilites if v.severite == 'CRITIQUE']
        if critiques:
            recommandations.append({
                'priority': 'HIGH',
                'action': 'Correction des vulnérabilités critiques',
                'description': f'{len(critiques)} vulnérabilités critiques à corriger',
                'effort': 'HIGH',
                'impact': 'HIGH'
            })

        # Recommandations générales
        recommandations.extend([
            {
                'priority': 'MEDIUM',
                'action': 'Mise à jour des dépendances',
                'description': 'Vérifier et mettre à jour toutes les dépendances',
                'effort': 'MEDIUM',
                'impact': 'MEDIUM'
            },
            {
                'priority': 'MEDIUM',
                'action': 'Configuration de sécurité',
                'description': 'Auditer et renforcer la configuration de sécurité',
                'effort': 'MEDIUM',
                'impact': 'HIGH'
            },
            {
                'priority': 'LOW',
                'action': 'Monitoring continu',
                'description': 'Mettre en place un monitoring de sécurité continu',
                'effort': 'LOW',
                'impact': 'MEDIUM'
            }
        ])

        return recommandations[:5]  # Top 5 recommandations

    def _normaliser_type_vulnerabilite(self, vuln_type: str) -> str:
        """Normalise le type de vulnérabilité pour la matrice"""
        vuln_type_lower = vuln_type.lower()

        # Mapping des types
        mappings = {
            'sql injection': 'sql_injection',
            'injection sql': 'sql_injection',
            'xss': 'xss',
            'cross-site scripting': 'xss',
            'command injection': 'command_injection',
            'xxe': 'xxe',
            'xml external entity': 'xxe',
            'weak authentication': 'weak_authentication',
            'broken access control': 'broken_access_control',
            'idor': 'broken_access_control',
            'csrf': 'csrf',
            'cross-site request forgery': 'csrf',
            'misconfiguration': 'misconfiguration',
            'information disclosure': 'information_disclosure',
            'debug mode': 'debug_mode_enabled',
            'path traversal': 'path_traversal',
            'directory traversal': 'path_traversal',
            'file upload': 'file_upload_vulnerable',
            'ssrf': 'ssrf',
            'server-side request forgery': 'ssrf',
            'cors': 'cors_misconfiguration'
        }

        for key, value in mappings.items():
            if key in vuln_type_lower:
                return value

        return 'misconfiguration'  # Par défaut

    def _categoriser_vulnerabilite(self, vuln_type: str) -> str:
        """Catégorise une vulnérabilité"""
        vuln_type_lower = vuln_type.lower()

        if any(word in vuln_type_lower for word in ['sql', 'xss', 'command', 'xxe', 'injection']):
            return 'injection'
        elif any(word in vuln_type_lower for word in ['auth', 'login', 'password', 'access', 'idor', 'csrf']):
            return 'auth'
        elif any(word in vuln_type_lower for word in ['config', 'debug', 'information', 'disclosure']):
            return 'config'
        else:
            return 'other'
