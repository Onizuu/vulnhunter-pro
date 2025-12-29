"""
Système de métriques de conformité et analyse OWASP pour VulnHunter Pro
OWASP Risk Rating, CVSS v4, PCI-DSS, GDPR, HIPAA, benchmarks, heatmaps
"""

import json
import math
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from core.models import Vulnerabilite


class SeveriteCVSS(Enum):
    """Sévérités CVSS"""
    NONE = "None"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class SeveriteOWASP(Enum):
    """Sévérités OWASP Risk Rating"""
    INFO = "Informational"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


@dataclass
class ScoreOWASP:
    """Score OWASP Risk Rating Methodology"""
    likelihood: float  # 0-9
    impact: float      # 0-9
    overall_score: float = field(init=False)
    severity: SeveriteOWASP = field(init=False)

    def __post_init__(self):
        self.overall_score = self.likelihood * self.impact
        self.severity = self._calculer_severite()

    def _calculer_severite(self) -> SeveriteOWASP:
        """Calcule la sévérité selon la méthodologie OWASP"""
        score = self.overall_score

        if score >= 36:  # 9*4 ou plus
            return SeveriteOWASP.CRITICAL
        elif score >= 16:  # 4*4 ou plus
            return SeveriteOWASP.HIGH
        elif score >= 9:   # 3*3 ou plus
            return SeveriteOWASP.MEDIUM
        elif score >= 4:   # 2*2 ou plus
            return SeveriteOWASP.LOW
        else:
            return SeveriteOWASP.INFO


@dataclass
class ScoreCVSS:
    """Score CVSS v3.1/v4"""
    base_score: float
    temporal_score: float = 0.0
    environmental_score: float = 0.0
    severity: SeveriteCVSS = field(init=False)
    vector: str = ""

    def __post_init__(self):
        self.severity = self._calculer_severite_cvss()

    def _calculer_severite_cvss(self) -> SeveriteCVSS:
        """Calcule la sévérité selon CVSS"""
        score = self.base_score

        if score >= 9.0:
            return SeveriteCVSS.CRITICAL
        elif score >= 7.0:
            return SeveriteCVSS.HIGH
        elif score >= 4.0:
            return SeveriteCVSS.MEDIUM
        elif score >= 0.1:
            return SeveriteCVSS.LOW
        else:
            return SeveriteCVSS.NONE


class CalculateurOWASPRisk:
    """
    Calculateur de scores selon la méthodologie OWASP Risk Rating
    """

    def __init__(self):
        # Tables de correspondance pour le calcul OWASP
        self.skill_level_weights = {
            'novice': 1,
            'intermediate': 2,
            'advanced': 3,
            'expert': 4
        }

        self.motive_weights = {
            'low': 1,
            'possible': 2,
            'high': 3,
            'assumed': 4
        }

        self.opportunity_weights = {
            'difficult': 1,
            'realistic': 2,
            'easy': 3,
            'ubiquitous': 4
        }

        self.size_weights = {
            'small': 1,
            'medium': 2,
            'large': 3,
            'enterprise': 4
        }

        self.ease_of_discovery_weights = {
            'difficult': 1,
            'realistic': 2,
            'easy': 3,
            'automated': 4
        }

        self.ease_of_exploit_weights = {
            'difficult': 1,
            'realistic': 2,
            'easy': 3,
            'automated': 4
        }

        self.awareness_weights = {
            'unknown': 1,
            'hidden': 2,
            'obvious': 3,
            'public': 4
        }

        self.intrusion_detection_weights = {
            'logged_reviewed': 1,
            'logged_unreviewed': 2,
            'not_logged': 3,
            'logged_bypassed': 4
        }

        # Technical Impact
        self.loss_of_confidentiality_weights = {
            'minimal': 1,
            'reasonable': 2,
            'significant': 3,
            'extensive': 4
        }

        self.loss_of_integrity_weights = {
            'minimal': 1,
            'reasonable': 2,
            'significant': 3,
            'extensive': 4
        }

        self.loss_of_availability_weights = {
            'minimal': 1,
            'reasonable': 2,
            'significant': 3,
            'extensive': 4
        }

        self.loss_of_accountability_weights = {
            'minimal': 1,
            'reasonable': 2,
            'significant': 3,
            'extensive': 4
        }

        # Business Impact
        self.financial_damage_weights = {
            'less_than_cost': 1,
            'minor': 2,
            'significant': 3,
            'bankruptcy': 4
        }

        self.reputation_damage_weights = {
            'minor': 1,
            'damaged': 2,
            'seriously': 3,
            'destroyed': 4
        }

        self.non_compliance_weights = {
            'minor': 1,
            'clear': 2,
            'high_profile': 3,
            'disastrous': 4
        }

        self.privacy_violation_weights = {
            'one_individual': 1,
            'hundreds': 2,
            'thousands': 3,
            'millions': 4
        }

    def calculer_risque_owasp(self, vulnerabilite: Vulnerabilite,
                             contexte: Dict[str, Any] = None) -> ScoreOWASP:
        """
        Calcule le score de risque OWASP pour une vulnérabilité

        Args:
            vulnerabilite: La vulnérabilité à évaluer
            contexte: Contexte additionnel (environnement, etc.)

        Returns:
            ScoreOWASP: Score calculé selon la méthodologie OWASP
        """
        contexte = contexte or {}

        # Facteurs de menace (Threat Agent Factors)
        skill_level = contexte.get('threat_skill_level', 'intermediate')
        motive = contexte.get('threat_motive', 'possible')
        opportunity = contexte.get('threat_opportunity', 'realistic')
        size = contexte.get('threat_size', 'medium')

        # Facteurs de vulnérabilité (Vulnerability Factors)
        ease_of_discovery = self._evaluer_ease_of_discovery(vulnerabilite)
        ease_of_exploit = self._evaluer_ease_of_exploit(vulnerabilite)
        awareness = self._evaluer_awareness(vulnerabilite)
        intrusion_detection = self._evaluer_intrusion_detection(vulnerabilite)

        # Calcul du Likelihood Score (0-9)
        threat_agent_score = (self.skill_level_weights.get(skill_level, 2) +
                            self.motive_weights.get(motive, 2) +
                            self.opportunity_weights.get(opportunity, 2) +
                            self.size_weights.get(size, 2)) / 4

        vulnerability_score = (self.ease_of_discovery_weights.get(ease_of_discovery, 2) +
                             self.ease_of_exploit_weights.get(ease_of_exploit, 2) +
                             self.awareness_weights.get(awareness, 2) +
                             self.intrusion_detection_weights.get(intrusion_detection, 2)) / 4

        likelihood = (threat_agent_score + vulnerability_score) / 2

        # Facteurs d'impact technique
        loss_of_confidentiality = self._evaluer_technical_impact(vulnerabilite, 'confidentiality')
        loss_of_integrity = self._evaluer_technical_impact(vulnerabilite, 'integrity')
        loss_of_availability = self._evaluer_technical_impact(vulnerabilite, 'availability')
        loss_of_accountability = self._evaluer_technical_impact(vulnerabilite, 'accountability')

        technical_impact = (self.loss_of_confidentiality_weights.get(loss_of_confidentiality, 2) +
                          self.loss_of_integrity_weights.get(loss_of_integrity, 2) +
                          self.loss_of_availability_weights.get(loss_of_availability, 2) +
                          self.loss_of_accountability_weights.get(loss_of_accountability, 2)) / 4

        # Facteurs d'impact business
        financial_damage = contexte.get('business_impact_financial', 'minor')
        reputation_damage = contexte.get('business_impact_reputation', 'damaged')
        non_compliance = contexte.get('business_impact_compliance', 'minor')
        privacy_violation = contexte.get('business_impact_privacy', 'hundreds')

        business_impact = (self.financial_damage_weights.get(financial_damage, 2) +
                         self.reputation_damage_weights.get(reputation_damage, 2) +
                         self.non_compliance_weights.get(non_compliance, 2) +
                         self.privacy_violation_weights.get(privacy_violation, 2)) / 4

        # Impact total (0-9)
        impact = (technical_impact + business_impact) / 2

        return ScoreOWASP(likelihood=likelihood, impact=impact)

    def _evaluer_ease_of_discovery(self, vuln: Vulnerabilite) -> str:
        """Évalue la facilité de découverte de la vulnérabilité"""
        type_lower = vuln.type.lower()

        # Vulnérabilités faciles à découvrir automatiquement
        if any(keyword in type_lower for keyword in ['xss', 'sql', 'command', 'path']):
            return 'automated'
        elif any(keyword in type_lower for keyword in ['csrf', 'idor', 'header']):
            return 'easy'
        elif any(keyword in type_lower for keyword in ['xxe', 'ssrf']):
            return 'realistic'
        else:
            return 'difficult'

    def _evaluer_ease_of_exploit(self, vuln: Vulnerabilite) -> str:
        """Évalue la facilité d'exploitation"""
        type_lower = vuln.type.lower()
        severite = vuln.severite.lower()

        if 'sql' in type_lower or 'xss' in type_lower:
            return 'automated' if severite in ['critique', 'élevé'] else 'easy'
        elif 'command' in type_lower or 'rce' in type_lower:
            return 'easy'
        elif 'idor' in type_lower or 'csrf' in type_lower:
            return 'realistic'
        else:
            return 'difficult'

    def _evaluer_awareness(self, vuln: Vulnerabilite) -> str:
        """Évalue le niveau de connaissance publique"""
        # Simulation basée sur le type de vulnérabilité
        type_lower = vuln.type.lower()

        if 'sql' in type_lower or 'xss' in type_lower:
            return 'public'  # Très connues
        elif 'zero' in type_lower or 'cve' in type_lower:
            return 'public'  # Documentées
        elif 'csrf' in type_lower or 'idor' in type_lower:
            return 'obvious'  # Bien documentées
        else:
            return 'hidden'  # Moins connues

    def _evaluer_intrusion_detection(self, vuln: Vulnerabilite) -> str:
        """Évalue l'évitement de la détection"""
        type_lower = vuln.type.lower()

        if 'blind' in type_lower or 'time' in type_lower:
            return 'logged_bypassed'  # Difficile à détecter
        elif 'error' in type_lower or 'information' in type_lower:
            return 'not_logged'  # Peu de logs
        elif 'xss' in type_lower or 'csrf' in type_lower:
            return 'logged_unreviewed'  # Logs mais pas analysés
        else:
            return 'logged_reviewed'  # Bien loggé

    def _evaluer_technical_impact(self, vuln: Vulnerabilite, aspect: str) -> str:
        """Évalue l'impact technique selon l'aspect"""
        type_lower = vuln.type.lower()
        severite = vuln.severite.lower()

        if aspect == 'confidentiality':
            if 'information' in type_lower or 'divulgation' in type_lower:
                return 'extensive' if severite in ['critique', 'élevé'] else 'significant'
            elif 'sql' in type_lower or 'path' in type_lower:
                return 'significant'
            else:
                return 'reasonable'

        elif aspect == 'integrity':
            if 'sql' in type_lower or 'command' in type_lower:
                return 'extensive' if severite in ['critique', 'élevé'] else 'significant'
            else:
                return 'reasonable'

        elif aspect == 'availability':
            if 'dos' in type_lower or 'flood' in type_lower:
                return 'extensive'
            else:
                return 'minimal'

        elif aspect == 'accountability':
            if 'log' in type_lower or 'audit' in type_lower:
                return 'significant'
            else:
                return 'minimal'

        return 'reasonable'


class CalculateurCVSS:
    """
    Calculateur de scores CVSS v3.1 (et préparation pour v4.0)
    """

    def __init__(self):
        # Métriques CVSS v3.1
        self.impact_weights = {
            'AV': {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2},  # Attack Vector
            'AC': {'L': 0.77, 'H': 0.44},                        # Attack Complexity
            'PR': {'N': 0.85, 'L': 0.62, 'H': 0.27},           # Privileges Required
            'UI': {'N': 0.85, 'R': 0.62},                        # User Interaction
            'S': {'U': 1.0, 'C': 1.0},                          # Scope
            'C': {'N': 0, 'L': 0.22, 'H': 0.56},               # Confidentiality
            'I': {'N': 0, 'L': 0.22, 'H': 0.56},               # Integrity
            'A': {'N': 0, 'L': 0.22, 'H': 0.56}                # Availability
        }

        self.temporal_weights = {
            'E': {'U': 1.0, 'P': 0.94, 'F': 0.97, 'H': 1.0},  # Exploit Code Maturity
            'RL': {'U': 1.0, 'W': 0.97, 'T': 0.96, 'O': 0.95}, # Remediation Level
            'RC': {'U': 1.0, 'R': 0.96, 'C': 0.92}             # Report Confidence
        }

    def calculer_score_cvss(self, vulnerabilite: Vulnerabilite,
                           contexte: Dict[str, Any] = None) -> ScoreCVSS:
        """
        Calcule le score CVSS pour une vulnérabilité

        Args:
            vulnerabilite: La vulnérabilité à scorer
            contexte: Contexte CVSS (vecteur, métriques temporelles, etc.)

        Returns:
            ScoreCVSS: Score calculé
        """
        contexte = contexte or {}

        # Utiliser le vecteur CVSS fourni ou en générer un
        vector = contexte.get('cvss_vector', '')
        if not vector:
            vector = self._generer_vecteur_cvss(vulnerabilite, contexte)

        # Parser le vecteur pour extraire les métriques
        metriques = self._parser_vecteur_cvss(vector)

        # Calculer le score de base
        base_score = self._calculer_base_score(metriques)

        # Calculer les scores temporels si disponibles
        temporal_score = self._calculer_temporal_score(metriques)

        # Calculer les scores environnementaux si disponibles
        environmental_score = self._calculer_environmental_score(metriques, contexte)

        return ScoreCVSS(
            base_score=base_score,
            temporal_score=temporal_score,
            environmental_score=environmental_score,
            vector=vector
        )

    def _generer_vecteur_cvss(self, vuln: Vulnerabilite, contexte: Dict) -> str:
        """Génère un vecteur CVSS basé sur la vulnérabilité"""
        # Métriques par défaut
        metriques = {
            'AV': 'N',  # Network (par défaut pour web)
            'AC': 'L',  # Low complexity
            'PR': 'N',  # None required
            'UI': 'R',  # Required (interaction nécessaire)
            'S': 'U',   # Unchanged scope
            'C': 'H',   # High confidentiality impact
            'I': 'H',   # High integrity impact
            'A': 'H'    # High availability impact
        }

        # Adapter selon le type de vulnérabilité
        type_lower = vuln.type.lower()
        severite = vuln.severite.lower()

        # Attack Vector
        if 'local' in type_lower or 'file' in type_lower:
            metriques['AV'] = 'L'  # Local
        elif 'adjacent' in type_lower:
            metriques['AV'] = 'A'  # Adjacent Network
        elif 'physical' in type_lower:
            metriques['AV'] = 'P'  # Physical

        # Attack Complexity
        if 'blind' in type_lower or 'time' in type_lower:
            metriques['AC'] = 'H'  # High complexity

        # Privileges Required
        if 'admin' in type_lower or 'root' in type_lower:
            metriques['PR'] = 'H'  # High privileges
        elif 'auth' in str(contexte) or 'login' in str(contexte):
            metriques['PR'] = 'L'  # Low privileges

        # User Interaction
        if 'csrf' in type_lower or 'clickjacking' in type_lower:
            metriques['UI'] = 'R'  # Required
        else:
            metriques['UI'] = 'N'  # None

        # Scope
        if 'container' in type_lower or 'vm' in type_lower:
            metriques['S'] = 'C'  # Changed

        # Impacts selon la sévérité
        if severite == 'critique':
            metriques.update({'C': 'H', 'I': 'H', 'A': 'H'})
        elif severite == 'élevé':
            metriques.update({'C': 'H', 'I': 'H', 'A': 'L'})
        elif severite == 'moyen':
            metriques.update({'C': 'H', 'I': 'L', 'A': 'L'})
        else:
            metriques.update({'C': 'L', 'I': 'L', 'A': 'L'})

        # Construire le vecteur
        vector = "CVSS:3.1"
        for metrique, valeur in metriques.items():
            vector += f"/{metrique}:{valeur}"

        return vector

    def _parser_vecteur_cvss(self, vector: str) -> Dict[str, str]:
        """Parse un vecteur CVSS en métriques"""
        metriques = {}

        if not vector.startswith('CVSS:'):
            return metriques

        parties = vector.split('/')
        for partie in parties[1:]:  # Skip CVSS:3.1
            if ':' in partie:
                cle, valeur = partie.split(':', 1)
                metriques[cle] = valeur

        return metriques

    def _calculer_base_score(self, metriques: Dict[str, str]) -> float:
        """Calcule le score de base CVSS"""
        # Impact Sub-Score
        confidentiality = self.impact_weights['C'].get(metriques.get('C', 'H'), 0.56)
        integrity = self.impact_weights['I'].get(metriques.get('I', 'H'), 0.56)
        availability = self.impact_weights['A'].get(metriques.get('A', 'H'), 0.56)

        scope = metriques.get('S', 'U')
        scope_weight = self.impact_weights['S'].get(scope, 1.0)

        if scope == 'U':
            impact = 1 - ((1 - confidentiality) * (1 - integrity) * (1 - availability))
        else:
            impact = 1.08 * (confidentiality + integrity + availability)

        # Exploitability Sub-Score
        attack_vector = self.impact_weights['AV'].get(metriques.get('AV', 'N'), 0.85)
        attack_complexity = self.impact_weights['AC'].get(metriques.get('AC', 'L'), 0.77)
        privileges_required = self.impact_weights['PR'].get(metriques.get('PR', 'N'), 0.85)
        user_interaction = self.impact_weights['UI'].get(metriques.get('UI', 'N'), 0.85)

        exploitability = 8.22 * attack_vector * attack_complexity * privileges_required * user_interaction

        # Base Score
        if impact <= 0:
            return 0.0

        if scope == 'U':
            base_score = min(impact + exploitability, 10.0)
        else:
            base_score = min(1.08 * (impact + exploitability), 10.0)

        return round(base_score, 1)

    def _calculer_temporal_score(self, metriques: Dict[str, str]) -> float:
        """Calcule le score temporel"""
        # Pour l'instant, retourner le score de base
        # En production, utiliser les métriques E, RL, RC
        return 0.0

    def _calculer_environmental_score(self, metriques: Dict[str, str],
                                    contexte: Dict[str, Any]) -> float:
        """Calcule le score environnemental"""
        # Pour l'instant, retourner le score de base
        # En production, utiliser les métriques environnementales
        return 0.0


class VerificateurCompliance:
    """
    Vérificateur de conformité réglementaire
    """

    def __init__(self):
        self.reglementations = {
            'pci_dss': self._regles_pci_dss(),
            'gdpr': self._regles_gdpr(),
            'hipaa': self._regles_hipaa(),
            'iso_27001': self._regles_iso27001(),
            'soc2': self._regles_soc2()
        }

    def verifier_conformite(self, vulnerabilites: List[Vulnerabilite],
                          reglementation: str) -> Dict[str, Any]:
        """
        Vérifie la conformité selon une réglementation donnée

        Args:
            vulnerabilites: Liste des vulnérabilités trouvées
            reglementation: Nom de la réglementation (pci_dss, gdpr, etc.)

        Returns:
            Rapport de conformité
        """
        if reglementation not in self.reglementations:
            return {'erreur': f'Réglementation non supportée: {reglementation}'}

        regles = self.reglementations[reglementation]

        rapport = {
            'reglementation': reglementation,
            'date_verification': datetime.now().isoformat(),
            'total_vulnerabilites': len(vulnerabilites),
            'conforme': True,
            'violations': [],
            'recommandations': [],
            'score_conformite': 100.0
        }

        # Vérifier chaque règle
        for regle in regles:
            violations = self._verifier_regle(regle, vulnerabilites)
            if violations:
                rapport['conforme'] = False
                rapport['violations'].extend(violations)
                rapport['score_conformite'] -= regle.get('impact_score', 10)

                if 'recommandation' in regle:
                    rapport['recommandations'].append(regle['recommandation'])

        # S'assurer que le score reste positif
        rapport['score_conformite'] = max(0, rapport['score_conformite'])

        return rapport

    def _regles_pci_dss(self) -> List[Dict]:
        """Règles PCI DSS v4.0"""
        return [
            {
                'id': 'PCI-1',
                'description': 'Protection des données de cartes de paiement',
                'check': lambda v: any(keyword in v.type.lower() for keyword in
                                     ['sql', 'injection', 'xss', 'csrf']),
                'impact_score': 25,
                'recommandation': 'Implémenter la tokenisation et chiffrer les données sensibles'
            },
            {
                'id': 'PCI-2',
                'description': 'Utilisation de pare-feux',
                'check': lambda v: 'firewall' in str(v.description).lower() or
                                 v.type.lower() in ['open_port', 'service_exposure'],
                'impact_score': 20,
                'recommandation': 'Configurer des pare-feux et WAF appropriés'
            },
            {
                'id': 'PCI-3',
                'description': 'Protection des mots de passe',
                'check': lambda v: any(keyword in v.type.lower() for keyword in
                                     ['weak_password', 'default_credential', 'auth_bypass']),
                'impact_score': 15,
                'recommandation': 'Implémenter des politiques de mots de passe forts'
            },
            {
                'id': 'PCI-4',
                'description': 'Chiffrement des données sensibles',
                'check': lambda v: any(keyword in str(v.description).lower() for keyword in
                                     ['unencrypted', 'plaintext', 'ssl_weak', 'tls_weak']),
                'impact_score': 25,
                'recommandation': 'Utiliser TLS 1.3+ et chiffrer toutes les données sensibles'
            }
        ]

    def _regles_gdpr(self) -> List[Dict]:
        """Règles GDPR"""
        return [
            {
                'id': 'GDPR-1',
                'description': 'Protection des données personnelles',
                'check': lambda v: any(keyword in v.type.lower() for keyword in
                                     ['information_disclosure', 'data_leak', 'privacy']),
                'impact_score': 30,
                'recommandation': 'Anonymiser et chiffrer les données personnelles'
            },
            {
                'id': 'GDPR-2',
                'description': 'Droit à la portabilité des données',
                'check': lambda v: 'api' in str(v.description).lower() and
                                 any(keyword in v.type.lower() for keyword in ['auth', 'access']),
                'impact_score': 15,
                'recommandation': 'Implémenter des APIs sécurisées pour l\'export de données'
            },
            {
                'id': 'GDPR-3',
                'description': 'Droit à l\'effacement',
                'check': lambda v: any(keyword in v.type.lower() for keyword in
                                     ['data_retention', 'deletion', 'purge']),
                'impact_score': 20,
                'recommandation': 'Implémenter des mécanismes d\'effacement automatique'
            }
        ]

    def _regles_hipaa(self) -> List[Dict]:
        """Règles HIPAA"""
        return [
            {
                'id': 'HIPAA-1',
                'description': 'Confidentialité des données médicales',
                'check': lambda v: any(keyword in str(v.description).lower() for keyword in
                                     ['medical', 'health', 'phi', 'patient']),
                'impact_score': 35,
                'recommandation': 'Implémenter des contrôles d\'accès stricts aux données médicales'
            },
            {
                'id': 'HIPAA-2',
                'description': 'Audit et logging',
                'check': lambda v: any(keyword in v.type.lower() for keyword in
                                     ['log_manipulation', 'audit_bypass']),
                'impact_score': 20,
                'recommandation': 'Implémenter un système d\'audit complet et immutable'
            }
        ]

    def _regles_iso27001(self) -> List[Dict]:
        """Règles ISO 27001"""
        return [
            {
                'id': 'ISO-1',
                'description': 'Contrôle d\'accès',
                'check': lambda v: any(keyword in v.type.lower() for keyword in
                                     ['auth_bypass', 'privilege_escalation', 'idor']),
                'impact_score': 20,
                'recommandation': 'Implémenter RBAC et principe du moindre privilège'
            },
            {
                'id': 'ISO-2',
                'description': 'Chiffrement des données',
                'check': lambda v: any(keyword in str(v.description).lower() for keyword in
                                     ['unencrypted', 'plaintext', 'weak_crypto']),
                'impact_score': 25,
                'recommandation': 'Utiliser des algorithmes de chiffrement approuvés'
            }
        ]

    def _regles_soc2(self) -> List[Dict]:
        """Règles SOC 2"""
        return [
            {
                'id': 'SOC2-1',
                'description': 'Sécurité des données',
                'check': lambda v: any(keyword in v.type.lower() for keyword in
                                     ['data_breach', 'information_disclosure', 'weak_crypto']),
                'impact_score': 30,
                'recommandation': 'Implémenter des contrôles de sécurité des données complets'
            },
            {
                'id': 'SOC2-2',
                'description': 'Disponibilité du système',
                'check': lambda v: any(keyword in v.type.lower() for keyword in
                                     ['dos', 'availability', 'service_disruption']),
                'impact_score': 25,
                'recommandation': 'Implémenter la redondance et les plans de continuité'
            }
        ]

    def _verifier_regle(self, regle: Dict, vulnerabilites: List[Vulnerabilite]) -> List[Dict]:
        """Vérifie une règle contre les vulnérabilites"""
        violations = []

        for vuln in vulnerabilites:
            if regle['check'](vuln):
                violations.append({
                    'regle_id': regle['id'],
                    'description': regle['description'],
                    'vulnerabilite': {
                        'type': vuln.type,
                        'severite': vuln.severite,
                        'url': vuln.url,
                        'description': vuln.description
                    },
                    'impact': regle.get('impact_score', 10)
                })

        return violations


class GenerateurBenchmarks:
    """
    Générateur de benchmarks industry et comparaisons
    """

    def __init__(self):
        self.benchmarks_industry = {
            'web_application': {
                'moyenne_critique': 2.5,
                'moyenne_eleve': 8.3,
                'moyenne_moyen': 15.7,
                'moyenne_faible': 25.2,
                'score_risque_moyen': 6.8
            },
            'api_rest': {
                'moyenne_critique': 1.8,
                'moyenne_eleve': 6.2,
                'moyenne_moyen': 12.4,
                'moyenne_faible': 18.9,
                'score_risque_moyen': 5.4
            },
            'mobile_app': {
                'moyenne_critique': 3.1,
                'moyenne_eleve': 9.8,
                'moyenne_moyen': 18.6,
                'moyenne_faible': 28.4,
                'score_risque_moyen': 7.2
            },
            'cloud_infrastructure': {
                'moyenne_critique': 4.2,
                'moyenne_eleve': 12.1,
                'moyenne_moyen': 22.8,
                'moyenne_faible': 35.6,
                'score_risque_moyen': 8.5
            }
        }

    def generer_benchmark(self, vulnerabilites: List[Vulnerabilite],
                         secteur: str = 'web_application') -> Dict[str, Any]:
        """
        Génère un benchmark comparatif

        Args:
            vulnerabilites: Liste des vulnérabilités trouvées
            secteur: Secteur d'activité pour la comparaison

        Returns:
            Rapport de benchmark
        """
        if secteur not in self.benchmarks_industry:
            secteur = 'web_application'

        benchmark = self.benchmarks_industry[secteur]

        # Compter les vulnérabilités par sévérité
        stats_actuelles = {
            'critique': 0,
            'eleve': 0,
            'moyen': 0,
            'faible': 0,
            'info': 0
        }

        for vuln in vulnerabilites:
            sev = vuln.severite.lower()
            if sev in stats_actuelles:
                stats_actuelles[sev] += 1

        # Calculer les pourcentages
        total = len(vulnerabilites)
        if total > 0:
            stats_pourcent = {k: (v / total) * 100 for k, v in stats_actuelles.items()}
        else:
            stats_pourcent = {k: 0.0 for k in stats_actuelles.keys()}

        # Comparer avec les benchmarks
        comparaison = {}
        for sev in ['critique', 'eleve', 'moyen', 'faible']:
            actuel = stats_pourcent[sev]
            industry = benchmark[f'moyenne_{sev}']
            difference = actuel - industry

            if difference > 5:
                statut = 'au_dessus_moyenne'
            elif difference < -5:
                statut = 'en_dessous_moyenne'
            else:
                statut = 'dans_moyenne'

            comparaison[sev] = {
                'actuel': actuel,
                'industry': industry,
                'difference': difference,
                'statut': statut
            }

        # Score de maturité sécurité
        score_maturite = self._calculer_score_maturite(stats_actuelles, benchmark)

        return {
            'secteur': secteur,
            'date_generation': datetime.now().isoformat(),
            'statistiques_actuelles': stats_actuelles,
            'pourcentages': stats_pourcent,
            'comparaison_industry': comparaison,
            'score_maturite': score_maturite,
            'recommandations': self._generer_recommandations_benchmark(comparaison)
        }

    def _calculer_score_maturite(self, stats: Dict, benchmark: Dict) -> float:
        """Calcule un score de maturité sécurité (0-100)"""
        # Score basé sur l'écart par rapport aux moyennes industry
        score = 100.0

        # Pénalités pour les vulnérabilités critiques
        score -= stats['critique'] * 15
        score -= stats['eleve'] * 8
        score -= stats['moyen'] * 4
        score -= stats['faible'] * 1

        # Bonus pour être en dessous des moyennes
        if stats['critique'] < benchmark['moyenne_critique']:
            score += 10
        if stats['eleve'] < benchmark['moyenne_eleve']:
            score += 5

        return max(0, min(100, score))

    def _generer_recommandations_benchmark(self, comparaison: Dict) -> List[str]:
        """Génère des recommandations basées sur le benchmark"""
        recommandations = []

        for sev, data in comparaison.items():
            if data['statut'] == 'au_dessus_moyenne':
                diff = data['difference']
                if sev == 'critique':
                    recommandations.append(
                        ".1f"
                    )
                elif sev == 'eleve':
                    recommandations.append(
                        ".1f"
                    )
                else:
                    recommandations.append(
                        f"Réduire les vulnérabilités {sev} ({diff:+.1f}% vs industrie)"
                    )

        if not recommandations:
            recommandations.append("Profil de sécurité dans les normes de l'industrie")

        return recommandations


class GenerateurHeatmap:
    """
    Générateur de heatmaps de risque
    """

    def __init__(self):
        self.palette_couleurs = {
            'tres_faible': '#00FF00',    # Vert
            'faible': '#90EE90',         # Vert clair
            'moyen': '#FFFF00',          # Jaune
            'eleve': '#FFA500',          # Orange
            'critique': '#FF0000',       # Rouge
            'tres_critique': '#8B0000'   # Rouge foncé
        }

    def generer_heatmap(self, vulnerabilites: List[Vulnerabilite],
                       dimensions: Tuple[str, str] = ('url', 'severite')) -> Dict[str, Any]:
        """
        Génère une heatmap de risque

        Args:
            vulnerabilites: Liste des vulnérabilités
            dimensions: Dimensions pour la heatmap (par défaut: URL x Sévérité)

        Returns:
            Données de heatmap
        """
        dim1, dim2 = dimensions

        # Agréger les données
        matrice = {}
        max_valeur = 0

        for vuln in vulnerabilites:
            val_dim1 = getattr(vuln, dim1, 'unknown')
            val_dim2 = getattr(vuln, dim2, 'unknown')

            cle = (str(val_dim1), str(val_dim2))
            matrice[cle] = matrice.get(cle, 0) + 1
            max_valeur = max(max_valeur, matrice[cle])

        # Convertir en format heatmap
        heatmap_data = []
        labels_dim1 = set()
        labels_dim2 = set()

        for (d1, d2), count in matrice.items():
            labels_dim1.add(d1)
            labels_dim2.add(d2)

            intensite = count / max_valeur if max_valeur > 0 else 0
            couleur = self._obtenir_couleur_par_intensite(intensite)

            heatmap_data.append({
                'x': d1,
                'y': d2,
                'value': count,
                'intensity': intensite,
                'color': couleur
            })

        return {
            'dimensions': dimensions,
            'data': heatmap_data,
            'labels_x': sorted(list(labels_dim1)),
            'labels_y': sorted(list(labels_dim2)),
            'max_value': max_valeur,
            'total_points': len(heatmap_data)
        }

    def _obtenir_couleur_par_intensite(self, intensite: float) -> str:
        """Détermine la couleur selon l'intensité"""
        if intensite >= 0.8:
            return self.palette_couleurs['tres_critique']
        elif intensite >= 0.6:
            return self.palette_couleurs['critique']
        elif intensite >= 0.4:
            return self.palette_couleurs['eleve']
        elif intensite >= 0.2:
            return self.palette_couleurs['moyen']
        elif intensite >= 0.1:
            return self.palette_couleurs['faible']
        else:
            return self.palette_couleurs['tres_faible']


class OrchestrateurMetriquesCompliance:
    """
    Orchestrateur principal pour les métriques et la conformité
    """

    def __init__(self):
        self.calculateur_owasp = CalculateurOWASPRisk()
        self.calculateur_cvss = CalculateurCVSS()
        self.verificateur_compliance = VerificateurCompliance()
        self.generateur_benchmarks = GenerateurBenchmarks()
        self.generateur_heatmap = GenerateurHeatmap()

    async def analyser_risques_complets(self, vulnerabilites: List[Vulnerabilite],
                                      contexte: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Analyse complète des risques avec toutes les métriques

        Args:
            vulnerabilites: Liste des vulnérabilités à analyser
            contexte: Contexte d'analyse (secteur, menaces, etc.)

        Returns:
            Rapport d'analyse complet
        """
        contexte = contexte or {}
        secteur = contexte.get('secteur', 'web_application')

        rapport = {
            'date_analyse': datetime.now().isoformat(),
            'total_vulnerabilites': len(vulnerabilites),
            'contexte': contexte,
            'scores_owasp': [],
            'scores_cvss': [],
            'conformite': {},
            'benchmark': {},
            'heatmap': {},
            'recommandations_globales': []
        }

        # Calculer les scores OWASP pour chaque vulnérabilité
        for vuln in vulnerabilites:
            score_owasp = self.calculateur_owasp.calculer_risque_owasp(vuln, contexte)
            rapport['scores_owasp'].append({
                'vulnerabilite': vuln.type,
                'score': score_owasp.overall_score,
                'severite': score_owasp.severity.value,
                'likelihood': score_owasp.likelihood,
                'impact': score_owasp.impact
            })

        # Calculer les scores CVSS
        for vuln in vulnerabilites:
            score_cvss = self.calculateur_cvss.calculer_score_cvss(vuln, contexte)
            rapport['scores_cvss'].append({
                'vulnerabilite': vuln.type,
                'base_score': score_cvss.base_score,
                'severity': score_cvss.severity.value,
                'vector': score_cvss.vector
            })

        # Vérifier la conformité
        reglementations = ['pci_dss', 'gdpr', 'hipaa']
        for regle in reglementations:
            conformite = self.verificateur_compliance.verifier_conformite(vulnerabilites, regle)
            rapport['conformite'][regle] = conformite

        # Générer le benchmark
        rapport['benchmark'] = self.generateur_benchmarks.generer_benchmark(vulnerabilites, secteur)

        # Générer la heatmap
        rapport['heatmap'] = self.generateur_heatmap.generer_heatmap(vulnerabilites)

        # Générer les recommandations globales
        rapport['recommandations_globales'] = self._generer_recommandations_globales(rapport)

        return rapport

    def _generer_recommandations_globales(self, rapport: Dict) -> List[str]:
        """Génère des recommandations globales basées sur l'analyse complète"""
        recommandations = []

        # Analyser les scores OWASP
        scores_owasp = rapport.get('scores_owasp', [])
        if scores_owasp:
            avg_score = sum(s['score'] for s in scores_owasp) / len(scores_owasp)
            if avg_score > 25:  # Risque élevé
                recommandations.append("Risque OWASP élevé - Prioriser les corrections critiques")

        # Analyser la conformité
        conformite = rapport.get('conformite', {})
        for regle, data in conformite.items():
            if not data.get('conforme', True):
                score = data.get('score_conformite', 100)
                if score < 70:
                    recommandations.append(f"Non-conformité {regle.upper()}: {len(data.get('violations', []))} violations")

        # Analyser le benchmark
        benchmark = rapport.get('benchmark', {})
        maturite = benchmark.get('score_maturite', 100)
        if maturite < 60:
            recommandations.append("Score de maturité sécurité faible - Audit approfondi recommandé")

        # Recommandations générales
        if not recommandations:
            recommandations.append("Profil de sécurité satisfaisant - Maintenir les bonnes pratiques")

        return recommandations
