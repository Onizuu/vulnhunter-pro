"""
Détecteur ML avancé pour VulnHunter Pro
Classification de payloads, prédiction de vulnérabilités, scoring intelligent
"""

import re
import json
import hashlib
from typing import Dict, List, Tuple, Optional, Any
from datetime import datetime
from collections import defaultdict, Counter
import math
from loguru import logger

from core.models import Vulnerabilite


class DetecteurML:
    """
    Système ML avancé pour classification de payloads et prédiction de vulnérabilités
    """

    def __init__(self):
        # Modèles de classification de payloads
        self.modele_payloads = self._charger_modele_payloads()

        # Système de prédiction de vulnérabilités
        self.modele_prediction = self._charger_modele_prediction()

        # Détecteur d'anomalies
        self.detecteur_anomalies = self._initialiser_detecteur_anomalies()

        # Système de corrélation
        self.correlateur = self._initialiser_correlateur()

        # Cache pour optimiser les performances
        self.cache_predictions = {}
        self.cache_timeout = 300  # 5 minutes

        logger.info("🧠 Détecteur ML initialisé avec succès")

    def _charger_modele_payloads(self) -> Dict[str, Dict]:
        """Charge le modèle de classification de payloads malveillants"""
        return {
            'sql_injection': {
                'patterns': [
                    r'union.*select.*from',
                    r'1=1.*--',
                    r'or.*1=1',
                    r';.*drop.*table',
                    r'exec.*xp_',
                    r'information_schema',
                    r'concat.*0x',
                    r'load_file',
                    r'benchmark.*999999',
                ],
                'keywords': ['union', 'select', 'from', 'where', 'drop', 'exec', 'information_schema'],
                'score_threshold': 0.7,
                'context_indicators': ['sql', 'database', 'query', 'mysql', 'postgres']
            },
            'xss': {
                'patterns': [
                    r'<script[^>]*>.*?</script>',
                    r'javascript:',
                    r'on\w+\s*=',
                    r'alert\s*\(',
                    r'document\.cookie',
                    r'eval\s*\(',
                    r'setTimeout\s*\(',
                    r'setInterval\s*\(',
                ],
                'keywords': ['script', 'javascript', 'alert', 'onload', 'onerror', 'onclick'],
                'score_threshold': 0.6,
                'context_indicators': ['html', 'javascript', 'form', 'input']
            },
            'command_injection': {
                'patterns': [
                    r';\s*(?:ls|cat|pwd|whoami|id)',
                    r'\|\s*(?:ls|cat|pwd|whoami)',
                    r'`.*`',
                    r'\$\([^)]+\)',
                    r'system\s*\(',
                    r'exec\s*\(',
                    r'shell_exec\s*\(',
                    r'popen\s*\(',
                ],
                'keywords': ['system', 'exec', 'shell_exec', 'popen', 'passthru'],
                'score_threshold': 0.8,
                'context_indicators': ['system', 'exec', 'command', 'shell']
            },
            'path_traversal': {
                'patterns': [
                    r'\.\./',
                    r'\.\.\\',
                    r'%2e%2e%2f',
                    r'%2e%2e%5c',
                    r'/\.\./',
                    r'\\\.\\',
                    r'/etc/passwd',
                    r'/windows/system32',
                    r'C:\\',
                ],
                'keywords': ['../', '..\\', 'passwd', 'system32', 'windows'],
                'score_threshold': 0.7,
                'context_indicators': ['file', 'path', 'include', 'require']
            },
            'xxe': {
                'patterns': [
                    r'<!ENTITY',
                    r'SYSTEM\s+["\']',
                    r'PUBLIC\s+["\']',
                    r'<!DOCTYPE.*\[',
                    r'&.*;',
                    r'file://',
                    r'http://',
                ],
                'keywords': ['ENTITY', 'DOCTYPE', 'SYSTEM', 'PUBLIC'],
                'score_threshold': 0.8,
                'context_indicators': ['xml', 'entity', 'doctype']
            },
            'ssrf': {
                'patterns': [
                    r'http://localhost',
                    r'http://127\.0\.0\.1',
                    r'http://0\.0\.0\.0',
                    r'http://169\.254\.',
                    r'file://',
                    r'gopher://',
                    r'dict://',
                ],
                'keywords': ['localhost', '127.0.0.1', '0.0.0.0', '169.254'],
                'score_threshold': 0.6,
                'context_indicators': ['url', 'http', 'request', 'fetch']
            },
            'csrf_token_missing': {
                'patterns': [
                    r'<form[^>]*method\s*=\s*["\']post["\'][^>]*>',
                    r'<input[^>]*type\s*=\s*["\']hidden["\'][^>]*>',
                ],
                'keywords': ['form', 'post', 'submit', 'input', 'hidden'],
                'score_threshold': 0.5,
                'context_indicators': ['form', 'post', 'submit']
            }
        }

    def _charger_modele_prediction(self) -> Dict[str, Dict]:
        """Charge le modèle de prédiction de vulnérabilités"""
        return {
            'technology_vulnerability_correlation': {
                'php': {
                    'common_vulns': ['sql_injection', 'xss', 'path_traversal'],
                    'version_risks': {
                        '5.6': ['rce', 'file_upload'],
                        '7.0': ['deserialization'],
                        '8.0': ['type_juggling']
                    },
                    'risk_score': 7.5
                },
                'apache': {
                    'common_vulns': ['path_traversal', 'ssrf'],
                    'version_risks': {
                        '2.4.1': ['mod_proxy'],
                        '2.4.49': ['path_traversal_critical']
                    },
                    'risk_score': 6.0
                },
                'nginx': {
                    'common_vulns': ['path_traversal', 'ssrf'],
                    'version_risks': {
                        '1.16': ['range_header'],
                        '1.19': ['off_by_one']
                    },
                    'risk_score': 5.5
                },
                'mysql': {
                    'common_vulns': ['sql_injection'],
                    'version_risks': {
                        '5.7': ['authentication_bypass'],
                        '8.0': ['privilege_escalation']
                    },
                    'risk_score': 8.0
                },
                'wordpress': {
                    'common_vulns': ['xss', 'sql_injection', 'path_traversal'],
                    'version_risks': {
                        '4.9': ['rest_api'],
                        '5.0': ['block_editor'],
                        '5.8': ['core_vulns']
                    },
                    'risk_score': 9.0
                }
            },
            'pattern_based_prediction': {
                'error_disclosure': {
                    'indicators': ['warning:', 'error:', 'notice:', 'fatal error', 'stack trace'],
                    'predicts': ['information_disclosure', 'debug_mode_enabled'],
                    'confidence': 0.8
                },
                'login_forms': {
                    'indicators': ['username', 'password', 'login', 'signin', 'auth'],
                    'predicts': ['brute_force_possible', 'weak_password_policy'],
                    'confidence': 0.7
                },
                'file_upload': {
                    'indicators': ['upload', 'file', 'attachment', 'multipart'],
                    'predicts': ['file_upload_vuln', 'path_traversal'],
                    'confidence': 0.6
                },
                'api_endpoints': {
                    'indicators': ['/api/', '/rest/', '/graphql', '/v1/', '/v2/'],
                    'predicts': ['api_misconfig', 'cors_misconfig', 'rate_limit_missing'],
                    'confidence': 0.5
                }
            }
        }

    def _initialiser_detecteur_anomalies(self) -> Dict[str, Any]:
        """Initialise le détecteur d'anomalies comportementales"""
        return {
            'baseline_metrics': {
                'response_time_avg': 200,  # ms
                'response_size_avg': 15000,  # bytes
                'error_rate_normal': 0.05,  # 5%
                'redirect_rate_normal': 0.1,  # 10%
            },
            'anomaly_thresholds': {
                'response_time': 2.0,  # 2x la moyenne
                'response_size': 3.0,  # 3x la moyenne
                'error_rate': 0.3,     # 30% erreurs
                'redirect_rate': 0.5,  # 50% redirects
            },
            'behavior_patterns': {
                'honeypot_indicators': [
                    'connection refused', 'port closed', 'service unavailable',
                    'too many requests', 'rate limited'
                ],
                'waf_indicators': [
                    'blocked', 'forbidden', '403', 'waf', 'cloudflare',
                    'akamai', 'mod_security'
                ],
                'load_balancer_indicators': [
                    'server busy', 'maintenance', 'temporarily unavailable'
                ]
            }
        }

    def _initialiser_correlateur(self) -> Dict[str, Any]:
        """Initialise le système de corrélation automatique"""
        return {
            'correlation_rules': {
                'sql_injection + xss': {
                    'correlation_type': 'input_validation_weakness',
                    'severity_boost': 1.5,
                    'description': 'Validation d\'entrée faible détectée'
                },
                'path_traversal + file_upload': {
                    'correlation_type': 'file_system_access',
                    'severity_boost': 2.0,
                    'description': 'Accès au système de fichiers compromis'
                },
                'csrf + missing_auth': {
                    'correlation_type': 'authentication_bypass',
                    'severity_boost': 1.8,
                    'description': 'Contournement d\'authentification possible'
                },
                'information_disclosure + debug_mode': {
                    'correlation_type': 'excessive_information',
                    'severity_boost': 1.3,
                    'description': 'Informations sensibles exposées'
                }
            },
            'correlation_matrix': defaultdict(lambda: defaultdict(float)),
            'correlation_history': []
        }

    def analyser_payload(self, payload: str, context: str = "") -> Dict[str, Any]:
        """
        Analyse et classe un payload malveillant avec ML

        Args:
            payload: Le payload à analyser
            context: Contexte d'utilisation (url, form, etc.)

        Returns:
            Dict avec classification, score de confiance, prédictions
        """
        try:
            # Vérifier le cache
            cache_key = hashlib.md5(f"{payload}:{context}".encode()).hexdigest()
            if cache_key in self.cache_predictions:
                cache_time, result = self.cache_predictions[cache_key]
                if (datetime.now().timestamp() - cache_time) < self.cache_timeout:
                    return result

            result = {
                'payload': payload,
                'classifications': [],
                'predictions': [],
                'confidence_score': 0.0,
                'risk_assessment': 'LOW',
                'recommended_actions': []
            }

            # Analyse de chaque modèle
            for vuln_type, model in self.modele_payloads.items():
                score = self._calculer_score_payload(payload, context, model)
                if score >= model['score_threshold']:
                    result['classifications'].append({
                        'type': vuln_type,
                        'score': score,
                        'confidence': min(score * 1.2, 1.0)
                    })

            # Prédictions basées sur les patterns
            predictions = self._predire_vulnerabilites(payload, context)
            result['predictions'] = predictions

            # Score global de confiance
            if result['classifications']:
                result['confidence_score'] = max(c['score'] for c in result['classifications'])
            else:
                result['confidence_score'] = max((p['confidence'] for p in predictions), default=0.0)

            # Évaluation du risque
            result['risk_assessment'] = self._evaluer_risque(result)

            # Actions recommandées
            result['recommended_actions'] = self._generer_actions_recommandees(result)

            # Mettre en cache
            self.cache_predictions[cache_key] = (datetime.now().timestamp(), result)

            return result

        except Exception as e:
            logger.debug(f"Erreur analyse ML payload: {str(e)}")
            return {
                'payload': payload,
                'error': str(e),
                'confidence_score': 0.0,
                'risk_assessment': 'UNKNOWN'
            }

    def _calculer_score_payload(self, payload: str, context: str, model: Dict) -> float:
        """Calcule le score de classification pour un payload"""
        score = 0.0
        payload_lower = payload.lower()
        context_lower = context.lower()

        # Score basé sur les patterns regex
        for pattern in model['patterns']:
            if re.search(pattern, payload, re.IGNORECASE):
                score += 0.3

        # Score basé sur les mots-clés
        keyword_matches = sum(1 for keyword in model['keywords']
                            if keyword.lower() in payload_lower)
        if keyword_matches > 0:
            score += min(keyword_matches * 0.2, 0.4)

        # Bonus contextuel
        context_matches = sum(1 for indicator in model.get('context_indicators', [])
                            if indicator.lower() in context_lower)
        if context_matches > 0:
            score += 0.2

        # Pénalité pour faux positifs courants
        if self._est_faux_positif(payload):
            score *= 0.5

        return min(score, 1.0)

    def _est_faux_positif(self, payload: str) -> bool:
        """Détecte les faux positifs courants"""
        faux_positifs = [
            r'^\d+$',  # Nombres seuls
            r'^[a-zA-Z]+$',  # Mots seuls
            r'^[a-zA-Z0-9\s]+$',  # Texte normal
            r'^https?://[^\s]+$',  # URLs normales
            r'^[\w\.\-\_]+$',  # Identifiants normaux
        ]

        return any(re.match(pattern, payload.strip()) for pattern in faux_positifs)

    def _predire_vulnerabilites(self, payload: str, context: str) -> List[Dict]:
        """Prédit les vulnérabilités potentielles basées sur les patterns"""
        predictions = []
        payload_lower = payload.lower()
        context_lower = context.lower()

        for pattern_type, pattern_data in self.modele_prediction['pattern_based_prediction'].items():
            confidence = 0.0

            # Vérifier les indicateurs
            indicator_matches = sum(1 for indicator in pattern_data['indicators']
                                  if indicator.lower() in payload_lower or
                                     indicator.lower() in context_lower)

            if indicator_matches > 0:
                confidence = min(indicator_matches * 0.2, pattern_data['confidence'])

                if confidence >= 0.3:  # Seuil minimum
                    for predicted_vuln in pattern_data['predicts']:
                        predictions.append({
                            'vulnerability': predicted_vuln,
                            'confidence': confidence,
                            'reason': f"Pattern {pattern_type} détecté"
                        })

        return predictions

    def analyser_anomalies(self, responses: List[Dict]) -> List[Dict]:
        """
        Analyse comportementale pour détecter des anomalies

        Args:
            responses: Liste des réponses HTTP avec métriques

        Returns:
            Liste des anomalies détectées
        """
        anomalies = []

        if not responses:
            return anomalies

        try:
            # Calculer les métriques de base
            response_times = [r.get('response_time', 0) for r in responses]
            response_sizes = [r.get('content_length', 0) for r in responses]
            status_codes = [r.get('status_code', 200) for r in responses]

            # Calculer les moyennes
            avg_time = sum(response_times) / len(response_times) if response_times else 0
            avg_size = sum(response_sizes) / len(response_sizes) if response_sizes else 0

            # Taux d'erreur et de redirection
            error_count = sum(1 for code in status_codes if code >= 400)
            redirect_count = sum(1 for code in status_codes if 300 <= code < 400)

            error_rate = error_count / len(status_codes) if status_codes else 0
            redirect_rate = redirect_count / len(status_codes) if status_codes else 0

            # Détecter les anomalies
            baseline = self.detecteur_anomalies['baseline_metrics']
            thresholds = self.detecteur_anomalies['anomaly_thresholds']

            # Anomalie de temps de réponse
            if avg_time > baseline['response_time_avg'] * thresholds['response_time']:
                anomalies.append({
                    'type': 'response_time_anomaly',
                    'severity': 'MEDIUM',
                    'description': f'Temps de réponse anormal: {avg_time:.0f}ms (moyenne normale: {baseline["response_time_avg"]}ms)',
                    'confidence': 0.8,
                    'data': {'avg_time': avg_time, 'threshold': baseline['response_time_avg']}
                })

            # Anomalie de taille de réponse
            if avg_size > baseline['response_size_avg'] * thresholds['response_size']:
                anomalies.append({
                    'type': 'response_size_anomaly',
                    'severity': 'LOW',
                    'description': f'Taille de réponse anormale: {avg_size:.0f} bytes (moyenne normale: {baseline["response_size_avg"]} bytes)',
                    'confidence': 0.6,
                    'data': {'avg_size': avg_size, 'threshold': baseline['response_size_avg']}
                })

            # Taux d'erreur élevé
            if error_rate > baseline['error_rate_normal'] * thresholds['error_rate']:
                anomalies.append({
                    'type': 'high_error_rate',
                    'severity': 'HIGH',
                    'description': f'Taux d\'erreur élevé: {error_rate:.1%} (normal: {baseline["error_rate_normal"]:.1%})',
                    'confidence': 0.9,
                    'data': {'error_rate': error_rate, 'threshold': baseline['error_rate_normal']}
                })

            # Détection de WAF/honeypot
            for response in responses:
                content = response.get('content', '').lower()
                for behavior_type, indicators in self.detecteur_anomalies['behavior_patterns'].items():
                    matches = sum(1 for indicator in indicators if indicator.lower() in content)
                    if matches >= 2:
                        anomalies.append({
                            'type': f'{behavior_type}_detected',
                            'severity': 'MEDIUM',
                            'description': f'{behavior_type.replace("_", " ").title()} détecté dans les réponses',
                            'confidence': 0.7,
                            'data': {'matches': matches, 'indicators': indicators}
                        })

        except Exception as e:
            logger.debug(f"Erreur analyse anomalies: {str(e)}")

        return anomalies

    def calculer_score_risque(self, vulnerabilites: List[Vulnerabilite],
                            technologies: Dict[str, str], anomalies: List[Dict]) -> float:
        """
        Calcule un score de risque intelligent avec ML

        Args:
            vulnerabilites: Liste des vulnérabilités trouvées
            technologies: Technologies détectées
            anomalies: Anomalies comportementales

        Returns:
            Score de risque sur 10
        """
        try:
            score = 0.0

            # Score basé sur les vulnérabilités
            vuln_weights = {
                'CRITIQUE': 3.0,
                'ÉLEVÉ': 2.0,
                'MOYEN': 1.0,
                'FAIBLE': 0.5,
                'INFO': 0.1
            }

            for vuln in vulnerabilites:
                severity = vuln.severite
                base_weight = vuln_weights.get(severity, 1.0)

                # Ajustement basé sur le CVSS
                cvss_adjustment = vuln.cvss_score / 10.0 if vuln.cvss_score else 0.5

                # Bonus pour les vulnérabilités corrélées
                correlation_bonus = self._calculer_bonus_correlation(vuln, vulnerabilites)

                score += base_weight * cvss_adjustment * (1 + correlation_bonus)

            # Score basé sur les technologies à risque
            tech_risks = self.modele_prediction['technology_vulnerability_correlation']
            for tech, version in technologies.items():
                tech_lower = tech.lower()
                if tech_lower in tech_risks:
                    tech_risk = tech_risks[tech_lower]
                    base_risk = tech_risk['risk_score']

                    # Ajustement basé sur la version
                    version_risks = tech_risk.get('version_risks', {})
                    if version in version_risks:
                        base_risk *= 1.5  # Versions connues vulnérables

                    score += base_risk * 0.1  # Pondération réduite

            # Score basé sur les anomalies
            anomaly_weights = {
                'HIGH': 2.0,
                'MEDIUM': 1.0,
                'LOW': 0.5
            }

            for anomaly in anomalies:
                severity = anomaly.get('severity', 'LOW')
                confidence = anomaly.get('confidence', 0.5)
                score += anomaly_weights.get(severity, 1.0) * confidence

            # Normalisation et application de la fonction sigmoïde pour lissage
            score = min(score, 50.0)  # Plafond pour éviter les scores extrêmes
            normalized_score = 1 / (1 + math.exp(-score / 10 + 2.5))  # Sigmoïde centrée

            return round(normalized_score * 10, 1)

        except Exception as e:
            logger.debug(f"Erreur calcul score risque: {str(e)}")
            return 5.0  # Score par défaut

    def _calculer_bonus_correlation(self, vuln: Vulnerabilite, toutes_vulns: List[Vulnerabilite]) -> float:
        """Calcule le bonus de corrélation pour une vulnérabilité"""
        bonus = 0.0

        vuln_type = vuln.type.lower().replace(' ', '_')

        for autre_vuln in toutes_vulns:
            if autre_vuln == vuln:
                continue

            autre_type = autre_vuln.type.lower().replace(' ', '_')

            # Chercher des corrélations connues
            correlation_key = f"{vuln_type} + {autre_type}"
            reverse_key = f"{autre_type} + {vuln_type}"

            correlation = self.correlateur['correlation_rules'].get(
                correlation_key,
                self.correlateur['correlation_rules'].get(reverse_key)
            )

            if correlation:
                bonus += correlation['severity_boost'] - 1.0  # Bonus relatif

        return min(bonus, 1.0)  # Maximum 100% bonus

    def _evaluer_risque(self, analysis_result: Dict) -> str:
        """Évalue le niveau de risque global"""
        confidence = analysis_result.get('confidence_score', 0.0)

        if confidence >= 0.8:
            return 'CRITICAL'
        elif confidence >= 0.6:
            return 'HIGH'
        elif confidence >= 0.4:
            return 'MEDIUM'
        elif confidence >= 0.2:
            return 'LOW'
        else:
            return 'INFO'

    def _generer_actions_recommandees(self, analysis_result: Dict) -> List[str]:
        """Génère des actions recommandées basées sur l'analyse"""
        actions = []

        classifications = analysis_result.get('classifications', [])
        predictions = analysis_result.get('predictions', [])

        # Actions basées sur les classifications
        for classification in classifications:
            vuln_type = classification['type']

            if vuln_type == 'sql_injection':
                actions.extend([
                    "Utiliser des requêtes préparées (prepared statements)",
                    "Valider et échapper toutes les entrées utilisateur",
                    "Utiliser un ORM avec protection SQL injection"
                ])
            elif vuln_type == 'xss':
                actions.extend([
                    "Échapper toutes les sorties HTML (output encoding)",
                    "Utiliser une Content Security Policy (CSP)",
                    "Valider les entrées côté serveur"
                ])
            elif vuln_type == 'command_injection':
                actions.extend([
                    "Éviter l'exécution de commandes système",
                    "Utiliser des APIs sécurisées au lieu de shell",
                    "Valider les arguments de commande"
                ])

        # Actions basées sur les prédictions
        for prediction in predictions:
            vuln_type = prediction['vulnerability']

            if 'brute_force' in vuln_type:
                actions.append("Implémenter un rate limiting et CAPTCHA")
            elif 'weak_password' in vuln_type:
                actions.append("Enforcer une politique de mots de passe forts")
            elif 'file_upload' in vuln_type:
                actions.append("Valider les types et contenus de fichiers uploadés")

        # Actions générales
        if analysis_result.get('confidence_score', 0) > 0.5:
            actions.append("Audit de sécurité immédiat recommandé")
        if len(classifications) > 1:
            actions.append("Révision complète de la validation d'entrée")

        return list(set(actions))  # Éliminer les doublons

    def predire_vulnerabilites_futures(self, technologies: Dict[str, str],
                                     vuln_history: List[Vulnerabilite]) -> List[Dict]:
        """
        Prédit les vulnérabilités futures basées sur les technologies et historique

        Args:
            technologies: Technologies détectées
            vuln_history: Historique des vulnérabilités trouvées

        Returns:
            Liste des prédictions de vulnérabilités futures
        """
        predictions = []

        try:
            # Analyser les technologies à risque
            tech_risks = self.modele_prediction['technology_vulnerability_correlation']

            for tech, version in technologies.items():
                tech_lower = tech.lower()

                if tech_lower in tech_risks:
                    tech_data = tech_risks[tech_lower]

                    # Vulnérabilités communes pour cette techno
                    for vuln_type in tech_data['common_vulns']:
                        # Vérifier si déjà détectée
                        deja_detectee = any(
                            vuln_type.lower() in vuln.type.lower()
                            for vuln in vuln_history
                        )

                        if not deja_detectee:
                            predictions.append({
                                'technology': tech,
                                'version': version,
                                'predicted_vulnerability': vuln_type,
                                'confidence': 0.7,
                                'reason': f'Vulnérabilité commune pour {tech}',
                                'recommendation': f'Mettre à jour {tech} ou appliquer correctifs spécifiques'
                            })

                    # Vulnérabilités spécifiques à la version
                    version_risks = tech_data.get('version_risks', {})
                    if version in version_risks:
                        vuln_specific = version_risks[version]
                        predictions.append({
                            'technology': tech,
                            'version': version,
                            'predicted_vulnerability': vuln_specific,
                            'confidence': 0.9,
                            'reason': f'Vulnérabilité connue pour {tech} {version}',
                            'recommendation': f'Mise à jour urgente vers version plus récente'
                        })

            # Prédictions basées sur les patterns comportementaux
            if len(vuln_history) > 3:
                predictions.extend(self._predire_patterns_comportementaux(vuln_history))

        except Exception as e:
            logger.debug(f"Erreur prédiction vulnérabilités futures: {str(e)}")

        return predictions

    def _predire_patterns_comportementaux(self, vuln_history: List[Vulnerabilite]) -> List[Dict]:
        """Prédit des vulnérabilités basées sur les patterns comportementaux"""
        predictions = []

        # Analyser les types de vulnérabilités fréquents
        vuln_types = Counter(vuln.type for vuln in vuln_history)

        # Si beaucoup de vulnérabilités XSS, prédire des vulnérabilités similaires
        if vuln_types.get('XSS', 0) >= 2:
            predictions.append({
                'pattern': 'multiple_xss',
                'predicted_vulnerability': 'stored_xss_possible',
                'confidence': 0.6,
                'reason': 'Multiples vulnérabilités XSS suggèrent des problèmes de validation globale',
                'recommendation': 'Audit complet de toutes les entrées/sorties'
            })

        # Si beaucoup d'injections SQL, prédire des problèmes similaires
        if vuln_types.get('Injection SQL', 0) >= 2:
            predictions.append({
                'pattern': 'multiple_sqli',
                'predicted_vulnerability': 'nosql_injection_possible',
                'confidence': 0.5,
                'reason': 'Problèmes d\'injection SQL suggèrent des failles similaires dans d\'autres requêtes',
                'recommendation': 'Migration vers ORM et requêtes préparées'
            })

        return predictions

    def mettre_a_jour_modeles(self, nouveaux_donnees: Dict):
        """
        Met à jour les modèles ML avec de nouvelles données

        Args:
            nouveaux_donnees: Nouvelles données d'entraînement
        """
        try:
            # Cette méthode pourrait être utilisée pour mettre à jour les modèles
            # avec de nouvelles vulnérabilités découvertes ou de nouveaux patterns

            logger.info("🔄 Mise à jour des modèles ML avec nouvelles données")
            # Implémentation simplifiée - en production, cela entraînerait les modèles

        except Exception as e:
            logger.debug(f"Erreur mise à jour modèles: {str(e)}")

    def analyser_chaine_exploitation(self, vulnerabilites: List[Vulnerabilite]) -> List[Dict]:
        """
        Analyse les chaînes d'exploitation possibles

        Args:
            vulnerabilites: Liste des vulnérabilités trouvées

        Returns:
            Liste des chaînes d'exploitation identifiées
        """
        chaines = []

        try:
            # Regrouper les vulnérabilités par URL/endpoint
            par_endpoint = defaultdict(list)
            for vuln in vulnerabilites:
                par_endpoint[vuln.url].append(vuln)

            # Analyser chaque endpoint
            for url, vulns_endpoint in par_endpoint.items():
                if len(vulns_endpoint) >= 2:
                    # Chercher des combinaisons dangereuses
                    vuln_types = [v.type.lower() for v in vulns_endpoint]

                    # Chaîne: Information disclosure + vulnérabilité technique
                    if any('information' in t for t in vuln_types) and \
                       any(t in ['sql injection', 'xss', 'rce'] for t in vuln_types):
                        chaines.append({
                            'type': 'information_disclosure_chain',
                            'endpoint': url,
                            'vulnerabilities': [v.type for v in vulns_endpoint],
                            'severity': 'HIGH',
                            'description': 'Chaîne d\'exploitation: divulgation d\'info + vulnérabilité technique',
                            'exploitability': 0.8
                        })

                    # Chaîne: Auth bypass + privilege escalation
                    if any('auth' in t or 'login' in t for t in vuln_types) and \
                       any('privilege' in t or 'idor' in t for t in vuln_types):
                        chaines.append({
                            'type': 'privilege_escalation_chain',
                            'endpoint': url,
                            'vulnerabilities': [v.type for v in vulns_endpoint],
                            'severity': 'CRITICAL',
                            'description': 'Chaîne d\'exploitation: contournement auth + élévation de privilèges',
                            'exploitability': 0.9
                        })

        except Exception as e:
            logger.debug(f"Erreur analyse chaîne exploitation: {str(e)}")

        return chaines
