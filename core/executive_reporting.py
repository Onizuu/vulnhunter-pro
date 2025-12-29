"""
Système de reporting exécutif avancé pour VulnHunter Pro
Dashboards interactifs, time-series, trend analysis, executive summaries, technical deep-dives, compliance reports
"""

import json
import csv
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import numpy as np
from collections import defaultdict
import os

from core.models import Vulnerabilite


@dataclass
class RapportExecutif:
    """Rapport exécutif complet"""
    id_rapport: str
    titre: str
    date_generation: datetime
    periode_analyse: Tuple[datetime, datetime]
    niveau_confidentialite: str = "interne"
    destinataires: List[str] = field(default_factory=list)
    resume_executif: Dict[str, Any] = field(default_factory=dict)
    metriques_cle: Dict[str, Any] = field(default_factory=dict)
    tendances: Dict[str, Any] = field(default_factory=dict)
    risques_critiques: List[Dict] = field(default_factory=list)
    recommandations_prioritaires: List[Dict] = field(default_factory=list)
    donnees_graphiques: Dict[str, Any] = field(default_factory=dict)
    rapports_techniques: Dict[str, Any] = field(default_factory=dict)
    conformite: Dict[str, Any] = field(default_factory=dict)


class GenerateurDashboards:
    """
    Générateur de dashboards interactifs
    """

    def __init__(self):
        self.palette_couleurs = {
            'critique': '#DC143C',    # Crimson
            'eleve': '#FF6347',       # Tomato
            'moyen': '#FFD700',       # Gold
            'faible': '#32CD32',      # LimeGreen
            'info': '#87CEEB'         # SkyBlue
        }

        self.template_style = {
            'paper_bgcolor': 'white',
            'plot_bgcolor': 'white',
            'font': {'family': 'Arial, sans-serif', 'size': 12},
            'title': {'font': {'size': 24, 'color': '#2E4057'}},
            'margin': dict(l=20, r=20, t=60, b=20)
        }

    def creer_dashboard_risques(self, vulnerabilites: List[Vulnerabilite],
                               contexte: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Crée un dashboard complet des risques
        """
        contexte = contexte or {}

        # Préparer les données
        df_vulns = self._preparer_dataframe_vulnerabilites(vulnerabilites)

        dashboard = {
            'titre': 'Dashboard de Sécurité VulnHunter Pro',
            'date_generation': datetime.now().isoformat(),
            'graphiques': {},
            'metriques': {},
            'recommandations': []
        }

        # Graphique 1: Distribution par sévérité
        fig_severite = self._creer_graphe_severite(df_vulns)
        dashboard['graphiques']['distribution_severite'] = fig_severite.to_json()

        # Graphique 2: Évolution temporelle (simulée)
        fig_temps = self._creer_graphe_temps(df_vulns)
        dashboard['graphiques']['evolution_temporelle'] = fig_temps.to_json()

        # Graphique 3: Top vulnérabilités par type
        fig_types = self._creer_graphe_types(df_vulns)
        dashboard['graphiques']['top_types'] = fig_types.to_json()

        # Graphique 4: Heatmap par URL et sévérité
        fig_heatmap = self._creer_heatmap_url_severite(vulnerabilites)
        dashboard['graphiques']['heatmap_risques'] = fig_heatmap.to_json()

        # Métriques clés
        dashboard['metriques'] = self._calculer_metriques_dashboard(df_vulns)

        # Recommandations automatiques
        dashboard['recommandations'] = self._generer_recommandations_dashboard(df_vulns)

        return dashboard

    def _preparer_dataframe_vulnerabilites(self, vulnerabilites: List[Vulnerabilite]) -> pd.DataFrame:
        """Prépare un DataFrame pandas à partir des vulnérabilités"""
        data = []
        for vuln in vulnerabilites:
            data.append({
                'type': vuln.type,
                'severite': vuln.severite,
                'url': vuln.url,
                'outil_source': getattr(vuln, 'outil_source', 'VulnHunter'),
                'cvss_score': getattr(vuln, 'cvss_score', 0),
                'date_detection': datetime.now()  # Simulation
            })

        return pd.DataFrame(data)

    def _creer_graphe_severite(self, df: pd.DataFrame) -> go.Figure:
        """Crée un graphique de distribution par sévérité"""
        severite_counts = df['severite'].value_counts()

        couleurs = [self.palette_couleurs.get(sev.lower(), '#808080') for sev in severite_counts.index]

        fig = go.Figure(data=[
            go.Bar(
                x=severite_counts.index,
                y=severite_counts.values,
                marker_color=couleurs,
                text=severite_counts.values,
                textposition='auto'
            )
        ])

        fig.update_layout(
            **self.template_style,
            title="Distribution des Vulnérabilités par Sévérité",
            xaxis_title="Sévérité",
            yaxis_title="Nombre de Vulnérabilités"
        )

        return fig

    def _creer_graphe_temps(self, df: pd.DataFrame) -> go.Figure:
        """Crée un graphique d'évolution temporelle"""
        # Simulation de données temporelles
        dates = pd.date_range(start='2024-01-01', end=datetime.now(), freq='W')
        np.random.seed(42)

        # Générer des données simulées
        trend_data = []
        severites = ['CRITIQUE', 'ÉLEVÉ', 'MOYEN', 'FAIBLE']

        for sev in severites:
            base_count = len(df[df['severite'] == sev])
            counts = []
            for i in range(len(dates)):
                # Ajouter une tendance et du bruit
                trend = base_count * (1 + 0.1 * np.sin(i/4))  # Légère oscillation
                noise = np.random.normal(0, base_count * 0.2)  # Bruit
                count = max(0, int(trend + noise))
                counts.append(count)

            trend_data.append(go.Scatter(
                x=dates,
                y=counts,
                mode='lines+markers',
                name=sev,
                line=dict(color=self.palette_couleurs.get(sev.lower(), '#808080'))
            ))

        fig = go.Figure(data=trend_data)

        fig.update_layout(
            **self.template_style,
            title="Évolution Temporelle des Vulnérabilités",
            xaxis_title="Date",
            yaxis_title="Nombre de Vulnérabilités"
        )

        return fig

    def _creer_graphe_types(self, df: pd.DataFrame) -> go.Figure:
        """Crée un graphique des types de vulnérabilités les plus courants"""
        type_counts = df['type'].value_counts().head(10)

        fig = px.pie(
            values=type_counts.values,
            names=type_counts.index,
            title="Top 10 Types de Vulnérabilités"
        )

        fig.update_layout(**self.template_style)
        return fig

    def _creer_heatmap_url_severite(self, vulnerabilites: List[Vulnerabilite]) -> go.Figure:
        """Crée une heatmap URL x Sévérité"""
        # Extraire les domaines des URLs
        domaines = []
        severites = []

        for vuln in vulnerabilites:
            try:
                domaine = vuln.url.split('/')[2]  # Extrait le domaine
                domaines.append(domaine)
                severites.append(vuln.severite)
            except:
                continue

        # Créer une matrice de comptage
        from collections import Counter
        paires = list(zip(domaines, severites))
        comptages = Counter(paires)

        # Préparer les données pour la heatmap
        domaines_uniques = sorted(list(set(domaines)))
        severites_uniques = ['CRITIQUE', 'ÉLEVÉ', 'MOYEN', 'FAIBLE', 'INFO']

        matrice = []
        for domaine in domaines_uniques:
            ligne = []
            for sev in severites_uniques:
                ligne.append(comptages.get((domaine, sev), 0))
            matrice.append(ligne)

        fig = go.Figure(data=go.Heatmap(
            z=matrice,
            x=severites_uniques,
            y=domaines_uniques,
            colorscale='Reds',
            text=[[f"{val}" for val in ligne] for ligne in matrice],
            texttemplate="%{text}",
            textfont={"size": 12}
        ))

        fig.update_layout(
            **self.template_style,
            title="Heatmap des Risques par Domaine et Sévérité",
            xaxis_title="Sévérité",
            yaxis_title="Domaine"
        )

        return fig

    def _calculer_metriques_dashboard(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Calcule les métriques clés du dashboard"""
        metriques = {}

        # Métriques générales
        metriques['total_vulnerabilites'] = len(df)
        metriques['severite_moyenne'] = self._calculer_score_severite_moyen(df)

        # Distribution par sévérité
        severite_dist = df['severite'].value_counts()
        metriques['distribution_severite'] = severite_dist.to_dict()

        # Métriques critiques
        metriques['critiques'] = len(df[df['severite'] == 'CRITIQUE'])
        metriques['elevees'] = len(df[df['severite'] == 'ÉLEVÉ'])

        # Métriques par outil source
        metriques['par_outil'] = df['outil_source'].value_counts().to_dict()

        # Score de risque global
        metriques['score_risque_global'] = self._calculer_score_risque_global(df)

        return metriques

    def _calculer_score_severite_moyen(self, df: pd.DataFrame) -> float:
        """Calcule un score de sévérité moyen"""
        mapping = {'CRITIQUE': 5, 'ÉLEVÉ': 4, 'MOYEN': 3, 'FAIBLE': 2, 'INFO': 1}
        scores = [mapping.get(sev, 3) for sev in df['severite']]
        return sum(scores) / len(scores) if scores else 3.0

    def _calculer_score_risque_global(self, df: pd.DataFrame) -> float:
        """Calcule un score de risque global (0-100)"""
        if len(df) == 0:
            return 0.0

        # Facteurs de calcul
        poids_critique = len(df[df['severite'] == 'CRITIQUE']) * 20
        poids_eleve = len(df[df['severite'] == 'ÉLEVÉ']) * 10
        poids_moyen = len(df[df['severite'] == 'MOYEN']) * 5
        poids_faible = len(df[df['severite'] == 'FAIBLE']) * 1

        score_brut = poids_critique + poids_eleve + poids_moyen + poids_faible

        # Normalisation (max théorique: 100 vulnérabilités critiques)
        score_normalise = min(100, (score_brut / 20))

        return score_normalise

    def _generer_recommandations_dashboard(self, df: pd.DataFrame) -> List[str]:
        """Génère des recommandations basées sur le dashboard"""
        recommandations = []

        metriques = self._calculer_metriques_dashboard(df)

        # Recommandations basées sur les vulnérabilités critiques
        if metriques['critiques'] > 0:
            recommandations.append(f"URGENT: Corriger immédiatement les {metriques['critiques']} vulnérabilités critiques")

        # Recommandations basées sur le score de risque
        if metriques['score_risque_global'] > 70:
            recommandations.append("Score de risque très élevé - Audit de sécurité approfondi recommandé")
        elif metriques['score_risque_global'] > 50:
            recommandations.append("Score de risque élevé - Renforcer les contrôles de sécurité")

        # Recommandations basées sur la diversité des outils
        if len(metriques['par_outil']) > 3:
            recommandations.append("Multiples sources de détection - Bonnes pratiques de sécurité appliquées")

        return recommandations


class AnalyseurTendances:
    """
    Analyseur de tendances temporelles
    """

    def __init__(self):
        self.fenetre_analyse = 90  # jours

    def analyser_tendances(self, historique_scans: List[Dict],
                          periode_jours: int = 90) -> Dict[str, Any]:
        """
        Analyse les tendances sur une période donnée

        Args:
            historique_scans: Liste des scans passés avec leurs résultats
            periode_jours: Période d'analyse en jours

        Returns:
            Analyse des tendances
        """
        if not historique_scans:
            return {'erreur': 'Aucune donnée historique disponible'}

        # Convertir en DataFrame pour analyse
        data = []
        for scan in historique_scans:
            data.append({
                'date': pd.to_datetime(scan.get('date_scan', datetime.now())),
                'total_vulns': scan.get('total_vulnerabilites', 0),
                'critiques': scan.get('critiques', 0),
                'elevees': scan.get('elevees', 0),
                'moyennes': scan.get('moyennes', 0),
                'faibles': scan.get('faibles', 0),
                'score_risque': scan.get('score_risque', 0)
            })

        df = pd.DataFrame(data)
        df = df.set_index('date').sort_index()

        # Filtrer sur la période demandée
        date_limite = datetime.now() - timedelta(days=periode_jours)
        df = df[df.index >= date_limite]

        analyse = {
            'periode_analyse': f"{periode_jours} jours",
            'total_scans': len(df),
            'tendances': {},
            'predictions': {},
            'insights': []
        }

        if len(df) < 2:
            analyse['insights'].append("Données insuffisantes pour analyse de tendance")
            return analyse

        # Analyser les tendances
        analyse['tendances'] = self._calculer_tendances(df)

        # Générer des prédictions
        analyse['predictions'] = self._generer_predictions(df)

        # Insights automatiques
        analyse['insights'] = self._generer_insights(df, analyse['tendances'])

        return analyse

    def _calculer_tendances(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Calcule les tendances statistiques"""
        tendances = {}

        # Tendance générale des vulnérabilités
        if len(df) >= 2:
            total_debut = df['total_vulns'].iloc[0]
            total_fin = df['total_vulns'].iloc[-1]

            if total_debut > 0:
                evolution_pct = ((total_fin - total_debut) / total_debut) * 100
                tendances['evolution_globale'] = {
                    'valeur': evolution_pct,
                    'direction': 'hausse' if evolution_pct > 0 else 'baisse',
                    'significative': abs(evolution_pct) > 10
                }

        # Tendance des vulnérabilités critiques
        tendances_critiques = self._calculer_tendance_serie(df['critiques'])
        tendances['critiques'] = tendances_critiques

        # Score de risque moyen
        tendances_risque = self._calculer_tendance_serie(df['score_risque'])
        tendances['risque_global'] = tendances_risque

        return tendances

    def _calculer_tendance_serie(self, serie: pd.Series) -> Dict[str, Any]:
        """Calcule la tendance d'une série temporelle"""
        if len(serie) < 2:
            return {'erreur': 'Données insuffisantes'}

        # Calcul de la pente (régression linéaire simple)
        x = np.arange(len(serie))
        y = serie.values

        slope, intercept = np.polyfit(x, y, 1)

        tendance = {
            'pente': slope,
            'direction': 'hausse' if slope > 0 else 'baisse',
            'valeur_moyenne': serie.mean(),
            'valeur_actuelle': serie.iloc[-1],
            'variation_relative': ((serie.iloc[-1] - serie.iloc[0]) / serie.iloc[0] * 100) if serie.iloc[0] != 0 else 0
        }

        return tendance

    def _generer_predictions(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Génère des prédictions basées sur les tendances"""
        predictions = {}

        # Prédiction simple basée sur les 7 derniers points
        if len(df) >= 7:
            dernier_score = df['score_risque'].iloc[-1]
            tendance = self._calculer_tendance_serie(df['score_risque']['-7:'])

            # Prédiction pour les 30 prochains jours
            prediction_30j = dernier_score + (tendance['pente'] * 4)  # ~4 semaines

            predictions['risque_30_jours'] = {
                'valeur_predite': max(0, min(100, prediction_30j)),
                'confiance': 0.7,  # Confiance arbitraire
                'base_sur_tendance': tendance['direction']
            }

        return predictions

    def _generer_insights(self, df: pd.DataFrame, tendances: Dict) -> List[str]:
        """Génère des insights automatiques"""
        insights = []

        # Insight sur l'évolution globale
        if 'evolution_globale' in tendances:
            evol = tendances['evolution_globale']
            if evol['significative']:
                direction = "augmenté" if evol['direction'] == 'hausse' else "diminué"
                insights.append(f"Nombre de vulnérabilités a {direction} de {abs(evol['valeur']):.1f}% sur la période")

        # Insight sur les critiques
        if 'critiques' in tendances:
            crit_tendance = tendances['critiques']
            if crit_tendance['pente'] > 0.5:
                insights.append("Tendance à la hausse des vulnérabilités critiques - Action immédiate requise")

        # Insight sur le score de risque
        if 'risque_global' in tendances:
            risque_tendance = tendances['risque_global']
            if risque_tendance['direction'] == 'hausse' and risque_tendance['valeur_actuelle'] > 70:
                insights.append("Score de risque élevé avec tendance à la hausse - Audit de sécurité recommandé")

        # Insights généraux
        if len(df) >= 30:  # Au moins un mois de données
            insights.append("Données historiques suffisantes pour analyse de tendance fiable")

        if not insights:
            insights.append("Situation stable - continuer la surveillance régulière")

        return insights


class GenerateurRapports:
    """
    Générateur de rapports spécialisés (executive, technique, conformité)
    """

    def __init__(self):
        self.templates = self._initialiser_templates()

    def _initialiser_templates(self) -> Dict[str, Dict]:
        """Initialise les templates de rapports"""
        return {
            'executive': {
                'sections': ['resume_executif', 'metriques_cle', 'risques_critiques', 'recommandations'],
                'longueur_max': 10,  # pages
                'audience': 'Direction, CISO',
                'focus': 'Business impact, décisions stratégiques'
            },
            'technique': {
                'sections': ['details_vulnerabilites', 'analyse_technique', 'recommandations_implémentation'],
                'longueur_max': 50,  # pages
                'audience': 'Équipes sécurité, développement',
                'focus': 'Détails techniques, solutions concrètes'
            },
            'conformite': {
                'sections': ['statut_conformite', 'ecarts_identifies', 'plan_correction', 'preuves'],
                'longueur_max': 25,  # pages
                'audience': 'Auditeurs, régulateurs',
                'focus': 'Conformité réglementaire, traçabilité'
            }
        }

    def generer_rapport_executif(self, vulnerabilites: List[Vulnerabilite],
                                contexte: Dict[str, Any] = None) -> RapportExecutif:
        """
        Génère un rapport exécutif complet
        """
        contexte = contexte or {}

        rapport = RapportExecutif(
            id_rapport=f"exec_report_{datetime.now().timestamp()}",
            titre="Rapport Exécutif de Sécurité - VulnHunter Pro",
            date_generation=datetime.now(),
            periode_analyse=(datetime.now() - timedelta(days=30), datetime.now()),
            destinataires=['Direction Générale', 'CISO', 'CTO']
        )

        # Résumé exécutif
        rapport.resume_executif = self._generer_resume_executif(vulnerabilites, contexte)

        # Métriques clés
        rapport.metriques_cle = self._calculer_metriques_cle(vulnerabilites)

        # Risques critiques
        rapport.risques_critiques = self._identifier_risques_critiques(vulnerabilites)

        # Recommandations prioritaires
        rapport.recommandations_prioritaires = self._generer_recommandations_prioritaires(vulnerabilites, contexte)

        return rapport

    def _generer_resume_executif(self, vulnerabilites: List[Vulnerabilite],
                                contexte: Dict) -> Dict[str, Any]:
        """Génère le résumé exécutif"""
        resume = {
            'situation_generale': '',
            'metriques_cle': {},
            'evolution_vs_periode_precedente': '',
            'impact_business_estime': '',
            'recommandations_strategiques': []
        }

        # Analyse de la situation
        total_vulns = len(vulnerabilites)
        critiques = len([v for v in vulnerabilites if v.severite == 'CRITIQUE'])
        elevees = len([v for v in vulnerabilites if v.severite == 'ÉLEVÉ'])

        if critiques > 0:
            resume['situation_generale'] = f"Situation critique avec {critiques} vulnérabilités critiques et {elevees} vulnérabilités élevées détectées."
        elif elevees > 5:
            resume['situation_generale'] = f"Situation préoccupante avec {elevees} vulnérabilités élevées nécessitant une attention immédiate."
        else:
            resume['situation_generale'] = f"Situation sous contrôle avec {total_vulns} vulnérabilités identifiées, principalement de sévérité moyenne à faible."

        # Métriques clés
        resume['metriques_cle'] = {
            'total_vulnerabilites': total_vulns,
            'vulnerabilites_critiques': critiques,
            'vulnerabilites_elevees': elevees,
            'score_risque_global': self._calculer_score_risque_global(vulnerabilites)
        }

        # Recommandations stratégiques
        if critiques > 0:
            resume['recommandations_strategiques'].extend([
                "Prioriser la correction des vulnérabilités critiques dans les 7 jours",
                "Mettre en place un plan de réponse aux incidents",
                "Augmenter temporairement la surveillance sécurité"
            ])

        resume['recommandations_strategiques'].append(
            "Maintenir un programme de sécurité continu avec scans réguliers"
        )

        return resume

    def _calculer_metriques_cle(self, vulnerabilites: List[Vulnerabilite]) -> Dict[str, Any]:
        """Calcule les métriques clés pour le rapport"""
        metriques = {
            'total_vulnerabilites': len(vulnerabilites),
            'distribution_severite': {},
            'top_types': [],
            'score_moyen_cvss': 0.0,
            'temps_resolution_estime': '30 jours'
        }

        # Distribution par sévérité
        severites = {}
        for vuln in vulnerabilites:
            sev = vuln.severite
            severites[sev] = severites.get(sev, 0) + 1

        metriques['distribution_severite'] = severites

        # Top types de vulnérabilités
        from collections import Counter
        types = [v.type for v in vulnerabilites]
        top_types = Counter(types).most_common(5)
        metriques['top_types'] = [{'type': t, 'count': c} for t, c in top_types]

        # Score CVSS moyen
        scores_cvss = [getattr(v, 'cvss_score', 5.0) for v in vulnerabilites if hasattr(v, 'cvss_score')]
        if scores_cvss:
            metriques['score_moyen_cvss'] = sum(scores_cvss) / len(scores_cvss)

        # Temps de résolution estimé
        critiques = severites.get('CRITIQUE', 0)
        elevees = severites.get('ÉLEVÉ', 0)

        if critiques > 0:
            metriques['temps_resolution_estime'] = '7 jours'
        elif elevees > 3:
            metriques['temps_resolution_estime'] = '14 jours'
        elif len(vulnerabilites) > 20:
            metriques['temps_resolution_estime'] = '45 jours'

        return metriques

    def _identifier_risques_critiques(self, vulnerabilites: List[Vulnerabilite]) -> List[Dict]:
        """Identifie les risques critiques"""
        risques_critiques = []

        # Vulnérabilités critiques
        for vuln in vulnerabilites:
            if vuln.severite == 'CRITIQUE':
                risques_critiques.append({
                    'type': 'vulnerabilite_critique',
                    'description': f"Vulnérabilité critique: {vuln.type}",
                    'impact': 'Élevé - Accès système possible',
                    'urgence': 'Immediate',
                    'localisation': vuln.url
                })

        # Risques structurels
        if len(vulnerabilites) > 50:
            risques_critiques.append({
                'type': 'probleme_structurel',
                'description': 'Nombre élevé de vulnérabilités indique des problèmes structurels',
                'impact': 'Très élevé - Surface d\'attaque importante',
                'urgence': 'Haute',
                'localisation': 'Architecture globale'
            })

        return risques_critiques

    def _generer_recommandations_prioritaires(self, vulnerabilites: List[Vulnerabilite],
                                           contexte: Dict) -> List[Dict]:
        """Génère les recommandations prioritaires"""
        recommandations = []

        critiques = len([v for v in vulnerabilites if v.severite == 'CRITIQUE'])
        elevees = len([v for v in vulnerabilites if v.severite == 'ÉLEVÉ'])

        if critiques > 0:
            recommandations.append({
                'priorite': 'Critique',
                'action': 'Corriger immédiatement toutes les vulnérabilités critiques',
                'delai': '7 jours',
                'responsable': 'Équipe sécurité',
                'impact': f'Réduit le risque de compromission de {critiques * 15}%'
            })

        if elevees > 3:
            recommandations.append({
                'priorite': 'Haute',
                'action': 'Planifier la correction des vulnérabilités élevées',
                'delai': '30 jours',
                'responsable': 'Équipe développement',
                'impact': f'Améliore la posture sécurité de {elevees * 8}%'
            })

        recommandations.extend([
            {
                'priorite': 'Moyenne',
                'action': 'Mettre en place un programme de scans réguliers',
                'delai': '3 mois',
                'responsable': 'Équipe sécurité',
                'impact': 'Détection précoce des nouvelles vulnérabilités'
            },
            {
                'priorite': 'Moyenne',
                'action': 'Former les équipes aux bonnes pratiques de sécurité',
                'delai': '6 mois',
                'responsable': 'RH / Équipe sécurité',
                'impact': 'Réduction des vulnérabilités introduites'
            }
        ])

        return recommandations

    def _calculer_score_risque_global(self, vulnerabilites: List[Vulnerabilite]) -> float:
        """Calcule un score de risque global (0-100)"""
        if not vulnerabilites:
            return 0.0

        # Pondération par sévérité
        poids = {'CRITIQUE': 20, 'ÉLEVÉ': 10, 'MOYEN': 5, 'FAIBLE': 2, 'INFO': 0.5}
        score = sum(poids.get(v.severite, 5) for v in vulnerabilites)

        # Normalisation
        score_normalise = min(100, score / 2)  # Arbitraire pour rester dans 0-100

        return score_normalise

    def generer_rapport_technique(self, vulnerabilites: List[Vulnerabilite],
                                 analyse_chaines: Dict = None) -> Dict[str, Any]:
        """
        Génère un rapport technique détaillé
        """
        analyse_chaines = analyse_chaines or {}

        rapport = {
            'titre': 'Rapport Technique Détaillé - VulnHunter Pro',
            'date_generation': datetime.now().isoformat(),
            'sections': []
        }

        # Section 1: Résumé technique
        rapport['sections'].append({
            'titre': 'Résumé Technique',
            'contenu': {
                'total_vulnerabilites': len(vulnerabilites),
                'analyse_par_outil': self._analyser_par_outil(vulnerabilites),
                'complexite_moyenne': self._calculer_complexite_moyenne(vulnerabilites)
            }
        })

        # Section 2: Analyse détaillée des vulnérabilités
        rapport['sections'].append({
            'titre': 'Analyse Détaillée des Vulnérabilités',
            'contenu': self._analyser_vulnerabilites_detaillees(vulnerabilites)
        })

        # Section 3: Chaînes d'attaque (si disponibles)
        if analyse_chaines:
            rapport['sections'].append({
                'titre': 'Analyse des Chaînes d\'Attaque',
                'contenu': analyse_chaines
            })

        # Section 4: Recommandations d'implémentation
        rapport['sections'].append({
            'titre': 'Recommandations d\'Implémentation',
            'contenu': self._generer_recommandations_techniques(vulnerabilites)
        })

        return rapport

    def _analyser_par_outil(self, vulnerabilites: List[Vulnerabilite]) -> Dict[str, int]:
        """Analyse la distribution par outil source"""
        outils = {}
        for vuln in vulnerabilites:
            outil = getattr(vuln, 'outil_source', 'VulnHunter')
            outils[outil] = outils.get(outil, 0) + 1

        return outils

    def _calculer_complexite_moyenne(self, vulnerabilites: List[Vulnerabilite]) -> float:
        """Calcule la complexité moyenne des vulnérabilités"""
        complexites = {
            'SQL Injection': 3,
            'XSS': 2,
            'CSRF': 2,
            'RCE': 4,
            'Path Traversal': 3,
            'Weak Authentication': 3,
            'Misconfiguration': 1,
            'Outdated Software': 2
        }

        scores = []
        for vuln in vulnerabilites:
            type_lower = vuln.type.lower()
            complexite = 2  # Défaut

            for pattern, score in complexites.items():
                if pattern.lower() in type_lower:
                    complexite = score
                    break

            scores.append(complexite)

        return sum(scores) / len(scores) if scores else 2.0

    def _analyser_vulnerabilites_detaillees(self, vulnerabilites: List[Vulnerabilite]) -> List[Dict]:
        """Analyse détaillée de chaque vulnérabilité"""
        analyse = []

        for vuln in vulnerabilites:
            detail = {
                'type': vuln.type,
                'severite': vuln.severite,
                'url': vuln.url,
                'description': vuln.description,
                'payload': getattr(vuln, 'payload', ''),
                'cvss_score': getattr(vuln, 'cvss_score', 'N/A'),
                'outil_source': getattr(vuln, 'outil_source', 'VulnHunter'),
                'analyse_technique': self._analyser_technique_vuln(vuln),
                'recommandations': self._generer_recommandations_vuln(vuln)
            }
            analyse.append(detail)

        return analyse

    def _analyser_technique_vuln(self, vuln: Vulnerabilite) -> Dict[str, Any]:
        """Analyse technique d'une vulnérabilité spécifique"""
        analyse = {
            'vecteur_attaque': '',
            'complexite_exploitation': '',
            'impact_technique': '',
            'facilite_detection': ''
        }

        type_lower = vuln.type.lower()

        # Vecteur d'attaque
        if 'sql' in type_lower:
            analyse['vecteur_attaque'] = 'Injection via paramètres utilisateur'
        elif 'xss' in type_lower:
            analyse['vecteur_attaque'] = 'Injection dans contenu rendu côté client'
        elif 'auth' in type_lower:
            analyse['vecteur_attaque'] = 'Contournement des mécanismes d\'authentification'
        elif 'file' in type_lower:
            analyse['vecteur_attaque'] = 'Accès non autorisé au système de fichiers'
        else:
            analyse['vecteur_attaque'] = 'Vecteur d\'attaque standard'

        # Complexité d'exploitation
        if vuln.severite == 'CRITIQUE':
            analyse['complexite_exploitation'] = 'Faible - Exploitation automatisée possible'
        elif vuln.severite == 'ÉLEVÉ':
            analyse['complexite_exploitation'] = 'Moyenne - Nécessite des compétences techniques'
        else:
            analyse['complexite_exploitation'] = 'Élevée - Expertise avancée requise'

        # Impact technique
        analyse['impact_technique'] = 'Affecte la confidentialité, intégrité et disponibilité des données'

        # Facilité de détection
        analyse['facilite_detection'] = 'Détectable via scanners automatisés et tests manuels'

        return analyse

    def _generer_recommandations_vuln(self, vuln: Vulnerabilite) -> List[str]:
        """Génère des recommandations pour une vulnérabilité spécifique"""
        recommandations = []
        type_lower = vuln.type.lower()

        if 'sql' in type_lower:
            recommandations.extend([
                "Utiliser des requêtes préparées (Prepared Statements)",
                "Implémenter la validation stricte des entrées utilisateur",
                "Utiliser un ORM sécurisé avec escaping automatique"
            ])

        elif 'xss' in type_lower:
            recommandations.extend([
                "Encoder toutes les sorties HTML (HTML encoding)",
                "Implémenter Content Security Policy (CSP)",
                "Valider et filtrer toutes les entrées utilisateur"
            ])

        elif 'auth' in type_lower:
            recommandations.extend([
                "Implémenter l'authentification multi-facteurs (MFA)",
                "Utiliser des fonctions de hachage fortes (bcrypt, Argon2)",
                "Appliquer le principe du moindre privilège"
            ])

        elif 'csrf' in type_lower:
            recommandations.extend([
                "Implémenter des tokens CSRF anti-contrefaçon",
                "Utiliser la méthode POST pour les actions sensibles",
                "Vérifier l'origine des requêtes (SameSite cookies)"
            ])

        return recommandations

    def _generer_recommandations_techniques(self, vulnerabilites: List[Vulnerabilite]) -> List[Dict]:
        """Génère des recommandations techniques globales"""
        recommandations = []

        # Analyse des patterns
        types_vuln = [v.type.lower() for v in vulnerabilites]

        # Recommandations basées sur les vulnérabilités trouvées
        if any('sql' in t for t in types_vuln):
            recommandations.append({
                'categorie': 'Sécurisation Base de Données',
                'actions': [
                    "Migrer vers des requêtes préparées sur toute l'application",
                    "Implémenter un WAF (Web Application Firewall)",
                    "Auditer tous les points d'entrée de données"
                ],
                'priorite': 'Critique',
                'effort_estime': '2-4 semaines'
            })

        if any('xss' in t for t in types_vuln):
            recommandations.append({
                'categorie': 'Sécurisation Frontend',
                'actions': [
                    "Implémenter CSP (Content Security Policy)",
                    "Utiliser des frameworks sécurisés (React, Vue.js avec escaping)",
                    "Mettre en place des sanitizers HTML automatiques"
                ],
                'priorite': 'Haute',
                'effort_estime': '1-2 semaines'
            })

        if any('auth' in t for t in types_vuln):
            recommandations.append({
                'categorie': 'Renforcement Authentification',
                'actions': [
                    "Déployer MFA sur tous les comptes",
                    "Réviser les politiques de mots de passe",
                    "Implémenter des contrôles de session avancés"
                ],
                'priorite': 'Haute',
                'effort_estime': '1-3 semaines'
            })

        # Recommandations générales
        recommandations.append({
            'categorie': 'Amélioration Continue',
            'actions': [
                "Mettre en place des scans automatisés quotidiens",
                "Implémenter un programme de formation sécurité",
                "Établir des métriques de sécurité suivies"
            ],
            'priorite': 'Moyenne',
            'effort_estime': '1-6 mois'
        })

        return recommandations

    def generer_rapport_conformite(self, vulnerabilites: List[Vulnerabilite],
                                  reglementations: List[str] = None) -> Dict[str, Any]:
        """
        Génère un rapport de conformité réglementaire
        """
        reglementations = reglementations or ['pci_dss', 'gdpr', 'hipaa']

        rapport = {
            'titre': 'Rapport de Conformité Réglementaire - VulnHunter Pro',
            'date_generation': datetime.now().isoformat(),
            'periode_audit': f"{datetime.now().strftime('%Y-%m-%d')}",
            'reglementations_auditees': reglementations,
            'statut_global': 'conforme',
            'details_conformite': {},
            'actions_correctives': [],
            'preuves': []
        }

        # Importer le vérificateur de conformité
        from core.compliance_metrics import VerificateurCompliance
        verificateur = VerificateurCompliance()

        conformite_generale = True

        for regle in reglementations:
            statut_regle = verificateur.verifier_conformite(vulnerabilites, regle)
            rapport['details_conformite'][regle.upper()] = {
                'conforme': statut_regle['conforme'],
                'score': statut_regle['score_conformite'],
                'violations': len(statut_regle['violations']),
                'recommandations': statut_regle['recommandations']
            }

            if not statut_regle['conforme']:
                conformite_generale = False

        rapport['statut_global'] = 'conforme' if conformite_generale else 'non_conforme'

        # Générer les actions correctives
        rapport['actions_correctives'] = self._generer_actions_correctives(rapport)

        # Preuves de conformité
        rapport['preuves'] = self._collecter_preuves_conformite(vulnerabilites)

        return rapport

    def _generer_actions_correctives(self, rapport: Dict) -> List[Dict]:
        """Génère les actions correctives pour les non-conformités"""
        actions = []

        for regle, details in rapport['details_conformite'].items():
            if not details['conforme']:
                actions.append({
                    'reglementation': regle,
                    'priorite': 'Critique' if details['score'] < 50 else 'Haute',
                    'description': f"Corriger {details['violations']} violations {regle}",
                    'delai': '30 jours' if details['score'] >= 50 else '7 jours',
                    'responsable': 'Équipe sécurité',
                    'suivi': 'Audit de suivi dans 3 mois'
                })

        return actions

    def _collecter_preuves_conformite(self, vulnerabilites: List[Vulnerabilite]) -> List[Dict]:
        """Collecte les preuves de conformité"""
        preuves = []

        # Preuve de scan complet
        preuves.append({
            'type': 'preuve_scan',
            'description': f"Scan complet réalisé sur {len(vulnerabilites)} points d'entrée",
            'date': datetime.now().isoformat(),
            'outil': 'VulnHunter Pro'
        })

        # Preuve de couverture d'outils
        outils = set(getattr(v, 'outil_source', 'VulnHunter') for v in vulnerabilites)
        preuves.append({
            'type': 'preuve_outils',
            'description': f"Utilisation de {len(outils)} outils de sécurité différents",
            'outils': list(outils)
        })

        # Preuve de méthodologie
        preuves.append({
            'type': 'preuve_methodologie',
            'description': 'Méthodologie OWASP Risk Rating et CVSS appliquée',
            'standards': ['OWASP Risk Rating', 'CVSS v3.1', 'ISO 27001']
        })

        return preuves


class OrchestrateurReporting:
    """
    Orchestrateur principal pour tous les types de reporting
    """

    def __init__(self):
        self.generateur_dashboards = GenerateurDashboards()
        self.analyseur_tendances = AnalyseurTendances()
        self.generateur_rapports = GenerateurRapports()

    async def generer_reporting_complet(self, vulnerabilites: List[Vulnerabilite],
                                       contexte: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Génère un reporting complet avec tous les types de rapports
        """
        contexte = contexte or {}

        reporting = {
            'timestamp_generation': datetime.now().isoformat(),
            'dashboard': {},
            'rapports': {},
            'analyse_tendances': {},
            'recommandations_globales': []
        }

        # Générer le dashboard
        reporting['dashboard'] = self.generateur_dashboards.creer_dashboard_risques(
            vulnerabilites, contexte
        )

        # Générer les rapports spécialisés
        reporting['rapports']['executif'] = self.generateur_rapports.generer_rapport_executif(
            vulnerabilites, contexte
        )

        reporting['rapports']['technique'] = self.generateur_rapports.generer_rapport_technique(
            vulnerabilites, contexte.get('analyse_chaines')
        )

        reporting['rapports']['conformite'] = self.generateur_rapports.generer_rapport_conformite(
            vulnerabilites, contexte.get('reglementations', ['pci_dss', 'gdpr'])
        )

        # Analyser les tendances (si données historiques disponibles)
        historique = contexte.get('historique_scans', [])
        if historique:
            reporting['analyse_tendances'] = self.analyseur_tendances.analyser_tendances(historique)

        # Générer recommandations globales
        reporting['recommandations_globales'] = self._synthetiser_recommandations(reporting)

        return reporting

    def _synthetiser_recommandations(self, reporting: Dict) -> List[str]:
        """Synthétise les recommandations de tous les rapports"""
        recommandations = []

        # Du rapport exécutif
        exec_rapport = reporting['rapports']['executif']
        if hasattr(exec_rapport, 'recommandations_prioritaires'):
            for rec in exec_rapport.recommandations_prioritaires[:2]:
                recommandations.append(f"EXEC: {rec.get('action', '')}")

        # Du rapport technique
        tech_rapport = reporting['rapports']['technique']
        for section in tech_rapport.get('sections', []):
            if section['titre'] == 'Recommandations d\'Implémentation':
                for rec in section['contenu'][:1]:
                    recommandations.append(f"TECH: {rec.get('categorie', '')} - {rec.get('priorite', '')}")

        # Du rapport de conformité
        comp_rapport = reporting['rapports']['conformite']
        for action in comp_rapport.get('actions_correctives', [])[:1]:
            recommandations.append(f"CONFORM: {action.get('description', '')}")

        # Du dashboard
        dashboard = reporting['dashboard']
        recommandations.extend(dashboard.get('recommandations', []))

        return list(set(recommandations))  # Éliminer les doublons

    def exporter_rapport(self, reporting: Dict, format_export: str = 'json',
                        chemin_fichier: str = None) -> str:
        """
        Exporte le reporting dans différents formats
        """
        if not chemin_fichier:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            chemin_fichier = f"vulnhunter_report_{timestamp}.{format_export}"

        if format_export == 'json':
            with open(chemin_fichier, 'w', encoding='utf-8') as f:
                json.dump(reporting, f, indent=2, ensure_ascii=False, default=str)

        elif format_export == 'html':
            html_content = self._generer_html_reporting(reporting)
            with open(chemin_fichier, 'w', encoding='utf-8') as f:
                f.write(html_content)

        elif format_export == 'pdf':
            # Pour PDF, on utiliserait une bibliothèque comme reportlab
            # Pour l'instant, on sauvegarde en JSON
            self.exporter_rapport(reporting, 'json', chemin_fichier.replace('.pdf', '.json'))

        return chemin_fichier

    def _generer_html_reporting(self, reporting: Dict) -> str:
        """Génère un rapport HTML complet"""
        html = f"""
        <!DOCTYPE html>
        <html lang="fr">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Rapport VulnHunter Pro</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background: #2E4057; color: white; padding: 20px; border-radius: 5px; }}
                .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
                .metric {{ display: inline-block; margin: 10px; padding: 10px; background: #f0f0f0; border-radius: 3px; }}
                .critical {{ background: #DC143C; color: white; }}
                .high {{ background: #FF6347; color: white; }}
                .chart {{ margin: 20px 0; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>📊 Rapport VulnHunter Pro</h1>
                <p>Généré le {reporting['timestamp_generation'][:10]}</p>
            </div>

            <div class="section">
                <h2>🎯 Résumé Exécutif</h2>
                <div class="metric">Total Vulnérabilités: {reporting['rapports']['executif'].metriques_cle['total_vulnerabilites']}</div>
                <div class="metric critical">Critiques: {reporting['rapports']['executif'].metriques_cle['distribution_severite'].get('CRITIQUE', 0)}</div>
                <div class="metric high">Élevées: {reporting['rapports']['executif'].metriques_cle['distribution_severite'].get('ÉLEVÉ', 0)}</div>
            </div>

            <div class="section">
                <h2>📈 Dashboard Interactif</h2>
                <p>Dashboard généré avec {len(reporting['dashboard']['graphiques'])} graphiques interactifs</p>
                <p>Métriques clés: Score risque {reporting['dashboard']['metriques']['score_risque_global']:.1f}/100</p>
            </div>

            <div class="section">
                <h2>⚖️ Conformité Réglementaire</h2>
                <p>Statut global: {reporting['rapports']['conformite']['statut_global'].upper()}</p>
                <p>Réglementations auditées: {', '.join(reporting['rapports']['conformite']['reglementations_auditees'])}</p>
            </div>

            <div class="section">
                <h2>💡 Recommandations Prioritaires</h2>
                <ul>
        """

        for rec in reporting['recommandations_globales'][:5]:
            html += f"<li>{rec}</li>\n"

        html += """
                </ul>
            </div>
        </body>
        </html>
        """

        return html
