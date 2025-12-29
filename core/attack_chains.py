"""
Système d'analyse de chaînes d'attaque pour VulnHunter Pro
Attack trees automatiques, privilege escalation, lateral movement, business impact
"""

import asyncio
from typing import Dict, List, Tuple, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime
import networkx as nx
from enum import Enum
from collections import defaultdict

from core.models import Vulnerabilite


class TypeNoeud(Enum):
    """Types de nœuds dans l'arbre d'attaque"""
    VULNERABILITE = "vulnerabilite"
    PRIVILEGE = "privilege"
    ACCES = "acces"
    DONNEE = "donnee"
    SYSTEME = "systeme"
    OBJECTIF = "objectif"


class VecteurAttaque(Enum):
    """Vecteurs d'attaque possibles"""
    WEB = "web"
    RESEAU = "reseau"
    AUTHENTIFICATION = "authentification"
    AUTORISATION = "autorisation"
    DONNEES = "donnees"
    CONFIGURATION = "configuration"
    PHYSIQUE = "physique"


@dataclass
class NoeudAttaque:
    """Nœud dans l'arbre d'attaque"""
    id_noeud: str
    type_noeud: TypeNoeud
    nom: str
    description: str
    vecteur_attaque: VecteurAttaque
    niveau_privilege: str = "none"
    impact_business: float = 0.0
    facilite_exploitation: float = 0.5
    probabilite_succes: float = 0.5
    cout_exploitation: float = 1.0
    temps_exploitation: int = 1  # minutes
    vulnerabilites_associees: List[str] = field(default_factory=list)
    pre_requis: List[str] = field(default_factory=list)
    consequences: List[str] = field(default_factory=list)


@dataclass
class ChaineAttaque:
    """Chaîne d'attaque complète"""
    id_chaine: str
    nom: str
    description: str
    noeuds: List[NoeudAttaque] = field(default_factory=list)
    connexions: List[Tuple[str, str]] = field(default_factory=list)
    graphe: nx.DiGraph = field(default_factory=nx.DiGraph)
    score_global: float = 0.0
    impact_business_total: float = 0.0
    probabilite_succes_total: float = 0.0
    temps_total_estime: int = 0
    niveau_risque: str = "low"
    objectifs_atteints: List[str] = field(default_factory=list)
    chemins_critiques: List[List[str]] = field(default_factory=list)


class ConstructeurArbresAttaque:
    """
    Constructeur automatique d'arbres d'attaque
    """

    def __init__(self):
        self.regles_chaines = self._initialiser_regles_chaines()
        self.templates_attaque = self._initialiser_templates()

    def _initialiser_regles_chaines(self) -> Dict[str, Dict]:
        """Initialise les règles pour construire des chaînes d'attaque"""
        return {
            # Chaînes SQL Injection
            'sql_injection_chain': {
                'vecteur_initial': 'web',
                'etapes': [
                    {'type': 'VULNERABILITE', 'pattern': 'sql.*injection', 'privilege': 'none'},
                    {'type': 'ACCES', 'action': 'database_access', 'privilege': 'db_user'},
                    {'type': 'DONNEE', 'action': 'data_extraction', 'privilege': 'db_user'},
                    {'type': 'PRIVILEGE', 'action': 'privilege_escalation', 'privilege': 'db_admin'},
                    {'type': 'SYSTEME', 'action': 'system_compromise', 'privilege': 'system'}
                ],
                'impact_business': 9.0,
                'probabilite': 0.8
            },

            # Chaînes XSS
            'xss_chain': {
                'vecteur_initial': 'web',
                'etapes': [
                    {'type': 'VULNERABILITE', 'pattern': 'xss', 'privilege': 'none'},
                    {'type': 'ACCES', 'action': 'user_session_hijack', 'privilege': 'user'},
                    {'type': 'DONNEE', 'action': 'credential_theft', 'privilege': 'user'},
                    {'type': 'PRIVILEGE', 'action': 'account_takeover', 'privilege': 'user_premium'},
                    {'type': 'SYSTEME', 'action': 'mass_compromise', 'privilege': 'multiple_users'}
                ],
                'impact_business': 7.5,
                'probabilite': 0.6
            },

            # Chaînes Authentication Bypass
            'auth_bypass_chain': {
                'vecteur_initial': 'authentification',
                'etapes': [
                    {'type': 'VULNERABILITE', 'pattern': 'auth.*bypass|weak.*auth', 'privilege': 'none'},
                    {'type': 'ACCES', 'action': 'unauthorized_access', 'privilege': 'user'},
                    {'type': 'DONNEE', 'action': 'sensitive_data_access', 'privilege': 'user'},
                    {'type': 'PRIVILEGE', 'action': 'admin_access', 'privilege': 'admin'},
                    {'type': 'SYSTEME', 'action': 'full_system_control', 'privilege': 'root'}
                ],
                'impact_business': 10.0,
                'probabilite': 0.9
            },

            # Chaînes File Inclusion
            'file_inclusion_chain': {
                'vecteur_initial': 'web',
                'etapes': [
                    {'type': 'VULNERABILITE', 'pattern': 'file.*inclusion|lfi|rfi', 'privilege': 'none'},
                    {'type': 'ACCES', 'action': 'file_system_access', 'privilege': 'web_user'},
                    {'type': 'DONNEE', 'action': 'config_file_reading', 'privilege': 'web_user'},
                    {'type': 'SYSTEME', 'action': 'web_shell_upload', 'privilege': 'web_user'},
                    {'type': 'PRIVILEGE', 'action': 'system_shell', 'privilege': 'system'}
                ],
                'impact_business': 8.5,
                'probabilite': 0.7
            },

            # Chaînes API Vulnerabilities
            'api_chain': {
                'vecteur_initial': 'web',
                'etapes': [
                    {'type': 'VULNERABILITE', 'pattern': 'api.*vulnerability|graphql|rest', 'privilege': 'none'},
                    {'type': 'ACCES', 'action': 'api_endpoint_access', 'privilege': 'api_user'},
                    {'type': 'DONNEE', 'action': 'bulk_data_extraction', 'privilege': 'api_user'},
                    {'type': 'PRIVILEGE', 'action': 'api_admin_access', 'privilege': 'api_admin'},
                    {'type': 'SYSTEME', 'action': 'backend_system_compromise', 'privilege': 'system'}
                ],
                'impact_business': 8.0,
                'probabilite': 0.75
            }
        }

    def _initialiser_templates(self) -> Dict[str, Dict]:
        """Initialise les templates d'attaque par type"""
        return {
            'web_application_attack': {
                'entree': ['SQL Injection', 'XSS', 'CSRF', 'File Inclusion'],
                'milieu': ['Session Hijacking', 'Privilege Escalation', 'Lateral Movement'],
                'sortie': ['Data Breach', 'System Compromise', 'Business Disruption']
            },

            'network_attack': {
                'entree': ['Open Ports', 'Weak Services', 'Misconfigurations'],
                'milieu': ['Service Exploitation', 'Network Pivoting', 'Credential Stuffing'],
                'sortie': ['Network Compromise', 'Data Exfiltration', 'Ransomware']
            },

            'insider_threat': {
                'entree': ['Weak Access Controls', 'Social Engineering', 'Physical Access'],
                'milieu': ['Data Copying', 'Privilege Abuse', 'Lateral Movement'],
                'sortie': ['Data Theft', 'Sabotage', 'Espionage']
            }
        }

    def construire_arbre_attaque(self, vulnerabilites: List[Vulnerabilite],
                               contexte: Dict[str, Any] = None) -> ChaineAttaque:
        """
        Construit automatiquement un arbre d'attaque à partir des vulnérabilités

        Args:
            vulnerabilites: Liste des vulnérabilités découvertes
            contexte: Contexte d'attaque (environnement, objectifs, etc.)

        Returns:
            ChaineAttaque: Arbre d'attaque complet
        """
        contexte = contexte or {}
        chaine = ChaineAttaque(
            id_chaine=f"attack_chain_{datetime.now().timestamp()}",
            nom="Chaîne d'attaque automatique",
            description="Arbre d'attaque généré automatiquement à partir des vulnérabilités découvertes"
        )

        # 1. Identifier les vulnérabilités d'entrée
        noeuds_entree = self._identifier_noeuds_entree(vulnerabilites)

        # 2. Construire les chemins d'attaque
        chemins = self._construire_chemins_attaque(noeuds_entree, contexte)

        # 3. Créer le graphe
        graphe = self._construire_graphe(chemins)

        # 4. Calculer les métriques
        metriques = self._calculer_metriques_chaine(graphe, vulnerabilites, contexte)

        # Mettre à jour la chaîne
        chaine.noeuds = list(graphe.nodes.values()) if hasattr(graphe, 'nodes') else []
        chaine.connexions = list(graphe.edges())
        chaine.graphe = graphe
        chaine.score_global = metriques['score_global']
        chaine.impact_business_total = metriques['impact_business']
        chaine.probabilite_succes_total = metriques['probabilite_succes']
        chaine.temps_total_estime = metriques['temps_total']
        chaine.niveau_risque = metriques['niveau_risque']
        chaine.objectifs_atteints = metriques['objectifs']
        chaine.chemins_critiques = metriques['chemins_critiques']

        return chaine

    def _identifier_noeuds_entree(self, vulnerabilites: List[Vulnerabilite]) -> List[NoeudAttaque]:
        """Identifie les nœuds d'entrée (vulnérabilités initiales)"""
        noeuds_entree = []

        for vuln in vulnerabilites:
            # Déterminer le vecteur d'attaque
            vecteur = self._determiner_vecteur_attaque(vuln)

            # Créer le nœud de vulnérabilité
            noeud = NoeudAttaque(
                id_noeud=f"vuln_{vuln.type.lower().replace(' ', '_')}_{hash(vuln.url) % 1000}",
                type_noeud=TypeNoeud.VULNERABILITE,
                nom=vuln.type,
                description=vuln.description,
                vecteur_attaque=vecteur,
                niveau_privilege="none",
                impact_business=self._calculer_impact_business_vuln(vuln),
                facilite_exploitation=self._evaluer_facilite_exploitation(vuln),
                probabilite_succes=self._evaluer_probabilite_succes(vuln),
                vulnerabilites_associees=[vuln.type]
            )

            noeuds_entree.append(noeud)

        return noeuds_entree

    def _determiner_vecteur_attaque(self, vuln: Vulnerabilite) -> VecteurAttaque:
        """Détermine le vecteur d'attaque d'une vulnérabilité"""
        type_lower = vuln.type.lower()

        if any(keyword in type_lower for keyword in ['sql', 'xss', 'csrf', 'file inclusion', 'path traversal']):
            return VecteurAttaque.WEB
        elif any(keyword in type_lower for keyword in ['weak password', 'auth bypass', 'session']):
            return VecteurAttaque.AUTHENTIFICATION
        elif any(keyword in type_lower for keyword in ['idor', 'access control']):
            return VecteurAttaque.AUTORISATION
        elif any(keyword in type_lower for keyword in ['information disclosure', 'data leak']):
            return VecteurAttaque.DONNEES
        elif any(keyword in type_lower for keyword in ['misconfiguration', 'weak ssl']):
            return VecteurAttaque.CONFIGURATION
        else:
            return VecteurAttaque.RESEAU

    def _calculer_impact_business_vuln(self, vuln: Vulnerabilite) -> float:
        """Calcule l'impact business d'une vulnérabilité"""
        severite_map = {
            'CRITIQUE': 10.0,
            'ÉLEVÉ': 7.5,
            'MOYEN': 5.0,
            'FAIBLE': 2.5,
            'INFO': 1.0
        }

        base_impact = severite_map.get(vuln.severite, 5.0)

        # Ajustements selon le type
        type_lower = vuln.type.lower()
        if 'data' in type_lower or 'information' in type_lower:
            base_impact *= 1.3  # Impact plus élevé pour les données
        elif 'admin' in type_lower or 'root' in type_lower:
            base_impact *= 1.2  # Impact élevé pour les accès privilégiés

        return min(base_impact, 10.0)

    def _evaluer_facilite_exploitation(self, vuln: Vulnerabilite) -> float:
        """Évalue la facilité d'exploitation (0-1)"""
        type_lower = vuln.type.lower()

        # Vulnérabilités faciles
        if 'sql injection' in type_lower or 'xss' in type_lower:
            return 0.8
        elif 'weak password' in type_lower or 'default credential' in type_lower:
            return 0.9
        elif 'misconfiguration' in type_lower:
            return 0.7

        # Vulnérabilités difficiles
        elif 'zero day' in type_lower or 'advanced' in type_lower:
            return 0.2
        elif 'rce' in type_lower or 'command injection' in type_lower:
            return 0.6

        return 0.5  # Moyenne

    def _evaluer_probabilite_succes(self, vuln: Vulnerabilite) -> float:
        """Évalue la probabilité de succès (0-1)"""
        severite = vuln.severite.lower()

        if severite == 'critique':
            return 0.9
        elif severite == 'élevé':
            return 0.75
        elif severite == 'moyen':
            return 0.6
        elif severite == 'faible':
            return 0.4
        else:
            return 0.2

    def _construire_chemins_attaque(self, noeuds_entree: List[NoeudAttaque],
                                  contexte: Dict[str, Any]) -> List[List[NoeudAttaque]]:
        """Construit les chemins d'attaque possibles"""
        chemins = []

        for noeud_entree in noeuds_entree:
            # Trouver les règles applicables
            regles_applicables = self._trouver_regles_applicables(noeud_entree)

            for regle in regles_applicables:
                chemin = self._construire_chemin_selon_regle(noeud_entree, regle, contexte)
                if chemin:
                    chemins.append(chemin)

        return chemins

    def _trouver_regles_applicables(self, noeud: NoeudAttaque) -> List[Dict]:
        """Trouve les règles d'attaque applicables à un nœud"""
        regles_applicables = []

        for nom_regle, regle in self.regles_chaines.items():
            # Vérifier si le vecteur correspond
            if regle['vecteur_initial'] == noeud.vecteur_attaque.value:
                # Vérifier si le pattern correspond
                etape_initiale = regle['etapes'][0]
                if etape_initiale.get('pattern'):
                    import re
                    if re.search(etape_initiale['pattern'], noeud.nom, re.IGNORECASE):
                        regles_applicables.append(regle)

        return regles_applicables

    def _construire_chemin_selon_regle(self, noeud_entree: NoeudAttaque,
                                     regle: Dict, contexte: Dict) -> Optional[List[NoeudAttaque]]:
        """Construit un chemin d'attaque selon une règle"""
        chemin = [noeud_entree]

        privilege_actuel = noeud_entree.niveau_privilege

        for etape in regle['etapes'][1:]:  # Skip first step (entry point)
            # Créer le nœud suivant
            noeud_suivant = NoeudAttaque(
                id_noeud=f"{etape['action']}_{hash(str(etape)) % 1000}",
                type_noeud=TypeNoeud(etape['type'].lower()),
                nom=etape['action'].replace('_', ' ').title(),
                description=f"Étape d'attaque: {etape['action']}",
                vecteur_attaque=noeud_entree.vecteur_attaque,
                niveau_privilege=etape.get('privilege', privilege_actuel),
                impact_business=regle.get('impact_business', 5.0) * 0.1,  # Fraction de l'impact total
                facilite_exploitation=0.6,
                probabilite_succes=regle.get('probabilite', 0.5),
                pre_requis=[noeud_entree.id_noeud]
            )

            privilege_actuel = etape.get('privilege', privilege_actuel)
            chemin.append(noeud_suivant)

        return chemin if len(chemin) > 1 else None

    def _construire_graphe(self, chemins: List[List[NoeudAttaque]]) -> nx.DiGraph:
        """Construit le graphe d'attaque à partir des chemins"""
        graphe = nx.DiGraph()

        for chemin in chemins:
            for i in range(len(chemin) - 1):
                noeud_courant = chemin[i]
                noeud_suivant = chemin[i + 1]

                # Ajouter les nœuds
                graphe.add_node(noeud_courant.id_noeud, data=noeud_courant)
                graphe.add_node(noeud_suivant.id_noeud, data=noeud_suivant)

                # Ajouter l'arête
                graphe.add_edge(noeud_courant.id_noeud, noeud_suivant.id_noeud)

        return graphe

    def _calculer_metriques_chaine(self, graphe: nx.DiGraph,
                                 vulnerabilites: List[Vulnerabilite],
                                 contexte: Dict) -> Dict[str, Any]:
        """Calcule les métriques de la chaîne d'attaque"""
        metriques = {
            'score_global': 0.0,
            'impact_business': 0.0,
            'probabilite_succes': 1.0,
            'temps_total': 0,
            'niveau_risque': 'low',
            'objectifs': [],
            'chemins_critiques': []
        }

        if not graphe or graphe.number_of_nodes() == 0:
            return metriques

        # Trouver tous les chemins depuis les nœuds d'entrée
        noeuds_entree = [n for n in graphe.nodes() if graphe.in_degree(n) == 0]

        tous_chemins = []
        for entree in noeuds_entree:
            try:
                for sortie in [n for n in graphe.nodes() if graphe.out_degree(n) == 0]:
                    chemins = list(nx.all_simple_paths(graphe, entree, sortie))
                    tous_chemins.extend(chemins)
            except:
                continue

        if not tous_chemins:
            return metriques

        # Analyser chaque chemin
        scores_chemins = []

        for chemin in tous_chemins:
            score_chemin = 0.0
            impact_chemin = 0.0
            proba_chemin = 1.0
            temps_chemin = 0

            for noeud_id in chemin:
                if noeud_id in graphe.nodes:
                    noeud = graphe.nodes[noeud_id]['data']
                    score_chemin += noeud.impact_business * noeud.facilite_exploitation
                    impact_chemin += noeud.impact_business
                    proba_chemin *= noeud.probabilite_succes
                    temps_chemin += noeud.temps_exploitation

            scores_chemins.append({
                'chemin': chemin,
                'score': score_chemin,
                'impact': impact_chemin,
                'probabilite': proba_chemin,
                'temps': temps_chemin
            })

        # Trouver le chemin critique (meilleur score)
        if scores_chemins:
            chemin_critique = max(scores_chemins, key=lambda x: x['score'])

            metriques['score_global'] = chemin_critique['score']
            metriques['impact_business'] = chemin_critique['impact']
            metriques['probabilite_succes'] = chemin_critique['probabilite']
            metriques['temps_total'] = chemin_critique['temps']
            metriques['chemins_critiques'] = [chemin_critique['chemin']]

            # Déterminer le niveau de risque
            if metriques['score_global'] >= 30:
                metriques['niveau_risque'] = 'critical'
            elif metriques['score_global'] >= 20:
                metriques['niveau_risque'] = 'high'
            elif metriques['score_global'] >= 10:
                metriques['niveau_risque'] = 'medium'
            else:
                metriques['niveau_risque'] = 'low'

        # Objectifs atteints (nœuds de sortie)
        noeuds_sortie = [n for n in graphe.nodes() if graphe.out_degree(n) == 0]
        metriques['objectifs'] = [graphe.nodes[n]['data'].nom for n in noeuds_sortie]

        return metriques


class AnalyseurEscaladePrivileges:
    """
    Analyseur de chemins d'escalade de privilèges
    """

    def __init__(self):
        self.chemins_escalade = self._initialiser_chemins_escalade()

    def _initialiser_chemins_escalade(self) -> Dict[str, List[Dict]]:
        """Initialise les chemins d'escalade de privilèges"""
        return {
            'web_to_system': [
                {'from': 'web_user', 'to': 'db_user', 'via': 'SQL Injection'},
                {'from': 'db_user', 'to': 'db_admin', 'via': 'Privilege Escalation DB'},
                {'from': 'db_admin', 'to': 'system_user', 'via': 'OS Command Execution'},
                {'from': 'system_user', 'to': 'root', 'via': 'Kernel Exploit'}
            ],

            'user_to_admin': [
                {'from': 'guest', 'to': 'user', 'via': 'Weak Credentials'},
                {'from': 'user', 'to': 'power_user', 'via': 'DLL Hijacking'},
                {'from': 'power_user', 'to': 'admin', 'via': 'UAC Bypass'},
                {'from': 'admin', 'to': 'system', 'via': 'Token Impersonation'}
            ],

            'network_to_domain': [
                {'from': 'external', 'to': 'dmz_host', 'via': 'Remote Code Execution'},
                {'from': 'dmz_host', 'to': 'internal_host', 'via': 'Lateral Movement'},
                {'from': 'internal_host', 'to': 'domain_user', 'via': 'Pass-the-Hash'},
                {'from': 'domain_user', 'to': 'domain_admin', 'via': 'Kerberos Attack'}
            ]
        }

    def analyser_escalade_privileges(self, chaine_attaque: ChaineAttaque) -> Dict[str, Any]:
        """
        Analyse les possibilités d'escalade de privilèges dans une chaîne d'attaque

        Args:
            chaine_attaque: La chaîne d'attaque à analyser

        Returns:
            Analyse des escalades possibles
        """
        analyse = {
            'chemins_escalade_identifies': [],
            'niveau_privilege_max_atteint': 'none',
            'probabilite_escalade': 0.0,
            'vecteurs_escalade': [],
            'recommandations_securite': []
        }

        niveaux_privilege = []
        for noeud in chaine_attaque.noeuds:
            if hasattr(noeud, 'niveau_privilege'):
                niveaux_privilege.append(noeud.niveau_privilege)

        if niveaux_privilege:
            # Déterminer le niveau max atteint
            hierarchie_privilege = {
                'none': 0,
                'guest': 1,
                'web_user': 2,
                'user': 3,
                'power_user': 4,
                'db_user': 5,
                'db_admin': 6,
                'admin': 7,
                'system': 8,
                'root': 9,
                'domain_admin': 10
            }

            niveaux_numeriques = [hierarchie_privilege.get(niveau, 0) for niveau in niveaux_privilege]
            niveau_max = max(niveaux_numeriques)

            # Trouver le nom du niveau max
            for nom, valeur in hierarchie_privilege.items():
                if valeur == niveau_max:
                    analyse['niveau_privilege_max_atteint'] = nom
                    break

        # Identifier les chemins d'escalade utilisés
        for type_chemin, etapes in self.chemins_escalade.items():
            chemin_utilise = []

            for etape in etapes:
                # Vérifier si cette étape est présente dans la chaîne
                for noeud in chaine_attaque.noeuds:
                    if etape['via'].lower() in noeud.nom.lower():
                        chemin_utilise.append(etape)
                        break

            if len(chemin_utilise) >= 2:  # Au moins 2 étapes connectées
                analyse['chemins_escalade_identifies'].append({
                    'type': type_chemin,
                    'etapes': chemin_utilise,
                    'probabilite': len(chemin_utilise) / len(etapes)
                })

        # Calculer la probabilité d'escalade
        if analyse['chemins_escalade_identifies']:
            analyse['probabilite_escalade'] = sum(
                c['probabilite'] for c in analyse['chemins_escalade_identifies']
            ) / len(analyse['chemins_escalade_identifies'])

        # Générer des recommandations
        if analyse['niveau_privilege_max_atteint'] in ['root', 'system', 'domain_admin']:
            analyse['recommandations_securite'].extend([
                "Implémenter une segmentation réseau stricte",
                "Appliquer le principe du moindre privilège",
                "Mettre en place des contrôles d'intégrité",
                "Surveiller les activités privilégiées"
            ])

        return analyse


class AnalyseurMouvementLateral:
    """
    Analyseur de mouvement latéral dans le réseau
    """

    def __init__(self):
        self.techniques_laterales = self._initialiser_techniques_laterales()

    def _initialiser_techniques_laterales(self) -> Dict[str, Dict]:
        """Initialise les techniques de mouvement latéral"""
        return {
            'pass_the_hash': {
                'description': 'Utilisation de hashes NTLM pour authentification',
                'requis': ['admin_access', 'credential_dump'],
                'impact': 'haut',
                'detection_difficulty': 'moyen'
            },

            'pass_the_ticket': {
                'description': 'Utilisation de tickets Kerberos volés',
                'requis': ['domain_access', 'kerberos_tickets'],
                'impact': 'tres_haut',
                'detection_difficulty': 'difficile'
            },

            'ps_exec': {
                'description': 'Exécution à distance via SMB',
                'requis': ['smb_access', 'admin_credentials'],
                'impact': 'haut',
                'detection_difficulty': 'facile'
            },

            'wmi_execution': {
                'description': 'Exécution via Windows Management Instrumentation',
                'requis': ['wmi_access', 'admin_privileges'],
                'impact': 'haut',
                'detection_difficulty': 'moyen'
            },

            'ssh_tunneling': {
                'description': 'Tunneling via SSH pour pivoter',
                'requis': ['ssh_access', 'ssh_keys'],
                'impact': 'moyen',
                'detection_difficulty': 'difficile'
            }
        }

    def analyser_mouvement_lateral(self, chaine_attaque: ChaineAttaque,
                                 topologie_reseau: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Analyse les possibilités de mouvement latéral

        Args:
            chaine_attaque: La chaîne d'attaque à analyser
            topologie_reseau: Description de la topologie réseau

        Returns:
            Analyse du mouvement latéral
        """
        topologie_reseau = topologie_reseau or {}

        analyse = {
            'techniques_laterales_possibles': [],
            'chemins_lateraux': [],
            'impact_propagation': 0.0,
            'vecteurs_exposition': [],
            'recommandations_containment': []
        }

        # Identifier les techniques applicables
        privileges_atteints = set()
        acces_atteints = set()

        for noeud in chaine_attaque.noeuds:
            if hasattr(noeud, 'niveau_privilege') and noeud.niveau_privilege:
                privileges_atteints.add(noeud.niveau_privilege)

            if noeud.type_noeud == TypeNoeud.ACCES:
                acces_atteints.add(noeud.nom.lower())

        # Vérifier chaque technique latérale
        for nom_technique, config in self.techniques_laterales.items():
            technique_applicable = True
            score_applicabilite = 0.0

            for requis in config['requis']:
                if not any(requis in privilege or requis in acces for privilege in privileges_atteints for acces in acces_atteints):
                    technique_applicable = False
                    break
                else:
                    score_applicabilite += 1.0

            if technique_applicable:
                score_applicabilite /= len(config['requis'])

                analyse['techniques_laterales_possibles'].append({
                    'technique': nom_technique,
                    'description': config['description'],
                    'score_applicabilite': score_applicabilite,
                    'impact': config['impact'],
                    'detection_difficulty': config['detection_difficulty']
                })

        # Estimer l'impact de propagation
        if analyse['techniques_laterales_possibles']:
            impacts = {
                'faible': 1,
                'moyen': 2,
                'haut': 3,
                'tres_haut': 4
            }

            impact_moyen = sum(
                impacts.get(t['impact'], 1) for t in analyse['techniques_laterales_possibles']
            ) / len(analyse['techniques_laterales_possibles'])

            analyse['impact_propagation'] = min(impact_moyen * 2.5, 10.0)

        # Générer des recommandations
        if analyse['techniques_laterales_possibles']:
            analyse['recommandations_containment'].extend([
                "Implémenter une segmentation réseau (Zero Trust)",
                "Déployer des EDR sur tous les actifs critiques",
                "Mettre en place des contrôles d'accès réseau stricts",
                "Surveiller les connexions latérales inhabituelles"
            ])

        return analyse


class CalculateurImpactBusiness:
    """
    Calculateur d'impact business des chaînes d'attaque
    """

    def __init__(self):
        self.categories_impact = self._initialiser_categories_impact()

    def _initialiser_categories_impact(self) -> Dict[str, Dict]:
        """Initialise les catégories d'impact business"""
        return {
            'financier': {
                'data_breach': 1000000,  # 1M€ pour fuite de données
                'system_downtime': 50000,  # 50k€ par heure d'indisponibilité
                'ransomware': 500000,  # 500k€ de rançon moyenne
                'fraud': 200000,  # 200k€ de pertes par fraude
                'regulatory_fines': 300000  # 300k€ d'amendes réglementaires
            },

            'reputationnel': {
                'brand_damage': 500000,  # 500k€ de dommages réputationnels
                'customer_loss': 200000,  # 200k€ de pertes clients
                'media_coverage': 100000,  # 100k€ de gestion crise média
                'investor_confidence': 300000  # 300k€ d'impact sur investisseurs
            },

            'operationnel': {
                'recovery_costs': 150000,  # 150k€ de coûts de récupération
                'productivity_loss': 100000,  # 100k€ par jour de productivité perdue
                'legal_costs': 200000,  # 200k€ de frais juridiques
                'training_costs': 50000  # 50k€ de formation sécurité
            },

            'strategique': {
                'competitive_advantage_loss': 1000000,  # 1M€ de perte d'avantage concurrentiel
                'ip_theft': 2000000,  # 2M€ de vol de propriété intellectuelle
                'merger_acquisition_impact': 500000  # 500k€ d'impact sur fusions/acquisitions
            }
        }

    def calculer_impact_business(self, chaine_attaque: ChaineAttaque,
                               contexte_business: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Calcule l'impact business complet d'une chaîne d'attaque

        Args:
            chaine_attaque: La chaîne d'attaque
            contexte_business: Contexte business (secteur, taille, etc.)

        Returns:
            Analyse d'impact business détaillée
        """
        contexte_business = contexte_business or {}

        impact = {
            'cout_total_estime': 0.0,
            'duree_indisponibilite': 0,
            'impact_reputation': 0.0,
            'pertes_financieres': 0.0,
            'consequences_strategiques': [],
            'scenarios_risque': [],
            'recommandations_mitigation': []
        }

        # Facteurs multiplicatifs selon le contexte
        taille_entreprise = contexte_business.get('taille_entreprise', 'moyenne')
        secteur = contexte_business.get('secteur', 'general')
        criticite_donnees = contexte_business.get('criticite_donnees', 'moyenne')

        multiplicateur_taille = {'petite': 0.5, 'moyenne': 1.0, 'grande': 2.0, 'enterprise': 3.0}
        multiplicateur_criticite = {'faible': 0.5, 'moyenne': 1.0, 'haute': 2.0, 'critique': 3.0}

        facteur_multiplicateur = (multiplicateur_taille.get(taille_entreprise, 1.0) *
                                multiplicateur_criticite.get(criticite_donnees, 1.0))

        # Analyser chaque nœud pour déterminer l'impact
        for noeud in chaine_attaque.noeuds:
            impact_noeud = self._calculer_impact_noeud(noeud, contexte_business)
            impact['cout_total_estime'] += impact_noeud['cout'] * facteur_multiplicateur
            impact['duree_indisponibilite'] += impact_noeud['duree_indisponibilite']
            impact['impact_reputation'] += impact_noeud['impact_reputation']
            impact['pertes_financieres'] += impact_noeud['pertes_financieres']

            if impact_noeud['consequences']:
                impact['consequences_strategiques'].extend(impact_noeud['consequences'])

        # Générer des scénarios de risque
        impact['scenarios_risque'] = self._generer_scenarios_risque(chaine_attaque, impact)

        # Recommandations de mitigation
        impact['recommandations_mitigation'] = self._generer_recommandations_mitigation(chaine_attaque, impact)

        return impact

    def _calculer_impact_noeud(self, noeud: NoeudAttaque, contexte: Dict) -> Dict[str, Any]:
        """Calcule l'impact d'un nœud spécifique"""
        impact_noeud = {
            'cout': 0.0,
            'duree_indisponibilite': 0,
            'impact_reputation': 0.0,
            'pertes_financieres': 0.0,
            'consequences': []
        }

        nom_lower = noeud.nom.lower()

        # Impacts selon le type de nœud
        if noeud.type_noeud == TypeNoeud.VULNERABILITE:
            if 'sql' in nom_lower or 'data' in nom_lower:
                impact_noeud.update({
                    'cout': self.categories_impact['financier']['data_breach'] * 0.3,
                    'pertes_financieres': self.categories_impact['financier']['data_breach'] * 0.7,
                    'impact_reputation': self.categories_impact['reputationnel']['brand_damage'] * 0.5,
                    'consequences': ['Fuite de données clients', 'Amendes RGPD/GDPR']
                })
            elif 'rce' in nom_lower or 'system' in nom_lower:
                impact_noeud.update({
                    'cout': self.categories_impact['financier']['ransomware'] * 0.4,
                    'duree_indisponibilite': 48,  # 48 heures
                    'pertes_financieres': self.categories_impact['financier']['ransomware'] * 0.6,
                    'consequences': ['Compromission système complète', 'Ransomware possible']
                })

        elif noeud.type_noeud == TypeNoeud.PRIVILEGE:
            if 'admin' in nom_lower or 'root' in nom_lower:
                impact_noeud.update({
                    'cout': self.categories_impact['operationnel']['recovery_costs'],
                    'duree_indisponibilite': 24,
                    'consequences': ['Escalade de privilèges critique', 'Accès à tous les systèmes']
                })

        elif noeud.type_noeud == TypeNoeud.SYSTEME:
            impact_noeud.update({
                'cout': self.categories_impact['financier']['system_downtime'] * 10,  # 10 heures
                'duree_indisponibilite': 240,  # 10 jours
                'impact_reputation': self.categories_impact['reputationnel']['brand_damage'],
                'pertes_financieres': self.categories_impact['financier']['fraud'],
                'consequences': ['Indisponibilité système totale', 'Perte de confiance clients']
            })

        return impact_noeud

    def _generer_scenarios_risque(self, chaine: ChaineAttaque, impact: Dict) -> List[Dict]:
        """Génère des scénarios de risque réalistes"""
        scenarios = []

        # Scénario pessimiste
        scenarios.append({
            'nom': 'Scénario Pessimiste (100% réussite attaque)',
            'probabilite': chaine.probabilite_succes_total,
            'impact_financier': impact['cout_total_estime'] + impact['pertes_financieres'],
            'duree_crise': impact['duree_indisponibilite'] + 30,  # +30 jours récupération
            'consequences': ['Arrêt complet des opérations', 'Perte massive de clients', 'Poursuites judiciaires']
        })

        # Scénario réaliste
        scenarios.append({
            'nom': 'Scénario Réaliste (70% réussite)',
            'probabilite': chaine.probabilite_succes_total * 0.7,
            'impact_financier': (impact['cout_total_estime'] + impact['pertes_financieres']) * 0.7,
            'duree_crise': int(impact['duree_indisponibilite'] * 0.7),
            'consequences': ['Perturbation partielle des services', 'Perte de confiance limitée']
        })

        # Scénario optimiste
        scenarios.append({
            'nom': 'Scénario Optimiste (Détection précoce)',
            'probabilite': chaine.probabilite_succes_total * 0.3,
            'impact_financier': (impact['cout_total_estime'] + impact['pertes_financieres']) * 0.3,
            'duree_crise': int(impact['duree_indisponibilite'] * 0.3),
            'consequences': ['Impact minimal grâce à la détection rapide']
        })

        return scenarios

    def _generer_recommandations_mitigation(self, chaine: ChaineAttaque, impact: Dict) -> List[str]:
        """Génère des recommandations de mitigation"""
        recommandations = []

        # Recommandations basées sur le score de risque
        if chaine.score_global >= 25:
            recommandations.extend([
                "URGENT: Corriger immédiatement toutes les vulnérabilités critiques",
                "Implémenter un SOC 24/7 pour surveillance continue",
                "Réaliser un audit de sécurité indépendant"
            ])

        # Recommandations basées sur l'impact financier
        impact_total = impact['cout_total_estime'] + impact['pertes_financieres']
        if impact_total >= 1000000:  # 1M€
            recommandations.extend([
                "Souscrire une assurance cyber appropriée",
                "Développer un plan de continuité d'activité détaillé",
                "Mettre en place des sauvegardes immuables"
            ])

        # Recommandations basées sur la durée d'indisponibilité
        if impact['duree_indisponibilite'] >= 168:  # 1 semaine
            recommandations.extend([
                "Implémenter une architecture haute disponibilité",
                "Mettre en place des plans de reprise d'activité",
                "Tester régulièrement les procédures de failover"
            ])

        # Recommandations générales
        recommandations.extend([
            "Mettre en place un programme de sécurité continu",
            "Former l'équipe aux bonnes pratiques de sécurité",
            "Réaliser des tests de pénétration réguliers"
        ])

        return list(set(recommandations))  # Éliminer les doublons


class ScoreurPrioriteRemediation:
    """
    Calculateur de scores de priorité pour les remédiations
    """

    def __init__(self):
        self.facteurs_priorite = self._initialiser_facteurs_priorite()

    def _initialiser_facteurs_priorite(self) -> Dict[str, Dict]:
        """Initialise les facteurs de priorité pour les remédiations"""
        return {
            'exploitability': {
                'description': 'Facilité d\'exploitation',
                'poids': 0.25,
                'niveaux': {'facile': 10, 'moyen': 5, 'difficile': 1}
            },

            'impact_business': {
                'description': 'Impact business',
                'poids': 0.30,
                'niveaux': {'critique': 10, 'élevé': 7, 'moyen': 4, 'faible': 1}
            },

            'probabilite_succes': {
                'description': 'Probabilité de succès de l\'attaque',
                'poids': 0.20,
                'niveaux': {'tres_haute': 10, 'haute': 7, 'moyenne': 4, 'faible': 1}
            },

            'complexite_remediation': {
                'description': 'Complexité de la remédiation',
                'poids': 0.15,
                'niveaux': {'faible': 10, 'moyenne': 5, 'haute': 1}  # Plus c'est facile, plus prioritaire
            },

            'regulatory_compliance': {
                'description': 'Conformité réglementaire requise',
                'poids': 0.10,
                'niveaux': {'critique': 10, 'haute': 7, 'moyenne': 4, 'faible': 1}
            }
        }

    def calculer_priorite_remediation(self, vulnerabilite: Vulnerabilite,
                                    contexte: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Calcule le score de priorité pour la remédiation d'une vulnérabilité

        Args:
            vulnerabilite: La vulnérabilité à prioriser
            contexte: Contexte de remédiation

        Returns:
            Analyse de priorité détaillée
        """
        contexte = contexte or {}

        priorite = {
            'score_global': 0.0,
            'niveau_priorite': 'low',
            'facteurs_influents': {},
            'temps_recommande': '90 jours',
            'justification': '',
            'actions_recommandees': []
        }

        # Calculer chaque facteur
        score_total = 0.0

        for facteur_nom, config in self.facteurs_priorite.items():
            valeur_facteur = self._evaluer_facteur(vulnerabilite, facteur_nom, contexte)
            score_facteur = config['niveaux'].get(valeur_facteur, 5) * config['poids']
            score_total += score_facteur

            priorite['facteurs_influents'][facteur_nom] = {
                'valeur': valeur_facteur,
                'score': score_facteur,
                'poids': config['poids']
            }

        priorite['score_global'] = min(score_total, 10.0)  # Max 10

        # Déterminer le niveau de priorité
        if priorite['score_global'] >= 8.0:
            priorite['niveau_priorite'] = 'critical'
            priorite['temps_recommande'] = '7 jours'
        elif priorite['score_global'] >= 6.0:
            priorite['niveau_priorite'] = 'high'
            priorite['temps_recommande'] = '30 jours'
        elif priorite['score_global'] >= 4.0:
            priorite['niveau_priorite'] = 'medium'
            priorite['temps_recommande'] = '90 jours'
        else:
            priorite['niveau_priorite'] = 'low'
            priorite['temps_recommande'] = '180 jours'

        # Générer justification et actions
        priorite['justification'] = self._generer_justification(priorite)
        priorite['actions_recommandees'] = self._generer_actions_recommandees(vulnerabilite, priorite)

        return priorite

    def _evaluer_facteur(self, vuln: Vulnerabilite, facteur: str, contexte: Dict) -> str:
        """Évalue un facteur spécifique pour la vulnérabilité"""
        type_lower = vuln.type.lower()
        severite = vuln.severite.lower()

        if facteur == 'exploitability':
            if any(keyword in type_lower for keyword in ['sql', 'xss', 'weak password']):
                return 'facile'
            elif any(keyword in type_lower for keyword in ['rce', 'command injection']):
                return 'moyen'
            else:
                return 'difficile'

        elif facteur == 'impact_business':
            if severite == 'critique':
                return 'critique'
            elif severite == 'élevé':
                return 'élevé'
            elif severite == 'moyen':
                return 'moyen'
            else:
                return 'faible'

        elif facteur == 'probabilite_succes':
            if severite == 'critique':
                return 'tres_haute'
            elif severite == 'élevé':
                return 'haute'
            elif severite == 'moyen':
                return 'moyenne'
            else:
                return 'faible'

        elif facteur == 'complexite_remediation':
            if 'configuration' in type_lower or 'password' in type_lower:
                return 'faible'
            elif 'code' in type_lower or 'development' in type_lower:
                return 'moyenne'
            else:
                return 'haute'

        elif facteur == 'regulatory_compliance':
            secteur = contexte.get('secteur', 'general')
            if secteur in ['finance', 'sante', 'government']:
                if any(keyword in type_lower for keyword in ['data', 'privacy', 'auth']):
                    return 'critique'
                else:
                    return 'haute'
            else:
                return 'moyenne'

        return 'moyenne'  # Valeur par défaut

    def _generer_justification(self, priorite: Dict) -> str:
        """Génère une justification pour la priorité"""
        score = priorite['score_global']
        niveau = priorite['niveau_priorite']

        facteurs_cle = sorted(
            priorite['facteurs_influents'].items(),
            key=lambda x: x[1]['score'],
            reverse=True
        )[:2]

        facteurs_str = ", ".join([f"{k} ({v['valeur']})" for k, v in facteurs_cle])

        return f"Priorité {niveau} (score: {score:.1f}/10) due principalement à: {facteurs_str}"

    def _generer_actions_recommandees(self, vuln: Vulnerabilite, priorite: Dict) -> List[str]:
        """Génère des actions recommandées selon la priorité"""
        actions = []
        niveau = priorite['niveau_priorite']
        type_lower = vuln.type.lower()

        # Actions selon le niveau de priorité
        if niveau == 'critical':
            actions.extend([
                "Créer un ticket d'urgence et assigner immédiatement",
                "Isoler les systèmes affectés si nécessaire",
                "Notifier l'équipe de sécurité senior"
            ])

        elif niveau == 'high':
            actions.extend([
                "Planifier la correction dans les 30 jours",
                "Mettre en place des mesures de mitigation temporaires",
                "Informer les équipes techniques concernées"
            ])

        # Actions spécifiques selon le type de vulnérabilité
        if 'sql' in type_lower:
            actions.extend([
                "Implémenter des requêtes préparées",
                "Valider et échapper toutes les entrées utilisateur",
                "Utiliser un WAF pour protection temporaire"
            ])

        elif 'xss' in type_lower:
            actions.extend([
                "Encoder toutes les sorties HTML",
                "Implémenter Content Security Policy (CSP)",
                "Valider et filtrer les entrées utilisateur"
            ])

        elif 'auth' in type_lower or 'password' in type_lower:
            actions.extend([
                "Forcer le changement de mots de passe",
                "Implémenter l'authentification multi-facteurs",
                "Réviser les politiques de mots de passe"
            ])

        elif 'data' in type_lower or 'information' in type_lower:
            actions.extend([
                "Chiffrer les données sensibles au repos et en transit",
                "Implémenter des contrôles d'accès stricts",
                "Auditer l'accès aux données sensibles"
            ])

        return list(set(actions))  # Éliminer les doublons


class OrchestrateurChainesAttaque:
    """
    Orchestrateur principal pour l'analyse de chaînes d'attaque
    """

    def __init__(self):
        self.constructeur_arbres = ConstructeurArbresAttaque()
        self.analyseur_escalade = AnalyseurEscaladePrivileges()
        self.analyseur_lateral = AnalyseurMouvementLateral()
        self.calculateur_impact = CalculateurImpactBusiness()
        self.scoreur_priorite = ScoreurPrioriteRemediation()

    async def analyser_chaine_complete(self, vulnerabilites: List[Vulnerabilite],
                                    contexte: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Analyse complète des chaînes d'attaque

        Args:
            vulnerabilites: Liste des vulnérabilités découvertes
            contexte: Contexte d'analyse complet

        Returns:
            Rapport d'analyse de chaînes d'attaque
        """
        contexte = contexte or {}

        rapport = {
            'date_analyse': datetime.now().isoformat(),
            'total_vulnerabilites': len(vulnerabilites),
            'chaines_identifiees': [],
            'analyse_escalade': {},
            'analyse_laterale': {},
            'impact_business': {},
            'priorites_remediation': [],
            'recommandations_globales': []
        }

        # 1. Construire les arbres d'attaque
        try:
            arbre_attaque = self.constructeur_arbres.construire_arbre_attaque(vulnerabilites, contexte)
            rapport['chaines_identifiees'].append({
                'id_chaine': arbre_attaque.id_chaine,
                'score_global': arbre_attaque.score_global,
                'niveau_risque': arbre_attaque.niveau_risque,
                'probabilite_succes': arbre_attaque.probabilite_succes_total,
                'objectifs_atteints': arbre_attaque.objectifs_atteints,
                'noeuds_critiques': len(arbre_attaque.noeuds)
            })
        except Exception as e:
            rapport['erreur_construction'] = str(e)

        # 2. Analyser l'escalade de privilèges
        if 'chaines_identifiees' in rapport and rapport['chaines_identifiees']:
            rapport['analyse_escalade'] = self.analyseur_escalade.analyser_escalade_privileges(arbre_attaque)

        # 3. Analyser le mouvement latéral
        if 'chaines_identifiees' in rapport and rapport['chaines_identifiees']:
            rapport['analyse_laterale'] = self.analyseur_lateral.analyser_mouvement_lateral(arbre_attaque)

        # 4. Calculer l'impact business
        if 'chaines_identifiees' in rapport and rapport['chaines_identifiees']:
            rapport['impact_business'] = self.calculateur_impact.calculer_impact_business(
                arbre_attaque, contexte.get('business', {})
            )

        # 5. Calculer les priorités de remédiation
        for vuln in vulnerabilites:
            priorite = self.scoreur_priorite.calculer_priorite_remediation(vuln, contexte)
            rapport['priorites_remediation'].append({
                'vulnerabilite': vuln.type,
                'score_priorite': priorite['score_global'],
                'niveau_priorite': priorite['niveau_priorite'],
                'temps_recommande': priorite['temps_recommande'],
                'actions_cle': priorite['actions_recommandees'][:2]
            })

        # 6. Générer recommandations globales
        rapport['recommandations_globales'] = self._generer_recommandations_globales(rapport)

        return rapport

    def _generer_recommandations_globales(self, rapport: Dict) -> List[str]:
        """Génère des recommandations globales basées sur l'analyse complète"""
        recommandations = []

        # Analyser les chaînes d'attaque
        chaines = rapport.get('chaines_identifiees', [])
        if chaines:
            chaine_principale = chaines[0]
            if chaine_principale.get('niveau_risque') == 'critical':
                recommandations.append("CHAÎNE CRITIQUE: Prioriser la correction des vulnérabilités d'entrée (web/auth)")

        # Analyser l'escalade
        escalade = rapport.get('analyse_escalade', {})
        if escalade.get('probabilite_escalade', 0) > 0.7:
            recommandations.append("RISQUE ÉCALADE: Implémenter des contrôles de segmentation réseau")

        # Analyser l'impact business
        impact = rapport.get('impact_business', {})
        if impact.get('cout_total_estime', 0) > 500000:
            recommandations.append("IMPACT FINANCIER ÉLEVÉ: Développer un plan de réponse aux incidents")

        # Analyser les priorités
        priorites = rapport.get('priorites_remediation', [])
        priorites_critiques = [p for p in priorites if p.get('niveau_priorite') == 'critical']
        if len(priorites_critiques) > 2:
            recommandations.append("MULTIPLES PRIORITÉS CRITIQUES: Créer un plan de remédiation accéléré")

        return recommandations if recommandations else ["Analyse complète réalisée - maintenir la surveillance continue"]
