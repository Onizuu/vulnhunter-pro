"""
Système de scan distribué pour VulnHunter Pro
Multi-threading avancé, load balancing, architecture distribuée
"""

import asyncio
import threading
import multiprocessing
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import queue
import time
from typing import Dict, List, Tuple, Optional, Any, Callable
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin
import random
import socket
import aiohttp
from loguru import logger

from core.models import Vulnerabilite


@dataclass
class TacheScan:
    """Représente une tâche de scan à exécuter"""
    id_tache: str
    url: str
    type_scan: str
    priorite: int = 1
    timeout: int = 30
    retries: int = 3
    contexte: Dict[str, Any] = field(default_factory=dict)
    timestamp_creation: float = field(default_factory=time.time)
    timestamp_debut: Optional[float] = None
    timestamp_fin: Optional[float] = None
    statut: str = "en_attente"
    resultat: Optional[Any] = None
    erreur: Optional[str] = None


@dataclass
class WorkerNode:
    """Représente un nœud worker dans le système distribué"""
    id_worker: str
    type_worker: str  # 'thread', 'process', 'remote'
    capacite_max: int
    taches_actives: int = 0
    taches_terminees: int = 0
    statut: str = "disponible"
    dernier_ping: float = field(default_factory=time.time)
    performance_score: float = 1.0
    specialites: List[str] = field(default_factory=list)


class LoadBalancer:
    """
    Système de load balancing intelligent pour répartir les tâches
    """

    def __init__(self):
        self.workers: Dict[str, WorkerNode] = {}
        self.queue_taches = asyncio.Queue()
        self.statistiques = {
            'taches_totales': 0,
            'taches_terminees': 0,
            'taches_echouees': 0,
            'temps_moyen_execution': 0.0,
            'workers_actifs': 0
        }

    def ajouter_worker(self, worker: WorkerNode):
        """Ajoute un worker au pool"""
        self.workers[worker.id_worker] = worker
        logger.info(f"🏭 Worker {worker.id_worker} ajouté ({worker.type_worker})")

    def retirer_worker(self, worker_id: str):
        """Retire un worker du pool"""
        if worker_id in self.workers:
            del self.workers[worker_id]
            logger.info(f"🏭 Worker {worker_id} retiré")

    def obtenir_worker_optimal(self, tache: TacheScan) -> Optional[WorkerNode]:
        """
        Sélectionne le worker optimal pour une tâche selon plusieurs critères
        """
        workers_disponibles = [
            w for w in self.workers.values()
            if w.statut == "disponible" and w.taches_actives < w.capacite_max
        ]

        if not workers_disponibles:
            return None

        # Score pour chaque worker
        scores_workers = {}
        for worker in workers_disponibles:
            score = worker.performance_score

            # Bonus pour spécialisation
            if tache.type_scan in worker.specialites:
                score *= 1.5

            # Pénalisation pour charge élevée
            charge_ratio = worker.taches_actives / worker.capacite_max
            score *= (1 - charge_ratio * 0.3)

            # Bonus pour priorité élevée
            if tache.priorite >= 3:
                score *= 1.2

            scores_workers[worker.id_worker] = score

        # Sélection du meilleur worker
        meilleur_worker_id = max(scores_workers, key=scores_workers.get)
        return self.workers[meilleur_worker_id]

    async def distribuer_tache(self, tache: TacheScan) -> Optional[str]:
        """Distribue une tâche au worker optimal"""
        worker = self.obtenir_worker_optimal(tache)

        if not worker:
            logger.warning(f"⚠️ Aucun worker disponible pour la tâche {tache.id_tache}")
            return None

        # Assigner la tâche au worker
        worker.taches_actives += 1
        worker.statut = "occupe" if worker.taches_actives >= worker.capacite_max else "disponible"

        self.statistiques['taches_totales'] += 1

        logger.debug(f"📤 Tâche {tache.id_tache} assignée au worker {worker.id_worker}")
        return worker.id_worker

    def mettre_a_jour_statut_worker(self, worker_id: str, statut: str, performance: float = None):
        """Met à jour le statut d'un worker"""
        if worker_id in self.workers:
            worker = self.workers[worker_id]

            if statut == "termine":
                worker.taches_actives = max(0, worker.taches_actives - 1)
                worker.taches_terminees += 1
            elif statut == "echec":
                worker.taches_actives = max(0, worker.taches_actives - 1)
                self.statistiques['taches_echouees'] += 1

            worker.statut = "disponible" if worker.taches_actives < worker.capacite_max else "occupe"
            worker.dernier_ping = time.time()

            if performance is not None:
                # Mise à jour du score de performance (moyenne pondérée)
                worker.performance_score = (worker.performance_score * 0.8) + (performance * 0.2)

    def obtenir_statistiques(self) -> Dict[str, Any]:
        """Retourne les statistiques du load balancer"""
        return {
            **self.statistiques,
            'workers': {
                wid: {
                    'statut': w.statut,
                    'taches_actives': w.taches_actives,
                    'performance': w.performance_score
                }
                for wid, w in self.workers.items()
            },
            'file_attente': self.queue_taches.qsize()
        }


class RateLimiterIntelligent:
    """
    Système de rate limiting intelligent avec apprentissage automatique
    """

    def __init__(self):
        self.domaines_rates: Dict[str, Dict] = {}
        self.global_rate = 10  # requêtes par seconde max global
        self.dernieres_requetes = []
        self.bloquages_detectes = {}
        self.apprentissage_actif = True

    def verifier_rate_limit(self, url: str) -> Tuple[bool, float]:
        """
        Vérifie si une requête peut être faite selon les limites de taux

        Returns:
            (autorise: bool, delai_attente: float)
        """
        domaine = urlparse(url).netloc

        maintenant = time.time()

        # Nettoyer les anciennes requêtes (fenêtre de 60 secondes)
        self.dernieres_requetes = [
            req for req in self.dernieres_requetes
            if maintenant - req['timestamp'] < 60
        ]

        # Compter les requêtes récentes par domaine
        requetes_domaine = [
            req for req in self.dernieres_requetes
            if req['domaine'] == domaine
        ]

        # Récupérer ou initialiser les limites pour ce domaine
        if domaine not in self.domaines_rates:
            self.domaines_rates[domaine] = {
                'rate_max': 5,  # début conservateur
                'bloquages': 0,
                'derniere_adaptation': maintenant
            }

        config_domaine = self.domaines_rates[domaine]

        # Vérifier si domaine est bloqué
        if domaine in self.bloquages_detectes:
            blocage_info = self.bloquages_detectes[domaine]
            if maintenant - blocage_info['timestamp'] < blocage_info['duree']:
                return False, blocage_info['duree'] - (maintenant - blocage_info['timestamp'])

        # Vérifier limite globale
        if len(self.dernieres_requetes) >= self.global_rate:
            plus_ancienne = min(req['timestamp'] for req in self.dernieres_requetes)
            delai = 1.0 - (maintenant - plus_ancienne)
            return False, max(0.1, delai)

        # Vérifier limite par domaine
        if len(requetes_domaine) >= config_domaine['rate_max']:
            plus_ancienne_domaine = min(req['timestamp'] for req in requetes_domaine)
            delai = 1.0 - (maintenant - plus_ancienne_domaine)
            return False, max(0.1, delai)

        return True, 0.0

    def enregistrer_requete(self, url: str, succes: bool = True, code_statut: int = 200):
        """Enregistre une requête pour l'apprentissage"""
        domaine = urlparse(url).netloc
        maintenant = time.time()

        self.dernieres_requetes.append({
            'domaine': domaine,
            'timestamp': maintenant,
            'succes': succes,
            'code_statut': code_statut
        })

        # Apprentissage automatique des limites
        if self.apprentissage_actif:
            self._adapter_limites(domaine, succes, code_statut)

    def _adapter_limites(self, domaine: str, succes: bool, code_statut: int):
        """Adapte les limites de taux selon les réponses"""
        if domaine not in self.domaines_rates:
            return

        config = self.domaines_rates[domaine]
        maintenant = time.time()

        # Si succès, augmenter légèrement la limite
        if succes and code_statut < 400:
            if maintenant - config['derniere_adaptation'] > 30:  # toutes les 30s
                config['rate_max'] = min(config['rate_max'] + 1, 20)  # max 20 req/s
                config['derniere_adaptation'] = maintenant

        # Si blocage détecté (429, 503, etc.)
        elif code_statut in [429, 503, 502, 504]:
            config['bloquages'] += 1
            config['rate_max'] = max(1, config['rate_max'] // 2)  # réduire de moitié
            config['derniere_adaptation'] = maintenant

            # Marquer comme bloqué temporairement
            self.bloquages_detectes[domaine] = {
                'timestamp': maintenant,
                'duree': 60  # 1 minute de blocage
            }
            logger.warning(f"🚫 Blocage détecté pour {domaine}, réduction du taux")

    def obtenir_statistiques(self) -> Dict[str, Any]:
        """Retourne les statistiques du rate limiter"""
        return {
            'global_rate': self.global_rate,
            'requetes_actives': len(self.dernieres_requetes),
            'domaines_surveilles': len(self.domaines_rates),
            'bloquages_actifs': len(self.bloquages_detectes),
            'limites_domaines': {
                domaine: config['rate_max']
                for domaine, config in self.domaines_rates.items()
            }
        }


class ProxyRotator:
    """
    Système de rotation automatique de proxies
    """

    def __init__(self):
        self.proxies_disponibles = []
        self.proxies_actifs = {}
        self.performance_proxies = {}
        self.derniere_rotation = time.time()

    def ajouter_proxy(self, proxy_url: str, type_proxy: str = 'http'):
        """Ajoute un proxy à la liste"""
        if proxy_url not in self.proxies_disponibles:
            self.proxies_disponibles.append(proxy_url)
            self.performance_proxies[proxy_url] = {
                'succes': 0,
                'echecs': 0,
                'temps_moyen': 0.0,
                'dernier_usage': None,
                'score': 1.0
            }
            logger.info(f"🌐 Proxy ajouté: {proxy_url}")

    def obtenir_proxy_optimal(self, domaine: str = None) -> Optional[str]:
        """
        Sélectionne le meilleur proxy selon les performances
        """
        if not self.proxies_disponibles:
            return None

        # Calculer scores des proxies
        scores_proxies = {}
        maintenant = time.time()

        for proxy in self.proxies_disponibles:
            perf = self.performance_proxies[proxy]

            # Score basé sur taux de succès
            total = perf['succes'] + perf['echecs']
            if total > 0:
                taux_succes = perf['succes'] / total
            else:
                taux_succes = 0.5  # score par défaut

            # Pénalisation pour temps lent
            score_temps = max(0.1, 1.0 - (perf['temps_moyen'] / 10.0))

            # Bonus pour utilisation récente (éviter les blocages)
            if perf['dernier_usage']:
                temps_depuis_usage = maintenant - perf['dernier_usage']
                score_fraicheur = min(1.0, temps_depuis_usage / 300.0)  # 5 minutes
            else:
                score_fraicheur = 1.0

            score_final = taux_succes * score_temps * score_fraicheur * perf['score']
            scores_proxies[proxy] = score_final

        if not scores_proxies:
            return random.choice(self.proxies_disponibles)

        # Sélectionner le meilleur proxy
        meilleur_proxy = max(scores_proxies, key=scores_proxies.get)
        return meilleur_proxy

    def marquer_proxy_resultat(self, proxy: str, succes: bool, temps_reponse: float):
        """Met à jour les performances d'un proxy"""
        if proxy in self.performance_proxies:
            perf = self.performance_proxies[proxy]

            if succes:
                perf['succes'] += 1
            else:
                perf['echecs'] += 1

            # Mise à jour du temps moyen
            total_temps = perf['temps_moyen'] * (perf['succes'] + perf['echecs'] - 1)
            perf['temps_moyen'] = (total_temps + temps_reponse) / (perf['succes'] + perf['echecs'])

            perf['dernier_usage'] = time.time()

            # Mise à jour du score global
            total = perf['succes'] + perf['echecs']
            if total >= 5:  # Après 5 utilisations minimum
                taux_succes = perf['succes'] / total
                perf['score'] = taux_succes * max(0.1, 1.0 - (perf['temps_moyen'] / 5.0))

    def nettoyer_proxies(self):
        """Nettoie les proxies défaillants"""
        proxies_a_supprimer = []

        for proxy, perf in self.performance_proxies.items():
            total = perf['succes'] + perf['echecs']

            if total >= 10:  # Après 10 utilisations
                taux_succes = perf['succes'] / total
                if taux_succes < 0.3:  # Moins de 30% de succès
                    proxies_a_supprimer.append(proxy)

        for proxy in proxies_a_supprimer:
            if proxy in self.proxies_disponibles:
                self.proxies_disponibles.remove(proxy)
                del self.performance_proxies[proxy]
                logger.info(f"🗑️ Proxy supprimé (défaillant): {proxy}")

    def obtenir_statistiques(self) -> Dict[str, Any]:
        """Retourne les statistiques des proxies"""
        return {
            'total_proxies': len(self.proxies_disponibles),
            'performance_proxies': {
                proxy: {
                    'succes': perf['succes'],
                    'echecs': perf['echecs'],
                    'taux_succes': (perf['succes'] / (perf['succes'] + perf['echecs'])) if (perf['succes'] + perf['echecs']) > 0 else 0,
                    'temps_moyen': perf['temps_moyen'],
                    'score': perf['score']
                }
                for proxy, perf in self.performance_proxies.items()
            }
        }


class OrchestrateurDistribue:
    """
    Orchestrateur principal du système de scan distribué
    """

    def __init__(self, max_workers_threads: int = 20, max_workers_process: int = 4):
        self.load_balancer = LoadBalancer()
        self.rate_limiter = RateLimiterIntelligent()
        self.proxy_rotator = ProxyRotator()

        # Initialiser les workers
        self._initialiser_workers(max_workers_threads, max_workers_process)

        # Statistiques globales
        self.statistiques_globales = {
            'scans_actifs': 0,
            'scans_termines': 0,
            'temps_moyen_scan': 0.0,
            'erreurs_totales': 0
        }

        logger.info("🎼 Orchestrateur distribué initialisé")

    def _initialiser_workers(self, max_threads: int, max_process: int):
        """Initialise les workers (threads et processus)"""
        # Workers threads pour tâches I/O bound
        for i in range(max_threads):
            worker = WorkerNode(
                id_worker=f"thread_{i}",
                type_worker="thread",
                capacite_max=5,
                specialites=['http_requests', 'api_scanning', 'lightweight_tasks']
            )
            self.load_balancer.ajouter_worker(worker)

        # Workers processus pour tâches CPU bound
        for i in range(max_process):
            worker = WorkerNode(
                id_worker=f"process_{i}",
                type_worker="process",
                capacite_max=2,
                specialites=['heavy_computation', 'ml_processing', 'complex_analysis']
            )
            self.load_balancer.ajouter_worker(worker)

        logger.info(f"👷 {max_threads} workers threads et {max_process} workers processus initialisés")

    async def scanner_distribue(self, urls: List[str], config_scan: Dict[str, Any]) -> Dict[str, Any]:
        """
        Lance un scan distribué sur plusieurs URLs

        Args:
            urls: Liste des URLs à scanner
            config_scan: Configuration du scan

        Returns:
            Résultats consolidés du scan distribué
        """
        debut_scan = time.time()
        logger.info(f"🚀 Démarrage scan distribué: {len(urls)} URLs")

        # Créer les tâches de scan
        taches_scan = []
        for i, url in enumerate(urls):
            tache = TacheScan(
                id_tache=f"scan_{i}",
                url=url,
                type_scan="full_scan",
                priorite=config_scan.get('priorite', 1),
                contexte={
                    'config': config_scan,
                    'index': i,
                    'total': len(urls)
                }
            )
            taches_scan.append(tache)

        # Exécuter les scans distribués
        resultats = await self._executer_scans_distribues(taches_scan)

        # Analyser et consolider les résultats
        rapport_final = self._consolider_resultats(resultats, debut_scan)

        logger.success(f"✅ Scan distribué terminé: {len(urls)} URLs scannées en {rapport_final['duree_totale']:.1f}s")
        return rapport_final

    async def _executer_scans_distribues(self, taches: List[TacheScan]) -> List[Dict]:
        """
        Exécute les tâches de scan de manière distribuée
        """
        semaphore = asyncio.Semaphore(50)  # Limite globale de concurrence
        resultats = []

        async def executer_tache(tache: TacheScan):
            async with semaphore:
                try:
                    # Distribuer la tâche
                    worker_id = await self.load_balancer.distribuer_tache(tache)
                    if not worker_id:
                        # Aucun worker disponible, attendre
                        await asyncio.sleep(1)
                        return await executer_tache(tache)

                    tache.timestamp_debut = time.time()
                    tache.statut = "en_cours"

                    # Exécuter le scan selon le type de worker
                    if worker_id.startswith("thread"):
                        resultat = await self._executer_scan_thread(tache)
                    elif worker_id.startswith("process"):
                        resultat = await self._executer_scan_process(tache)
                    else:
                        resultat = await self._executer_scan_generique(tache)

                    # Finaliser la tâche
                    tache.timestamp_fin = time.time()
                    tache.statut = "termine"
                    tache.resultat = resultat

                    # Calculer performance du worker
                    temps_execution = tache.timestamp_fin - tache.timestamp_debut
                    performance = 1.0 / (1.0 + temps_execution)  # Score basé sur vitesse

                    self.load_balancer.mettre_a_jour_statut_worker(
                        worker_id, "termine", performance
                    )

                    resultats.append({
                        'tache': tache,
                        'resultat': resultat,
                        'worker': worker_id,
                        'temps_execution': temps_execution
                    })

                except Exception as e:
                    logger.error(f"❌ Erreur exécution tâche {tache.id_tache}: {str(e)}")
                    tache.statut = "echec"
                    tache.erreur = str(e)
                    self.statistiques_globales['erreurs_totales'] += 1

        # Exécuter toutes les tâches en parallèle
        await asyncio.gather(*[executer_tache(tache) for tache in taches], return_exceptions=True)

        return resultats

    async def _executer_scan_thread(self, tache: TacheScan) -> Dict[str, Any]:
        """Exécute un scan dans un thread (pour tâches I/O bound)"""
        loop = asyncio.get_event_loop()

        def scan_blocking():
            # Simulation d'un scan I/O bound
            time.sleep(random.uniform(0.5, 2.0))  # Temps aléatoire pour simulation

            # Vérifier rate limiting
            autorise, delai = self.rate_limiter.verifier_rate_limit(tache.url)
            if not autorise:
                time.sleep(delai)

            # Obtenir un proxy
            proxy = self.proxy_rotator.obtenir_proxy_optimal(tache.url)

            # Simuler scan et enregistrer métriques
            succes = random.random() > 0.1  # 90% de succès
            temps_reponse = random.uniform(0.1, 1.0)

            self.rate_limiter.enregistrer_requete(tache.url, succes, 200 if succes else 500)
            if proxy:
                self.proxy_rotator.marquer_proxy_resultat(proxy, succes, temps_reponse)

            return {
                'url': tache.url,
                'succes': succes,
                'vulnerabilites_trouvees': random.randint(0, 3) if succes else 0,
                'proxy_utilise': proxy,
                'temps_reponse': temps_reponse
            }

        return await loop.run_in_executor(None, scan_blocking)

    async def _executer_scan_process(self, tache: TacheScan) -> Dict[str, Any]:
        """Exécute un scan dans un processus (pour tâches CPU bound)"""
        # Simulation d'un scan CPU bound (analyse ML, etc.)
        await asyncio.sleep(random.uniform(1.0, 3.0))

        # Analyse complexe simulée
        complexite = random.uniform(0.1, 1.0)
        await asyncio.sleep(complexite)  # Plus c'est complexe, plus c'est long

        return {
            'url': tache.url,
            'succes': True,
            'analyse_ml_effectuee': True,
            'score_confiance': random.uniform(0.5, 1.0),
            'complexite_traitee': complexite
        }

    async def _executer_scan_generique(self, tache: TacheScan) -> Dict[str, Any]:
        """Exécute un scan générique"""
        await asyncio.sleep(random.uniform(0.5, 1.5))

        return {
            'url': tache.url,
            'succes': random.random() > 0.05,  # 95% de succès
            'type_scan': tache.type_scan,
            'resultat': f"Scan {tache.type_scan} terminé"
        }

    def _consolider_resultats(self, resultats: List[Dict], debut_scan: float) -> Dict[str, Any]:
        """Consolide les résultats de tous les scans"""
        duree_totale = time.time() - debut_scan

        # Statistiques générales
        scans_reussis = sum(1 for r in resultats if r.get('resultat', {}).get('succes', False))
        scans_total = len(resultats)

        # Agrégation des vulnérabilités
        vuln_totales = sum(r.get('resultat', {}).get('vulnerabilites_trouvees', 0) for r in resultats)

        # Performance des workers
        stats_workers = self.load_balancer.obtenir_statistiques()

        # Statistiques des proxies
        stats_proxies = self.proxy_rotator.obtenir_statistiques()

        # Statistiques du rate limiting
        stats_rate = self.rate_limiter.obtenir_statistiques()

        return {
            'duree_totale': duree_totale,
            'scans_total': scans_total,
            'scans_reussis': scans_reussis,
            'taux_succes': scans_reussis / scans_total if scans_total > 0 else 0,
            'vulnerabilites_totales': vuln_totales,
            'performance_workers': stats_workers,
            'performance_proxies': stats_proxies,
            'performance_rate_limiting': stats_rate,
            'resultats_detailes': resultats,
            'recommandations': self._generer_recommandations_distribuees(
                scans_total, duree_totale, scans_reussis
            )
        }

    def _generer_recommandations_distribuees(self, total_scans: int, duree: float,
                                           scans_reussis: int) -> List[str]:
        """Génère des recommandations pour optimiser le scan distribué"""
        recommandations = []

        taux_succes = scans_reussis / total_scans if total_scans > 0 else 0

        if taux_succes < 0.8:
            recommandations.append("Taux de succès faible - envisager d'ajouter plus de proxies")

        temps_moyen_par_scan = duree / total_scans if total_scans > 0 else 0
        if temps_moyen_par_scan > 5.0:
            recommandations.append("Temps de scan élevé - optimiser la répartition des workers")

        stats_workers = self.load_balancer.obtenir_statistiques()
        workers_inactifs = sum(1 for w in stats_workers.get('workers', {}).values()
                             if w.get('taches_actives', 0) == 0)

        if workers_inactifs > len(stats_workers.get('workers', {})) * 0.5:
            recommandations.append("Beaucoup de workers inactifs - réduire le nombre de workers")

        if len(self.proxy_rotator.proxies_disponibles) < 5:
            recommandations.append("Nombre de proxies limité - ajouter plus de proxies pour meilleure distribution")

        return recommandations if recommandations else ["Configuration optimale détectée"]

    def ajouter_proxy(self, proxy_url: str):
        """Ajoute un proxy au système"""
        self.proxy_rotator.ajouter_proxy(proxy_url)

    def obtenir_statistiques_globales(self) -> Dict[str, Any]:
        """Retourne les statistiques globales du système distribué"""
        return {
            'orchestrateur': self.statistiques_globales,
            'load_balancer': self.load_balancer.obtenir_statistiques(),
            'rate_limiter': self.rate_limiter.obtenir_statistiques(),
            'proxy_rotator': self.proxy_rotator.obtenir_statistiques()
        }

    async def nettoyer_systeme(self):
        """Nettoie le système distribué (proxies défaillants, etc.)"""
        self.proxy_rotator.nettoyer_proxies()
        logger.info("🧹 Système distribué nettoyé")
