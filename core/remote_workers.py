"""
Système de workers à distance pour VulnHunter Pro
Distribution réelle sur plusieurs machines
"""

import asyncio
import socket
import json
import threading
import time
from typing import Dict, List, Tuple, Optional, Any, Callable
from dataclasses import dataclass, field
import websockets
import aiohttp
from concurrent.futures import ThreadPoolExecutor
from loguru import logger

from core.distributed_scanner import WorkerNode, TacheScan


@dataclass
class WorkerDistant:
    """Représente un worker distant connecté"""
    id_worker: str
    adresse_ip: str
    port: int
    websocket: Optional[websockets.WebSocketServerProtocol] = None
    statut: str = "connecte"
    dernier_ping: float = field(default_factory=time.time)
    capacite_cpu: int = 4
    capacite_memoire: int = 8
    taches_actives: int = 0
    performances: Dict[str, float] = field(default_factory=dict)
    specialites: List[str] = field(default_factory=list)


class ServeurCoordination:
    """
    Serveur de coordination pour les workers distants
    """

    def __init__(self, host: str = '0.0.0.0', port: int = 8765):
        self.host = host
        self.port = port
        self.workers_distants: Dict[str, WorkerDistant] = {}
        self.queue_taches = asyncio.Queue()
        self.websocket_server = None
        self.executor = ThreadPoolExecutor(max_workers=10)

        logger.info(f"🎼 Serveur de coordination initialisé sur {host}:{port}")

    async def demarrer_serveur(self):
        """Démarre le serveur WebSocket de coordination"""
        try:
            self.websocket_server = await websockets.serve(
                self.gerer_connexion_worker,
                self.host,
                self.port,
                ping_interval=30,
                ping_timeout=10
            )
            logger.success(f"✅ Serveur de coordination démarré sur ws://{self.host}:{self.port}")

            # Démarrer les tâches de fond
            asyncio.create_task(self.monitorer_workers())
            asyncio.create_task(self.distribuer_taches())

        except Exception as e:
            logger.error(f"❌ Erreur démarrage serveur: {str(e)}")
            raise

    async def gerer_connexion_worker(self, websocket: websockets.WebSocketServerProtocol, path: str):
        """Gère une connexion de worker distant"""
        try:
            # Recevoir l'identification du worker
            message = await websocket.recv()
            data = json.loads(message)

            if data.get('type') == 'enregistrement_worker':
                worker_info = data.get('worker', {})

                worker = WorkerDistant(
                    id_worker=worker_info.get('id', f"remote_{len(self.workers_distants)}"),
                    adresse_ip=websocket.remote_address[0],
                    port=websocket.remote_address[1],
                    websocket=websocket,
                    capacite_cpu=worker_info.get('cpu_cores', 4),
                    capacite_memoire=worker_info.get('memory_gb', 8),
                    specialites=worker_info.get('specialites', [])
                )

                self.workers_distants[worker.id_worker] = worker
                logger.info(f"🔗 Worker distant connecté: {worker.id_worker} ({worker.adresse_ip})")

                # Confirmer l'enregistrement
                await websocket.send(json.dumps({
                    'type': 'enregistrement_confirme',
                    'worker_id': worker.id_worker
                }))

                # Maintenir la connexion
                await self.maintenir_connexion_worker(worker)

        except Exception as e:
            logger.error(f"❌ Erreur gestion connexion worker: {str(e)}")

    async def maintenir_connexion_worker(self, worker: WorkerDistant):
        """Maintient la connexion avec un worker distant"""
        try:
            while worker.websocket and not worker.websocket.closed:
                try:
                    # Attendre les messages du worker
                    message = await asyncio.wait_for(
                        worker.websocket.recv(),
                        timeout=60
                    )

                    data = json.loads(message)

                    if data.get('type') == 'pong':
                        worker.dernier_ping = time.time()

                    elif data.get('type') == 'tache_terminee':
                        await self.gerer_tache_terminee(worker, data)

                    elif data.get('type') == 'statut_update':
                        self.mettre_a_jour_statut_worker(worker, data)

                    elif data.get('type') == 'performance_update':
                        worker.performances.update(data.get('performances', {}))

                except asyncio.TimeoutError:
                    # Ping timeout - vérifier si worker toujours vivant
                    if time.time() - worker.dernier_ping > 120:  # 2 minutes
                        logger.warning(f"⏰ Worker {worker.id_worker} ping timeout")
                        break

                except websockets.exceptions.ConnectionClosed:
                    logger.info(f"🔌 Worker {worker.id_worker} déconnecté")
                    break

        except Exception as e:
            logger.error(f"❌ Erreur maintien connexion {worker.id_worker}: {str(e)}")

        finally:
            # Nettoyer la connexion
            if worker.id_worker in self.workers_distants:
                worker.statut = "deconnecte"
                worker.websocket = None

    async def gerer_tache_terminee(self, worker: WorkerDistant, data: Dict):
        """Gère la fin d'une tâche par un worker distant"""
        worker.taches_actives = max(0, worker.taches_actives - 1)

        resultat = data.get('resultat', {})
        temps_execution = data.get('temps_execution', 0)

        logger.info(f"✅ Tâche terminée par {worker.id_worker}: {resultat.get('url', 'unknown')} en {temps_execution:.2f}s")

        # Mettre à jour les performances du worker
        if temps_execution > 0:
            performance = 1.0 / (1.0 + temps_execution)  # Score basé sur vitesse
            worker.performances['dernier_score'] = performance

    def mettre_a_jour_statut_worker(self, worker: WorkerDistant, data: Dict):
        """Met à jour le statut d'un worker distant"""
        nouveau_statut = data.get('statut')
        if nouveau_statut:
            worker.statut = nouveau_statut
            worker.dernier_ping = time.time()

        worker.taches_actives = data.get('taches_actives', worker.taches_actives)

    async def envoyer_tache_worker(self, worker: WorkerDistant, tache: TacheScan) -> bool:
        """Envoie une tâche à un worker distant"""
        if not worker.websocket or worker.websocket.closed:
            return False

        try:
            # Convertir la tâche en format JSON
            data_tache = {
                'type': 'nouvelle_tache',
                'tache': {
                    'id': tache.id_tache,
                    'url': tache.url,
                    'type_scan': tache.type_scan,
                    'priorite': tache.priorite,
                    'timeout': tache.timeout,
                    'contexte': tache.contexte
                }
            }

            await worker.websocket.send(json.dumps(data_tache))
            worker.taches_actives += 1
            tache.timestamp_debut = time.time()

            logger.debug(f"📤 Tâche {tache.id_tache} envoyée à {worker.id_worker}")
            return True

        except Exception as e:
            logger.error(f"❌ Erreur envoi tâche à {worker.id_worker}: {str(e)}")
            return False

    async def distribuer_taches(self):
        """Distribue les tâches en attente aux workers disponibles"""
        while True:
            try:
                # Attendre une tâche
                tache = await self.queue_taches.get()

                # Trouver un worker disponible
                worker_disponible = None
                for worker in self.workers_distants.values():
                    if (worker.statut == "disponible" and
                        worker.websocket and not worker.websocket.closed and
                        worker.taches_actives < worker.capacite_cpu):
                        worker_disponible = worker
                        break

                if worker_disponible:
                    succes = await self.envoyer_tache_worker(worker_disponible, tache)
                    if succes:
                        self.queue_taches.task_done()
                    else:
                        # Remettre en queue si échec
                        await asyncio.sleep(1)
                        await self.queue_taches.put(tache)
                else:
                    # Aucun worker disponible, attendre
                    await asyncio.sleep(2)
                    await self.queue_taches.put(tache)

            except Exception as e:
                logger.error(f"❌ Erreur distribution tâche: {str(e)}")
                await asyncio.sleep(1)

    async def ajouter_tache(self, tache: TacheScan):
        """Ajoute une tâche à la queue de distribution"""
        await self.queue_taches.put(tache)
        logger.debug(f"📋 Tâche ajoutée à la queue: {tache.id_tache}")

    async def monitorer_workers(self):
        """Surveille l'état des workers distants"""
        while True:
            try:
                maintenant = time.time()

                # Vérifier les workers inactifs
                workers_a_supprimer = []
                for worker_id, worker in self.workers_distants.items():
                    if maintenant - worker.dernier_ping > 300:  # 5 minutes sans ping
                        workers_a_supprimer.append(worker_id)
                        logger.warning(f"💀 Worker inactif détecté: {worker_id}")

                # Supprimer les workers inactifs
                for worker_id in workers_a_supprimer:
                    if worker_id in self.workers_distants:
                        del self.workers_distants[worker_id]

                # Ping des workers actifs
                for worker in self.workers_distants.values():
                    if worker.websocket and not worker.websocket.closed:
                        try:
                            await worker.websocket.send(json.dumps({'type': 'ping'}))
                        except:
                            worker.statut = "deconnecte"

                await asyncio.sleep(60)  # Vérifier chaque minute

            except Exception as e:
                logger.error(f"❌ Erreur monitoring workers: {str(e)}")
                await asyncio.sleep(10)

    def obtenir_statistiques_workers(self) -> Dict[str, Any]:
        """Retourne les statistiques des workers distants"""
        return {
            'total_workers': len(self.workers_distants),
            'workers_actifs': sum(1 for w in self.workers_distants.values()
                                if w.statut == "disponible"),
            'workers_occupes': sum(1 for w in self.workers_distants.values()
                                 if w.statut == "occupe"),
            'workers_deconnectes': sum(1 for w in self.workers_distants.values()
                                     if w.statut == "deconnecte"),
            'taches_actives_total': sum(w.taches_actives for w in self.workers_distants.values()),
            'file_attente': self.queue_taches.qsize(),
            'details_workers': {
                wid: {
                    'statut': w.statut,
                    'ip': w.adresse_ip,
                    'cpu': w.capacite_cpu,
                    'memoire': w.capacite_memoire,
                    'taches_actives': w.taches_actives,
                    'performances': w.performances,
                    'specialites': w.specialites
                }
                for wid, w in self.workers_distants.items()
            }
        }

    async def arreter_serveur(self):
        """Arrête proprement le serveur de coordination"""
        logger.info("🛑 Arrêt du serveur de coordination...")

        # Fermer toutes les connexions WebSocket
        for worker in self.workers_distants.values():
            if worker.websocket and not worker.websocket.closed:
                await worker.websocket.close()

        if self.websocket_server:
            self.websocket_server.close()
            await self.websocket_server.wait_closed()

        self.executor.shutdown(wait=True)
        logger.info("✅ Serveur de coordination arrêté")


class ClientWorkerDistant:
    """
    Client pour connecter un worker distant au serveur de coordination
    """

    def __init__(self, serveur_host: str, serveur_port: int, worker_info: Dict[str, Any]):
        self.serveur_host = serveur_host
        self.serveur_port = serveur_port
        self.worker_info = worker_info
        self.websocket = None
        self.statut = "deconnecte"
        self.taches_actives = 0

        # Callback pour traiter les tâches
        self.callback_traitement_tache: Optional[Callable] = None

        logger.info(f"🤖 Client worker initialisé pour {serveur_host}:{serveur_port}")

    async def connecter_au_serveur(self) -> bool:
        """Se connecte au serveur de coordination"""
        try:
            uri = f"ws://{self.serveur_host}:{self.serveur_port}"
            self.websocket = await websockets.connect(uri)

            # S'enregistrer auprès du serveur
            enregistrement = {
                'type': 'enregistrement_worker',
                'worker': self.worker_info
            }

            await self.websocket.send(json.dumps(enregistrement))

            # Attendre la confirmation
            response = await self.websocket.recv()
            data = json.loads(response)

            if data.get('type') == 'enregistrement_confirme':
                self.statut = "connecte"
                logger.success(f"✅ Worker connecté au serveur: {data.get('worker_id')}")

                # Démarrer le traitement des messages
                asyncio.create_task(self.gerer_messages_serveur())

                return True
            else:
                logger.error("❌ Enregistrement rejeté par le serveur")
                return False

        except Exception as e:
            logger.error(f"❌ Erreur connexion serveur: {str(e)}")
            return False

    async def gerer_messages_serveur(self):
        """Gère les messages reçus du serveur"""
        try:
            while self.websocket and not self.websocket.closed:
                message = await self.websocket.recv()
                data = json.loads(message)

                if data.get('type') == 'ping':
                    # Répondre au ping
                    await self.websocket.send(json.dumps({'type': 'pong'}))

                elif data.get('type') == 'nouvelle_tache':
                    # Traiter la nouvelle tâche
                    await self.traiter_tache_recue(data.get('tache', {}))

        except websockets.exceptions.ConnectionClosed:
            logger.info("🔌 Connexion serveur fermée")
            self.statut = "deconnecte"
        except Exception as e:
            logger.error(f"❌ Erreur gestion messages serveur: {str(e)}")
            self.statut = "deconnecte"

    async def traiter_tache_recue(self, data_tache: Dict):
        """Traite une tâche reçue du serveur"""
        try:
            self.taches_actives += 1

            tache = TacheScan(
                id_tache=data_tache.get('id'),
                url=data_tache.get('url'),
                type_scan=data_tache.get('type_scan'),
                priorite=data_tache.get('priorite', 1),
                timeout=data_tache.get('timeout', 30),
                contexte=data_tache.get('contexte', {})
            )

            logger.info(f"🎯 Traitement tâche: {tache.id_tache} - {tache.url}")

            # Traiter la tâche avec le callback
            if self.callback_traitement_tache:
                debut = time.time()
                resultat = await self.callback_traitement_tache(tache)
                temps_execution = time.time() - debut

                # Envoyer le résultat au serveur
                await self.envoyer_resultat_tache(tache.id_tache, resultat, temps_execution)

            else:
                # Callback non défini, simuler un traitement
                await asyncio.sleep(1)
                await self.envoyer_resultat_tache(tache.id_tache, {'succes': True}, 1.0)

        except Exception as e:
            logger.error(f"❌ Erreur traitement tâche {data_tache.get('id')}: {str(e)}")
            await self.envoyer_resultat_tache(data_tache.get('id'), {'erreur': str(e)}, 0)
        finally:
            self.taches_actives = max(0, self.taches_actives - 1)

    async def envoyer_resultat_tache(self, tache_id: str, resultat: Dict, temps_execution: float):
        """Envoie le résultat d'une tâche au serveur"""
        if not self.websocket or self.websocket.closed:
            return

        try:
            message = {
                'type': 'tache_terminee',
                'tache_id': tache_id,
                'resultat': resultat,
                'temps_execution': temps_execution
            }

            await self.websocket.send(json.dumps(message))
            logger.debug(f"📤 Résultat envoyé pour tâche {tache_id}")

        except Exception as e:
            logger.error(f"❌ Erreur envoi résultat tâche {tache_id}: {str(e)}")

    def definir_callback_traitement(self, callback: Callable):
        """Définit le callback pour traiter les tâches"""
        self.callback_traitement_tache = callback

    async def envoyer_statut_update(self):
        """Envoie une mise à jour du statut au serveur"""
        if not self.websocket or self.websocket.closed:
            return

        try:
            message = {
                'type': 'statut_update',
                'statut': self.statut,
                'taches_actives': self.taches_actives
            }

            await self.websocket.send(json.dumps(message))

        except Exception as e:
            logger.debug(f"Erreur envoi statut: {str(e)}")

    async def deconnecter(self):
        """Se déconnecte proprement du serveur"""
        self.statut = "deconnecte"

        if self.websocket and not self.websocket.closed:
            await self.websocket.close()

        logger.info("🔌 Worker déconnecté du serveur")


async def creer_worker_distant(serveur_host: str, serveur_port: int,
                              worker_id: str, specialites: List[str] = None) -> ClientWorkerDistant:
    """
    Fonction utilitaire pour créer et connecter un worker distant
    """
    import psutil

    # Informations système du worker
    worker_info = {
        'id': worker_id,
        'cpu_cores': psutil.cpu_count(),
        'memory_gb': int(psutil.virtual_memory().total / (1024**3)),
        'hostname': socket.gethostname(),
        'platform': 'linux',  # À adapter selon le système
        'specialites': specialites or ['general_scan']
    }

    client = ClientWorkerDistant(serveur_host, serveur_port, worker_info)

    # Connecter au serveur
    if await client.connecter_au_serveur():
        return client
    else:
        raise Exception("Impossible de connecter le worker au serveur")
