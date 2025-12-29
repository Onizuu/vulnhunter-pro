"""
VulnHunter Pro - Point d'entrée principal
Scanner de vulnérabilités web professionnel avec IA
"""

import os
import asyncio
import uuid
import threading
from pathlib import Path
from datetime import datetime
from dotenv import load_dotenv
from flask import Flask, request, jsonify, render_template, send_from_directory
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from loguru import logger

from core.scanner_engine import MoteurScanIntelligent
from core.models import RapportScan
from rapports.report_generator import GenerateurRapports
from core.html_generator import HTMLGenerator
from utilitaires.logger import ConfigurerLogger
from utilitaires.notifications import GestionnaireNotifications

# Charger les variables d'environnement
load_dotenv()


def _parse_bool(value, default=True):
    """
    Convertit une valeur en booléen (accepte bool, str, int).
    """
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    value_str = str(value).strip().lower()
    if value_str in {'1', 'true', 'yes', 'on'}:
        return True
    if value_str in {'0', 'false', 'no', 'off'}:
        return False
    return default


# Configurer le logger
ConfigurerLogger(
    niveau=os.getenv('NIVEAU_LOG', 'INFO'),
    fichier_log=os.getenv('LOG_FILE', 'logs/vulnhunter.log')
)

# Créer l'application Flask avec les bons chemins
app = Flask(__name__, 
            template_folder='interface_web/templates',
            static_folder='interface_web/static')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'vulnhunter-secret-key-change-in-production')
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Gestionnaire de notifications
notificateur = GestionnaireNotifications()

# Générateur de rapports
generateur_rapports = GenerateurRapports()

# Stocker les scans en cours
scans_en_cours = {}
moteurs_en_cours = {}  # ⭐ NOUVEAU: Pour accéder aux méthodes pause/resume
scan_errors = {}  # ⭐ NOUVEAU: Stocker les erreurs par scan
current_scan_id = None  # ⭐ NOUVEAU: ID du scan en cours pour collecter les erreurs

# ⭐ NOUVEAU: Sink pour les logs WebSocket
def socketio_sink(message):
    global current_scan_id
    try:
        record = message.record
        log_entry = {
            'time': record["time"].strftime("%H:%M:%S"),
            'level': record["level"].name,
            'message': record["message"],
            'module': record["name"]
        }
        socketio.emit('log_message', log_entry)
        
        # ⭐ NOUVEAU: Collecter les erreurs pour le scan en cours
        if record["level"].name == "ERROR" and current_scan_id:
            if current_scan_id not in scan_errors:
                scan_errors[current_scan_id] = []
            scan_errors[current_scan_id].append(
                f"{record['time'].strftime('%Y-%m-%d %H:%M:%S')} | {record['name']} | {record['message']}"
            )
    except Exception:
        pass

# Reconfigurer le logger avec le sink WebSocket
ConfigurerLogger(
    niveau=os.getenv('NIVEAU_LOG', 'INFO'),
    fichier_log=os.getenv('LOG_FILE', 'logs/vulnhunter.log'),
    sink=socketio_sink
)


@app.route('/')
@app.route('/dashboard')
def index():
    """
    Page d'accueil - Dashboard principal
    """
    return render_template('dashboard.html')


@app.route('/api/scan/start', methods=['POST'])
def demarrer_scan():
    """
    Démarre un nouveau scan
    
    Body JSON:
    {
        "url": "http://example.com",
        "intensite": "aggressive",
        "modules": ["sql", "xss", "rce"]
    }
    """
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({
                'status': 'error',
                'message': 'URL manquante'
            }), 400
        
        url_cible = data['url']
        intensite = data.get('intensite', 'normal')
        modules_cibles = data.get('modules', [])  # ⭐ NOUVEAU: Modules ciblés (ex: ['sql', 'xss'])
        scan_type = data.get('scan_type', 'full')  # ⭐ NOUVEAU: 'full' ou 'specific_url'
        auth_config = data.get('auth', {})  # ⭐ NOUVEAU: {cookies: {}, headers: {}}
        
        # Gestion de l'IA (priorité au payload JSON, sinon variable d'environnement)
        ia_active_env = _parse_bool(os.getenv('IA_ACTIVE', 'false'), default=False)
        ia_active_payload = data.get('ia_active')
        ia_active = _parse_bool(ia_active_payload, default=ia_active_env)
        
        # Configuration du scan
        config = {
            'modules_cibles': modules_cibles,  # ⭐ NOUVEAU: Modules à scanner
            'scan_type': scan_type,  # ⭐ NOUVEAU: Type de scan
            'auth': auth_config,  # ⭐ NOUVEAU: Authentification
            'ia_active': ia_active,
            # Anciennes clés API (compatibilité)
            'mistral_api_key': os.getenv('MISTRAL_API_KEY'),
            'openai_api_key': os.getenv('OPENAI_API_KEY'),
            # ⭐ NOUVEAU: Système Ollama + Claude fallback
            'ollama_model': os.getenv('OLLAMA_MODEL', 'mistral:7b'),
            'anthropic_api_key': os.getenv('ANTHROPIC_API_KEY'),  # Claude (optionnel)
            'claude_budget_max': float(os.getenv('CLAUDE_BUDGET_MAX', '5.0')),  # 5€ max par scan
            'intensite': intensite,
            'threads': int(os.getenv('NOMBRE_THREADS', 10)),
            'timeout': int(os.getenv('TIMEOUT_REQUETE', 30)),
            'max_urls': int(os.getenv('MAX_URLS_SCAN', 1000))
        }
        
        # Créer un ID unique pour le scan
        scan_id = str(uuid.uuid4())
        
        # Démarrer le scan en arrière-plan dans un thread
        thread = threading.Thread(
            target=lambda: asyncio.run(executer_scan(scan_id, url_cible, config))
        )
        thread.daemon = True
        thread.start()
        
        logger.info(f"🎯 Scan démarré: {scan_id} pour {url_cible}")
        
        return jsonify({
            'status': 'success',
            'message': 'Scan démarré avec succès',
            'scan_id': scan_id,
            'url_cible': url_cible
        }), 200
    
    except Exception as e:
        logger.error(f"Erreur démarrage scan: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


async def executer_scan(scan_id: str, url_cible: str, config: dict):
    """
    Exécute un scan en arrière-plan
    
    Args:
        scan_id: ID unique du scan
        url_cible: URL à scanner
        config: Configuration du scan
    """
    global current_scan_id
    try:
        # ⭐ NOUVEAU: Définir le scan actuel pour la collecte des erreurs
        current_scan_id = scan_id
        scan_errors[scan_id] = []  # Initialiser la liste d'erreurs
        
        # Émettre le statut de démarrage
        socketio.emit('scan_status', {
            'scan_id': scan_id,
            'status': 'started',
            'message': 'Scan démarré'
        })

        # ⭐ NOUVEAU: Callback pour les vulnérabilités en temps réel
        def vulnerability_callback(vuln):
            try:
                socketio.emit('vulnerability_found', {
                    'scan_id': scan_id,
                    'vulnerability': vuln.to_dict()
                })
            except Exception as e:
                logger.error(f"Erreur callback vulnérabilité: {str(e)}")

        # Ajouter le callback à la configuration
        config['callback_vulnerabilite'] = vulnerability_callback
        
        # Créer le moteur de scan
        moteur = MoteurScanIntelligent(config)
        moteurs_en_cours[scan_id] = moteur  # ⭐ NOUVEAU: Stocker l'instance du moteur
        
        # Exécuter le scan
        rapport = await moteur.scanner_complet(url_cible)
        
        # Sauvegarder le rapport
        scans_en_cours[scan_id] = rapport
        
        # Générer les rapports
        socketio.emit('scan_status', {
            'scan_id': scan_id,
            'status': 'generating_reports',
            'message': 'Génération des rapports'
        })
        
        chemin_html = generateur_rapports.generer_rapport_complet(
            rapport,
            format_sortie='html'
        )
        
        chemin_json = generateur_rapports.generer_rapport_complet(
            rapport,
            format_sortie='json'
        )
        
        chemin_executif = generateur_rapports.generer_resume_executif(rapport)
        
        # Notifier si vulnérabilités critiques
        vulns_critiques = [
            v for v in rapport.vulnerabilites 
            if v.severite == 'CRITIQUE'
        ]
        
        if vulns_critiques:
            for vuln in vulns_critiques[:5]:  # Limiter aux 5 premières
                await notificateur.notifier_vulnerabilite_critique(vuln)
        
        # Récupérer les statistiques de budget IA
        stats_budget = {}
        if hasattr(moteur.client_ia, 'get_statistiques_budget'):
            stats_budget = moteur.client_ia.get_statistiques_budget()
        
        # Sauvegarder le rapport
        scans_en_cours[scan_id] = rapport
        
        # ⭐ DÉSACTIVÉ: Génération du rapport exécutif HTML
        # Le template report_template.html est incompatible avec RapportExecutif
        # Les rapports techniques HTML, JSON et exécutif sont déjà générés ci-dessus
        """
        try:
            from core.html_generator import HTMLGenerator
            from core.executive_reporting import GenerateurRapports as GenerateurRapportExecutif
            gen_html = HTMLGenerator()
            
            # Créer l'objet rapport exécutif
            gen_rapports_exec = GenerateurRapportExecutif()
            rapport_exec = gen_rapports_exec.generer_rapport_executif(
                rapport.vulnerabilites,
                contexte={'url_cible': url_cible}
            )
            rapport_exec.id_rapport = scan_id
            
            # Générer le fichier HTML
            chemin_rapport_exec_html = gen_html.generer_rapport(rapport_exec)
            url_rapport_exec_html = f"/report/{scan_id}"
            
            logger.info(f"Rapport exécutif généré: {chemin_rapport_exec_html}")
            
        except Exception as e:
            logger.error(f"Erreur génération rapport exécutif HTML: {str(e)}")
            url_rapport_exec_html = None
            chemin_rapport_exec_html = None
        """
        url_rapport_exec_html = None
        chemin_rapport_exec_html = None

        # ⭐ NOUVEAU: Calculer les stats par sévérité (APRÈS déduplication)
        stats_severite = {'CRITIQUE': 0, 'ÉLEVÉ': 0, 'MOYEN': 0, 'FAIBLE': 0, 'INFO': 0}
        for vuln in rapport.vulnerabilites:
            if vuln.severite in stats_severite:
                stats_severite[vuln.severite] += 1
        
        # Émettre le statut de fin
        socketio.emit('scan_status', {
            'scan_id': scan_id,
            'status': 'completed',
            'message': 'Scan terminé',
            'rapport': {
                'scan_id': scan_id,
                'nb_vulnerabilites': len(rapport.vulnerabilites),
                'score_risque': rapport.score_risque_global,
                'chemin_html': chemin_html,
                'chemin_json': chemin_json,
                'chemin_executif': chemin_executif,
                'chemin_rapport_exec_html': chemin_rapport_exec_html, # NEW
                'url_rapport_exec_html': url_rapport_exec_html, # NEW
                'stats_budget_ia': stats_budget,  # ⭐ Statistiques de budget
                'stats_severite': stats_severite  # ⭐ NOUVEAU: Stats finales
            }
        })
        
        # ⭐ Stocker les chemins de rapports dans l'objet rapport pour l'API
        rapport.chemin_html = chemin_html
        rapport.chemin_json = chemin_json
        rapport.chemin_executif = chemin_executif
        
        logger.success(f"✅ Scan {scan_id} terminé avec succès")
        
        # Nettoyage
        if scan_id in moteurs_en_cours:
            del moteurs_en_cours[scan_id]
    
    except Exception as e:
        logger.error(f"Erreur lors du scan {scan_id}: {str(e)}")
        
        socketio.emit('scan_status', {
            'scan_id': scan_id,
            'status': 'error',
            'message': str(e)
        })


@app.route('/api/scan/status/<scan_id>', methods=['GET'])
def statut_scan(scan_id):
    """
    Récupère le statut d'un scan
    """
    if scan_id in scans_en_cours:
        rapport = scans_en_cours[scan_id]
        
        return jsonify({
            'status': 'success',
            'scan': {
                'url_cible': rapport.url_cible,
                'nb_vulnerabilites': len(rapport.vulnerabilites),
                'score_risque': rapport.score_risque_global,
                'date_debut': rapport.date_debut.isoformat(),
                'date_fin': rapport.date_fin.isoformat(),
                'duree': rapport.duree
            }
        }), 200
    else:
        return jsonify({
            'status': 'error',
            'message': 'Scan non trouvé'
        }), 404


@app.route('/api/scan/results/<scan_id>', methods=['GET'])
def resultats_scan(scan_id):
    """
    Récupère les résultats détaillés d'un scan
    """
    if scan_id in scans_en_cours:
        rapport = scans_en_cours[scan_id]
        
        # Convertir en dict
        vulnerabilites = []
        for vuln in rapport.vulnerabilites:
            vulnerabilites.append({
                'type': vuln.type,
                'severite': vuln.severite,
                'url': vuln.url,
                'description': vuln.description,
                'payload': vuln.payload,
                'cvss_score': vuln.cvss_score,
                'remediation': vuln.remediation
            })
        
        
        # Convertir les chemins absolus en URLs de téléchargement
        import os
        rapports_download = {}
        if hasattr(rapport, 'chemin_html') and rapport.chemin_html:
            rapports_download['html'] = f"/rapports/output/{os.path.basename(rapport.chemin_html)}"
        if hasattr(rapport, 'chemin_json') and rapport.chemin_json:
            rapports_download['json'] = f"/rapports/output/{os.path.basename(rapport.chemin_json)}"
        if hasattr(rapport, 'chemin_executif') and rapport.chemin_executif:
            rapports_download['executif'] = f"/rapports/output/{os.path.basename(rapport.chemin_executif)}"
        
        return jsonify({
            'status': 'success',
            'rapport': {
                'url_cible': rapport.url_cible,
                'score_risque': rapport.score_risque_global,
                'vulnerabilites': vulnerabilites,
                'chaines_exploit': rapport.chaines_exploit,
                'statistiques': rapport.statistiques,
                'nb_vulnerabilites': len(vulnerabilites),
                'rapports': rapports_download
            }
        }), 200
    else:
        return jsonify({
            'status': 'error',
            'message': 'Scan non trouvé'
        }), 404


@app.route('/api/scan/pause/<scan_id>', methods=['POST'])
def pauser_scan(scan_id):
    """Met un scan en pause"""
    if scan_id in moteurs_en_cours:
        moteurs_en_cours[scan_id].pauser()
        return jsonify({'status': 'success', 'message': 'Scan mis en pause'}), 200
    return jsonify({'status': 'error', 'message': 'Scan non trouvé ou terminé'}), 404


@app.route('/api/scan/resume/<scan_id>', methods=['POST'])
def resume_scan(scan_id):
    """Reprend un scan en pause"""
    if scan_id in moteurs_en_cours:
        moteur = moteurs_en_cours[scan_id]
        moteur.reprendre()
        return jsonify({'status': 'success', 'message': 'Scan repris'})
    return jsonify({'status': 'error', 'message': 'Scan non trouvé'}), 404

@app.route('/report/<scan_id>')
def serve_report(scan_id):
    """Sert le rapport HTML généré"""
    try:
        filename = f"rapport_{scan_id}.html"
        return send_from_directory('rapports/output', filename)
    except Exception as e:
        return f"Rapport non trouvé: {str(e)}", 404


@app.route('/api/vulnerabilites/<scan_id>', methods=['GET'])
def vulnerabilites_scan(scan_id):
    """
    Récupère les vulnérabilités détaillées d'un scan pour l'affichage interactif
    Supporte les scan_id UUID (mémoire) et timestamp (fichiers)
    """
    # D'abord vérifier en mémoire (scan_id UUID)
    if scan_id in scans_en_cours:
        rapport = scans_en_cours[scan_id]
        vulnerabilites = rapport.vulnerabilites
        logger.info(f"Scan {scan_id} chargé depuis la mémoire")
    else:
        # Essayer de charger depuis les fichiers JSON
        from pathlib import Path
        import json
        import glob

        rapport_dir = Path("rapports/output")

        # Essayer d'abord le format UUID
        json_file = rapport_dir / f"rapport_{scan_id}.json"

        if not json_file.exists():
            # Si pas trouvé, chercher par pattern (pour les anciens scans)
            json_files = list(rapport_dir.glob("rapport_*.json"))
            json_file = None

            # Chercher un fichier récent qui pourrait correspondre
            for jf in sorted(json_files, key=lambda x: x.stat().st_mtime, reverse=True):
                # Essayer de lire le fichier et voir s'il correspond
                try:
                    with open(jf, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        # Pour l'instant, on prend le fichier le plus récent
                        # TODO: Améliorer la correspondance scan_id
                        json_file = jf
                        break
                except:
                    continue

        if json_file and json_file.exists():
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                # Convertir les données JSON en objets vulnerabilité
                vulnerabilites = []
                for vuln_data in data.get('vulnerabilites', []):
                    from core.models import Vulnerabilite
                    vuln = Vulnerabilite(
                        type=vuln_data['type'],
                        severite=vuln_data['severite'],
                        url=vuln_data['url'],
                        description=vuln_data['description'],
                        payload=vuln_data.get('payload', ''),
                        cvss_score=vuln_data.get('cvss_score'),
                        remediation=vuln_data.get('remediation', '')
                    )
                    vulnerabilites.append(vuln)

                logger.info(f"Scan chargé depuis {json_file.name}: {len(vulnerabilites)} vulnérabilités")

            except Exception as e:
                logger.error(f"Erreur chargement rapport JSON {scan_id}: {e}")
                return jsonify({
                    'success': False,
                    'message': f'Erreur chargement rapport: {str(e)}'
                }), 500
        else:
            # Chercher tous les fichiers JSON disponibles
            json_files = list(rapport_dir.glob("rapport_*.json"))
            if json_files:
                logger.warning(f"Scan {scan_id} non trouvé. Fichiers disponibles: {[f.name for f in json_files]}")
                # Prendre le plus récent comme fallback
                json_file = sorted(json_files, key=lambda x: x.stat().st_mtime, reverse=True)[0]
                logger.warning(f"Utilisation du rapport le plus récent: {json_file.name}")

                try:
                    with open(json_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)

                    vulnerabilites = []
                    for vuln_data in data.get('vulnerabilites', []):
                        from core.models import Vulnerabilite
                        vuln = Vulnerabilite(
                            type=vuln_data['type'],
                            severite=vuln_data['severite'],
                            url=vuln_data['url'],
                            description=vuln_data['description'],
                            payload=vuln_data.get('payload', ''),
                            cvss_score=vuln_data.get('cvss_score'),
                            remediation=vuln_data.get('remediation', '')
                        )
                        vulnerabilites.append(vuln)

                    logger.info(f"Fallback: {len(vulnerabilites)} vulnérabilités chargées depuis {json_file.name}")

                except Exception as e:
                    logger.error(f"Erreur fallback chargement: {e}")
                    return jsonify({
                        'success': False,
                        'message': 'Scan non trouvé et erreur de chargement fallback'
                    }), 500
            else:
                return jsonify({
                    'success': False,
                    'message': 'Aucun scan trouvé en mémoire ni dans les fichiers'
                }), 404

    # Convertir les vulnérabilités en dict pour JSON
    vulnerabilites_dict = []
    for vuln in vulnerabilites:
        vulnerabilites_dict.append({
            'type': vuln.type,
            'severite': vuln.severite,
            'url': vuln.url,
            'description': vuln.description,
            'payload': vuln.payload,
            'cvss_score': vuln.cvss_score,
            'remediation': vuln.remediation
        })

    logger.info(f"Retour de {len(vulnerabilites_dict)} vulnérabilités pour scan {scan_id}")
    return jsonify({
        'success': True,
        'vulnerabilites': vulnerabilites_dict,
        'total': len(vulnerabilites_dict)
    }), 200


@app.route('/api/health', methods=['GET'])
def health_check():
    """
    Vérification de santé de l'API
    """
    return jsonify({
        'status': 'ok',
        'version': '1.0.0',
        'service': 'VulnHunter Pro'
    }), 200


@app.route('/rapports/output/<path:filename>')
def servir_rapport(filename):
    """
    Sert les fichiers de rapport générés
    """
    rapports_dir = os.path.join(os.path.dirname(__file__), 'rapports', 'output')
    return send_from_directory(rapports_dir, filename)


@socketio.on('connect')
def handle_connect():
    """
    Gestion de la connexion WebSocket
    """
    logger.info("Client WebSocket connecté")
    emit('connected', {'message': 'Connecté à VulnHunter Pro'})


@socketio.on('disconnect')
def handle_disconnect():
    """
    Gestion de la déconnexion WebSocket
    """
    logger.info("Client WebSocket déconnecté")


@app.route('/api/logs/download', methods=['GET'])
@app.route('/api/logs/<scan_id>/download', methods=['GET'])
def download_logs(scan_id=None):
    """
    Télécharge les erreurs collectées pendant un scan
    """
    from flask import Response
    try:
        # Si un scan_id est fourni, servir les erreurs de ce scan
        if scan_id and scan_id in scan_errors:
            errors = scan_errors[scan_id]
            if errors:
                content = f"=== ERREURS DU SCAN {scan_id} ===\n\n"
                content += "\n".join(errors)
                return Response(
                    content,
                    mimetype='text/plain',
                    headers={'Content-Disposition': f'attachment; filename=errors_{scan_id[:8]}.txt'}
                )
            else:
                return Response(
                    f"Aucune erreur collectée pour le scan {scan_id}",
                    mimetype='text/plain',
                    headers={'Content-Disposition': 'attachment; filename=no_errors.txt'}
                )
        
        # Fallback: servir toutes les erreurs récentes
        all_errors = []
        for sid, errs in scan_errors.items():
            all_errors.extend([f"[{sid[:8]}] {e}" for e in errs])
        
        if all_errors:
            content = "=== TOUTES LES ERREURS RÉCENTES ===\n\n" + "\n".join(all_errors)
        else:
            content = "Aucune erreur collectée."
        
        return Response(
            content,
            mimetype='text/plain',
            headers={'Content-Disposition': 'attachment; filename=all_errors.txt'}
        )
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


def main():
    """
    Point d'entrée principal
    """
    # Créer les dossiers nécessaires
    Path("logs").mkdir(exist_ok=True)
    Path("rapports/output").mkdir(parents=True, exist_ok=True)
    
    logger.info("🚀 Démarrage de VulnHunter Pro...")
    
    # Vérifier la configuration IA
    ollama_model = os.getenv('OLLAMA_MODEL', 'mistral:7b')
    claude_key = os.getenv('ANTHROPIC_API_KEY')
    budget_max = float(os.getenv('CLAUDE_BUDGET_MAX', '5.0'))
    
    logger.info(f"🤖 Configuration IA:")
    logger.info(f"   - Ollama: {ollama_model} (principal, gratuit)")
    if claude_key:
        logger.info(f"   - Claude: Configuré (fallback, budget: {budget_max}€ max)")
    else:
        logger.info(f"   - Claude: Non configuré (fallback désactivé)")
    
    # Vérifier si Ollama est disponible
    try:
        import requests
        response = requests.get("http://localhost:11434/api/tags", timeout=2)
        if response.status_code == 200:
            logger.info("✅ Ollama détecté et accessible")
        else:
            logger.warning("⚠️  Ollama non accessible - Installez: brew install ollama && ollama pull mistral:7b")
    except:
        logger.warning("⚠️  Ollama non détecté - Installez: brew install ollama && ollama pull mistral:7b")
    
    # Configuration Flask
    host = os.getenv('FLASK_HOST', '0.0.0.0')
    port = int(os.getenv('FLASK_PORT', 5000))
    debug = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
    
    logger.info(f"🌐 API Flask disponible sur http://{host}:{port}")
    logger.info(f"📡 WebSocket disponible sur ws://{host}:{port}/socket.io")
    
    # Démarrer le serveur
    socketio.run(
        app,
        host=host,
        port=port,
        debug=debug,
        allow_unsafe_werkzeug=True
    )


if __name__ == '__main__':
    main()

