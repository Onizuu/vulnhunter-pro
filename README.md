# 🚀 VulnHunter Pro

**Scanner de vulnérabilités web assisté par Intelligence Artificielle**

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-4.4-orange.svg)]()

---

## 🎯 **Vue d'ensemble**

VulnHunter Pro est un scanner de vulnérabilités web qui combine :

- 🤖 **Intelligence Artificielle** (GPT-4, Machine Learning)
- 🔗 **Analyse prédictive** de chaînes d'attaque
- 📊 **Reporting exécutif** professionnel
- ⚖️ **Conformité réglementaire** automatisée
- ⚡ **Architecture distribuée** haute performance

**13 phases implémentées** pour une couverture complète OWASP Top 10 + IA.

---

## 🏆 **Fonctionnalités Clés**

### 🤖 Intelligence Artificielle
- Génération de payloads avec GPT-4/Claude
- Classification ML des vulnérabilités
- Prédiction de menaces comportementales
- Scoring intelligent des risques

### 🔗 Analyse Prédictive
- Chaînes d'attaque automatiques (NetworkX)
- Escalade de privilèges cartographiée
- Mouvement latéral analysé
- Impact business quantifié (€)

### 📊 Reporting Enterprise
- Dashboards Plotly interactifs
- Time-series analysis prédictive
- Rapports spécialisés (Exécutif/Technique/Conformité)
- Exports multi-formats (JSON/HTML/PDF)

### ⚖️ Conformité Réglementaire
- OWASP Risk Rating & CVSS v4
- PCI-DSS, GDPR, HIPAA intégrés
- Benchmarks sectoriels
- Audits automatisés

### ⚡ Performance
- Architecture distribuée multi-threading
- Workers parallèles pour scaling
- Cache intelligent et rate limiting
- Interface React temps réel

---

## 📋 **Installation**

### Prérequis
- **Python 3.9+** ([Téléchargement](https://python.org))
- **Système** : Linux/macOS/Windows

### Installation Automatique (Recommandé)
```bash
# Cloner le dépôt
git clone <repository-url>
cd vulnhunter

# Installation complète
./install.sh
```

### Installation Manuelle
```bash
# Créer l'environnement virtuel
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate    # Windows

# Installer les dépendances
pip install -r requirements.txt
```

---

## 🚀 **Démarrage**

### Démarrage Rapide
```bash
# Démarrer l'application complète
./start.sh
```

### Accès aux Interfaces
- 🌐 **Interface Web** : http://localhost:5000
- 📊 **Dashboard** : http://localhost:5000/dashboard
- 🔗 **API REST** : http://localhost:5000/api

### Démos Disponibles
```bash
# Démo chaînes d'attaque
./run_attack_chains.sh

# Démo reporting exécutif
./run_executive_reporting.sh

# Tests unitaires
python3 test_attack_chains_simple.py
python3 test_executive_reporting.py
```

---

## ⚙️ **Configuration**

### Variables d'Environnement (.env)
```bash
# Clés API IA (optionnel)
OPENAI_API_KEY=sk-your-openai-key-here
ANTHROPIC_API_KEY=sk-ant-your-anthropic-key-here

# Base de données (optionnel)
DATABASE_URL=postgresql://user:pass@localhost/vulnhunter

# Notifications (optionnel)
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
TELEGRAM_BOT_TOKEN=your-bot-token

# Configuration
LOG_LEVEL=INFO
MAX_CONCURRENT_SCANS=5
```

### Outils Système Optionnels
```bash
# Pour performances optimales
brew install nmap          # macOS
sudo apt install nmap      # Ubuntu

# Outils avancés (optionnel)
# masscan, subfinder, rustscan
```

---

## 🎯 **Utilisation**

### Scan Basique
```python
from core.scanner_engine import MoteurScanIntelligent

scanner = MoteurScanIntelligent()
resultats = await scanner.executer_scan_complet("https://example.com")
```

### Analyse de Chaînes d'Attaque
```python
from core.attack_chains import OrchestrateurChainesAttaque

analyseur = OrchestrateurChainesAttaque()
rapports = await analyseur.analyser_chaine_complete(vulnerabilites)
```

### Génération de Rapports
```python
from core.executive_reporting import OrchestrateurReporting

reporting = OrchestrateurReporting()
rapports = await reporting.generer_reporting_complet(vulnerabilites)
```

---

## 📊 **API REST**

### Endpoints Principaux
```
GET  /api/health          # État du service
POST /api/scan/start      # Démarrer un scan
GET  /api/scan/status/:id # Statut du scan
GET  /api/scan/results/:id # Résultats du scan
GET  /api/reports         # Liste des rapports
POST /api/reports/generate # Générer un rapport
```

### Exemple d'Utilisation
```bash
# Démarrer un scan
curl -X POST http://localhost:5000/api/scan/start \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com", "intensity": "normal"}'

# Obtenir les résultats
curl http://localhost:5000/api/scan/results/scan_123
```

---

## 🧪 **Tests**

### Tests Unitaires
```bash
# Tests des chaînes d'attaque
python3 test_attack_chains_simple.py

# Tests du reporting
python3 test_executive_reporting.py

# Tests de reconnaissance
python3 test_tech_detection.py
python3 test_subdomain_enum.py
python3 test_port_scanner.py
```

### Tests d'Intégration
```bash
# Test complet avec données réelles
python3 test_integration_complete.py
```

---

## 📚 **Documentation**

### Guides Disponibles
- `README.md` - Ce fichier
- `CHANGELOG.md` - Historique des versions

### Architecture
```
vulnhunter/
├── core/                    # Noyau du système
│   ├── models.py           # Modèles de données
│   ├── scanner_engine.py   # Moteur de scan principal
│   ├── attack_chains.py    # Analyse de chaînes d'attaque
│   └── executive_reporting.py # Reporting avancé
├── modules/                # Modules spécialisés
│   ├── reconnaissance/     # Reconnaissance passive/active
│   ├── vulnerabilites/     # Détecteurs de vulnérabilités
│   └── intelligence/       # IA et ML
├── interface_web/          # Interface utilisateur
│   ├── static/            # Assets frontend
│   └── templates/         # Templates HTML
├── rapports/              # Système de reporting
├── utilitaires/           # Outils utilitaires
└── tests/                 # Tests unitaires
```

---

## 🔧 **Développement**

### Structure du Code
- **Modulaire** : Chaque fonctionnalité dans son module
- **Asynchrone** : Utilisation d'asyncio pour performance
- **Typé** : Annotations de type complètes
- **Testé** : Tests unitaires et d'intégration

### Contribution
```bash
# Installation en mode développement
pip install -e .
pip install -r requirements-dev.txt

# Linting et formatage
black . --line-length 100
flake8 . --max-line-length 100
mypy .
```

---

## 🏆 **Performances**

### Capacités
- **Rapidité** : Exécution asynchrone via asyncio permettant de traiter plusieurs requêtes simultanément pour optimiser le temps de scan.
- **Précision** : Analyse basée sur des signatures de vulnérabilités connues et validation par comparaison de patterns HTTP pour limiter les erreurs d'interprétation.
- **Modularité** : Architecture découplée facilitant l'intégration de nouveaux vecteurs de test sans modifier le noyau du système.
- **Robustesse** : Gestion native des timeouts et des erreurs de connexion pour garantir la continuité des scans sur des cibles instables.

### Optimisations
- Cache Redis pour résultats
- Pool de connexions aiohttp
- Rate limiting intelligent
- Compression des réponses

---

## ⚖️ **Conformité & Sécurité**

### Réglementations Supportées
- ✅ **OWASP Top 10** (complet)
- ✅ **CVSS v4** (scoring avancé)
- ✅ **PCI-DSS** (commerce électronique)
- ✅ **GDPR** (protection données)
- ✅ **HIPAA** (santé)

### Sécurité
- **Chiffrement** des données sensibles
- **Audit logging** complet
- **Rate limiting** anti-abus
- **Validation** stricte des entrées

---

## 🌟 **Roadmap**

### Améliorations Prévue
- 🤖 **Deep Learning** (BERT, GANs)
- 📱 **Interface Mobile** React Native
- 🔗 **Blockchain** pour traçabilité
- 🥽 **AR/VR Reports** immersifs
- ☁️ **Edge Computing** pour IoT
- 🤝 **SIEM Integration** native

---

## 📄 **Licence**

**MIT License** - Voir [LICENSE](LICENSE) pour plus de détails.

Libre utilisation pour projets personnels et commerciaux.

---

---

*Créé avec ❤️ par l'équipe VulnHunter Pro*

**🌟 Version 4.4 - L'ultime scanner de cybersécurité ! 🌟**
