# Manuel Utilisateur - VulnHunter Pro v4.4

## 1. Installation

```bash
# Cloner le projet
git clone https://github.com/[username]/vulnhunter-pro.git
cd vulnhunter-pro

# Créer un environnement virtuel
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# ou: venv\Scripts\activate  # Windows

# Installer les dépendances
pip install -r requirements.txt
```

---

## 2. Configuration (Optionnel)

Créer un fichier `.env` pour les clés API :

```env
# Intelligence Artificielle (optionnel)
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...

# NIST CVE Database (optionnel)
NIST_API_KEY=...

# GitHub Reconnaissance (optionnel)
GITHUB_TOKEN=ghp_...
```

> ⚠️ Sans clés API, le scanner fonctionne mais sans les fonctionnalités IA.

---

## 3. Lancement

```bash
./start.sh
```

Ouvrir le navigateur à : **http://localhost:5000**

---

## 4. Utilisation du Dashboard

### Étape 1 : Configuration du scan

1. Entrer l'**URL cible** (ex: `http://testphp.vulnweb.com`)
2. Cocher les options souhaitées :
   - ☑️ **API Fuzzing** : Test des endpoints API
   - ☐ **Authentification** : Pour sites avec login
   - ☐ **Mode Agressif** : Plus de payloads (plus lent)
3. (Optionnel) Entrer les clés API dans la section dédiée

### Étape 2 : Lancer le scan

- Cliquer sur **🚀 Démarrer le Scan**
- Observer la barre de progression et les logs en temps réel

### Étape 3 : Résultats

Une fois le scan terminé :
- Consulter le résumé (Critiques, Élevées, Moyennes, Faibles)
- Télécharger le **Rapport HTML** (rapport complet)
- Télécharger le **JSON** (données brutes)
- Télécharger les **Logs d'erreurs** (debugging)

---

## 5. Phases du Scan

| Phase | Description | Durée estimée |
|-------|-------------|---------------|
| 1. Reconnaissance | Découverte de sous-domaines, technologies, répertoires | 30s - 2min |
| 2. Détection | Test de toutes les vulnérabilités (SQL, XSS, SSRF...) | 5 - 20min |
| 3. Validation | Confirmation des vulnérabilités, élimination des faux positifs | 1 - 5min |
| 4. Exploits | Génération de preuves de concept | 1 - 3min |
| 5. Rapport | Création du rapport HTML professionnel | 10s |

---

## 6. Types de Vulnérabilités Détectées

| Catégorie | Vulnérabilités |
|-----------|----------------|
| **Injection** | SQL, NoSQL, LDAP, OS Command, SSTI |
| **XSS** | Réfléchi, Stocké, DOM-based |
| **Authentification** | Bypass, Brute-force, Session |
| **Accès** | IDOR, Path Traversal, LFI |
| **Configuration** | Headers manquants, CORS, Clickjacking |
| **Autres** | SSRF, XXE, Désérialisation, CSRF |

---

## 7. Lecture du Rapport

Le rapport HTML contient :

1. **Page de couverture** : Client, date, classification
2. **Résumé exécutif** : Score de risque, statistiques
3. **Synthèse** : Tableau de toutes les vulnérabilités
4. **Analyse détaillée** : Pour chaque vulnérabilité critique/élevée :
   - URL affectée
   - Payload utilisé
   - Preuve d'exploitation
   - Recommandation de correction
5. **Plan de remédiation** : Actions prioritaires

---

## 8. Conseils d'Utilisation

### ✅ À faire

- Tester d'abord sur des sites de test (testphp.vulnweb.com, DVWA)
- Obtenir une autorisation écrite avant de scanner un site tiers
- Commencer en mode normal avant le mode agressif

### ❌ À ne pas faire

- Scanner des sites sans autorisation (illégal)
- Scanner des sites en production pendant les heures de pointe
- Ignorer les vulnérabilités critiques

---

## 9. Dépannage

| Problème | Solution |
|----------|----------|
| `ModuleNotFoundError` | `pip install -r requirements.txt` |
| Port 5000 occupé | `lsof -i :5000` puis `kill <PID>` |
| Scan trop long | Réduire la cible ou désactiver certains modules |
| Pas de vulnérabilités | Vérifier que l'URL est accessible |

---

## 10. Sites de Test Recommandés

| Site | Description |
|------|-------------|
| http://testphp.vulnweb.com | Site PHP vulnérable (Acunetix) |
| http://demo.testfire.net | Application bancaire vulnérable |
| DVWA (Docker) | Damn Vulnerable Web Application |
| OWASP Juice Shop | Application moderne vulnérable |

---

## 11. Support

- **Documentation** : Voir `README.md`
- **Rapports générés** : Dossier `rapports/output/`
- **Logs** : Dossier `logs/`

---

*VulnHunter Pro v4.4 - Scanner de Vulnérabilités Web Professionnel*
