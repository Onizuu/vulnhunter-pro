"""
Templates de prompts optimisés pour l'IA
"""


class PromptsIA:
    """
    Collection de prompts optimisés pour différentes tâches
    """

    @staticmethod
    def generer_payloads_sqli(contexte: str, dbms: str = None) -> str:
        """
        Prompt pour générer des payloads SQL injection
        """
        dbms_info = f"pour {dbms}" if dbms else ""
        
        return f"""Tu es un expert en sécurité offensive spécialisé dans les injections SQL.

Contexte d'injection: {contexte}
SGBD: {dbms or "Inconnu"}

Génère 30 payloads d'injection SQL {dbms_info} qui:
1. Contournent les WAF modernes (Cloudflare, AWS WAF, ModSecurity)
2. Utilisent des techniques d'obfuscation variées
3. Incluent des payloads temporels (SLEEP, WAITFOR)
4. Incluent des payloads basés sur erreur
5. Incluent des payloads UNION-based
6. Sont fonctionnels et testés

Techniques à utiliser:
- Encodage multiple (URL, hex, unicode, base64)
- Commentaires SQL variés (-- , /*, #, ;--)
- Variations de casse (sElEcT)
- Espaces alternatifs (tabs, newlines, /**/)
- Opérateurs logiques alternatifs (AND/&&, OR/||)
- Fonctions SQL alternatives
- Bypass de quotes (char(), concat(), hex())

Retourne UNIQUEMENT un JSON avec ce format exact:
{{
    "payloads": [
        {{"payload": "...", "technique": "...", "description": "..."}},
        ...
    ]
}}

Ne pas inclure d'explications en dehors du JSON."""

    @staticmethod
    def generer_payloads_xss(contexte: str, filtres: list = None) -> str:
        """
        Prompt pour générer des payloads XSS
        """
        filtres_info = ", ".join(filtres) if filtres else "Aucun détecté"
        
        return f"""Tu es un expert en sécurité offensive spécialisé dans les attaques XSS.

Contexte d'injection: {contexte}
Filtres détectés: {filtres_info}

Génère 30 payloads XSS innovants qui:
1. Contournent CSP (Content Security Policy)
2. Fonctionnent dans différents contextes (HTML, JavaScript, attribut)
3. Utilisent l'obfuscation avancée
4. Évitent les mots-clés courants bloqués (script, alert, onerror)
5. Incluent des variantes DOM-based
6. Incluent des payloads sans parenthèses
7. Incluent des payloads polyglot

Techniques:
- Encodages multiples (HTML entities, unicode, hex, base64)
- Event handlers alternatifs (onload, onfocus, onerror, onmouseover)
- Vecteurs sans parenthèses (onerror=alert`1`)
- Template literals ES6
- Mutation XSS
- Tags alternatifs (svg, iframe, img, embed)

Retourne UNIQUEMENT un JSON:
{{
    "payloads": ["payload1", "payload2", ...]
}}"""

    @staticmethod
    def analyser_vulnerabilite(url: str, reponse: str, headers: dict) -> str:
        """
        Prompt pour analyser une réponse HTTP
        """
        headers_str = "\n".join(f"{k}: {v}" for k, v in headers.items())
        
        return f"""Tu es un expert en cybersécurité qui analyse des réponses HTTP.

URL: {url}
Headers:
{headers_str}

Réponse (premiers 3000 caractères):
{reponse[:3000]}

Analyse cette réponse et identifie TOUTES les vulnérabilités et anomalies de sécurité:

1. Fuites d'informations (tokens, clés API, mots de passe, chemins)
2. Messages d'erreur détaillés
3. Commentaires HTML suspects
4. Configurations mal sécurisées
5. Headers de sécurité manquants
6. Indices d'injection SQL, XSS, etc.
7. Endpoints cachés dans JavaScript
8. Paths de fichiers système exposés

Retourne UNIQUEMENT un JSON:
{{
    "vulnerabilites": [
        {{
            "type": "Type exact",
            "severite": "CRITIQUE|ÉLEVÉ|MOYEN|FAIBLE",
            "description": "Description détaillée",
            "preuve": "Extrait de code prouvant la vulnérabilité",
            "recommandation": "Comment corriger"
        }}
    ]
}}"""

    @staticmethod
    def construire_chaine_exploit(vulnerabilites: list) -> str:
        """
        Prompt pour construire des chaînes d'exploitation
        """
        vulns_str = "\n".join([
            f"- {v.get('type', 'Unknown')}: {v.get('description', '')[:100]}"
            for v in vulnerabilites[:10]
        ])
        
        return f"""Tu es un expert en exploitation de vulnérabilités.

Vulnérabilités identifiées:
{vulns_str}

Analyse comment ces vulnérabilités peuvent être combinées en chaînes d'exploitation puissantes.

Pour chaque chaîne possible, fournis:
1. Les vulnérabilités utilisées dans l'ordre
2. Les étapes précises d'exploitation
3. L'impact business réel
4. Un exemple de proof of concept
5. La sévérité globale de la chaîne

Retourne UNIQUEMENT un JSON:
{{
    "chaines": [
        {{
            "nom": "Nom descriptif",
            "vulnerabilites_utilisees": ["type1", "type2"],
            "etapes": ["étape 1", "étape 2", "étape 3"],
            "impact": "Description de l'impact",
            "severite": "CRITIQUE|ÉLEVÉ|MOYEN",
            "poc": "Pseudo-code de preuve de concept"
        }}
    ]
}}"""

    @staticmethod
    def generer_remediation(vulnerabilite) -> str:
        """
        Prompt pour générer des recommandations de correction
        """
        return f"""Tu es un consultant en sécurité qui aide à corriger des vulnérabilités.

Vulnérabilité:
Type: {vulnerabilite.type}
URL: {vulnerabilite.url}
Description: {vulnerabilite.description}
Payload: {vulnerabilite.payload}

Génère des recommandations de correction détaillées en français:

1. **Cause Racine** : Explique pourquoi cette vulnérabilité existe
2. **Corrections Immédiates** : Actions à prendre immédiatement avec exemples de code
3. **Bonnes Pratiques** : Recommandations pour éviter ce problème à l'avenir
4. **Tests de Validation** : Comment valider que la correction fonctionne
5. **Ressources** : Liens vers documentation pertinente

Format en Markdown avec sections claires et exemples de code."""

    @staticmethod
    def generer_resume_executif(statistiques: dict, vulnerabilites: list) -> str:
        """
        Prompt pour générer un résumé exécutif
        """
        return f"""Tu es un consultant en sécurité qui rédige des résumés pour la direction.

Statistiques du scan:
{statistiques}

Principales vulnérabilités:
{vulnerabilites[:5]}

Rédige un résumé exécutif professionnel en français (300-500 mots) qui:

1. Présente la vue d'ensemble de la sécurité
2. Met en avant les risques business (pas techniques)
3. Priorise les actions à prendre
4. Utilise un langage compréhensible pour des non-techniques
5. Inclut des métriques clés
6. Propose des prochaines étapes concrètes

Format: Markdown avec sections:
- Vue d'ensemble
- Risques principaux
- Impact business
- Recommandations prioritaires
- Prochaines étapes

Ton professionnel et factuel."""

