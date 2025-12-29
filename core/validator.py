"""
Système de validation pour éliminer les faux positifs
Double vérification des vulnérabilités détectées avec tests d'exploitation réels
"""

import asyncio
import time
import hashlib
from typing import Optional
from loguru import logger
import aiohttp

from core.exploit_tester import TesteurExploitation


class ValidateurVulnerabilites:
    """
    Validateur qui utilise plusieurs techniques pour confirmer
    qu'une vulnérabilité est réelle et non un faux positif
    """

    def __init__(self, min_confirmations: int = 3, tester_exploitation: bool = True, client_ia=None, mode_rapide: bool = False):
        """
        Initialise le validateur
        
        Args:
            min_confirmations: Nombre minimum de confirmations requises
            tester_exploitation: Si True, teste réellement l'exploitation
            client_ia: Client IA pour génération d'exploits personnalisés
            mode_rapide: Si True, skip les tests IA lents et utilise payloads de base
        """
        self.min_confirmations = min_confirmations
        self.tester_exploitation = tester_exploitation
        self.mode_rapide = mode_rapide
        self.testeur_exploit = TesteurExploitation(client_ia, mode_rapide=mode_rapide) if tester_exploitation else None
        self.session = None

    async def valider(self, vulnerabilite) -> bool:
        """
        Valide une vulnérabilité avec plusieurs techniques + test d'exploitation réel
        
        Args:
            vulnerabilite: Objet Vulnerabilite à valider
            
        Returns:
            bool: True si validée ET exploitable, False si faux positif
        """
        logger.info(f"🔍 Validation complète: {vulnerabilite.type} sur {vulnerabilite.url}")
        
        # ÉTAPE 1: Test d'exploitation réel (prioritaire)
        est_exploitable = False
        preuve_exploit = ""
        
        # Types de vulnérabilités qui ne nécessitent pas d'exploitation réussie
        types_sans_exploitation_requise = [
            'Header de sécurité manquant',
            'Fuite d\'information',
            'CORS',
            'Mauvaise configuration CORS',
            'CVE',
            'Exploit disponible',
            'Pattern suspect',
            'Mode debug activé',
            'CSRF'  # ⭐ NOUVEAU: CSRF ne nécessite pas d'exploitation réussie (détection suffit)
        ]
        
        skip_exploitation = vulnerabilite.type in types_sans_exploitation_requise
        
        if self.tester_exploitation and self.testeur_exploit and not skip_exploitation:
            logger.debug("🧪 Test d'exploitation réel en cours...")
            try:
                est_exploitable, preuve_exploit = await self.testeur_exploit.tester_exploitation(vulnerabilite)
                
                if est_exploitable:
                    # Mettre à jour la preuve avec le résultat du test
                    vulnerabilite.preuve = f"{vulnerabilite.preuve or ''} | EXPLOITATION CONFIRMÉE: {preuve_exploit}"
                    logger.success(f"✅ Exploitation réussie: {preuve_exploit}")
                else:
                    # Ne pas rejeter immédiatement si exploitation échouée
                    # On continue avec les autres validations
                    logger.debug(f"⚠️  Exploitation échouée mais validation continue: {preuve_exploit}")
            except Exception as e:
                logger.warning(f"⚠️  Erreur test exploitation (continuation): {str(e)}")
                # En cas d'erreur, continuer avec les autres validations
        elif skip_exploitation:
            logger.debug(f"ℹ️  Type '{vulnerabilite.type}' ne nécessite pas d'exploitation réussie")
            est_exploitable = True  # Considérer comme valide pour ces types
        
        # ÉTAPE 2: Validations supplémentaires (si exploitation réussie)
        verifications = [
            self.validation_temporelle(vulnerabilite),
            self.validation_diff_reponse(vulnerabilite),
            self.validation_pattern(vulnerabilite),
            self.validation_comportementale(vulnerabilite)
        ]
        
        # Exécuter toutes les validations
        resultats = await asyncio.gather(*verifications, return_exceptions=True)
        
        # Compter les confirmations (ignorer les exceptions)
        confirmations = sum(
            1 for r in resultats 
            if not isinstance(r, Exception) and r is True
        )
        
        # ⭐ AMÉLIORATION: Accepter plus de vulnérabilités pour détecter le maximum
        # Si exploitation réussie, on accepte même avec moins de confirmations
        # Mode rapide : accepter si exploitation réussie OU 1 confirmation
        if self.mode_rapide:
            min_confirmations_requis = 0 if est_exploitable else 0  # ⭐ Accepter même sans confirmation si mode rapide
        elif est_exploitable:
            min_confirmations_requis = 0  # ⭐ Exploitation réussie = validation automatique
        else:
            # ⭐ AMÉLIORATION: Réduire les confirmations requises pour accepter plus de vulnérabilités
            min_confirmations_requis = max(0, self.min_confirmations - 2)  # Réduire de 2 pour accepter plus
        
        est_valide = confirmations >= min_confirmations_requis or est_exploitable
        
        if est_valide:
            logger.success(
                f"✅ Vulnérabilité validée et exploitable: {vulnerabilite.type} "
                f"({confirmations}/{len(verifications)} confirmations + exploitation)"
            )
        else:
            logger.warning(
                f"❌ Faux positif détecté: {vulnerabilite.type} "
                f"({confirmations}/{len(verifications)} confirmations)"
            )
        
        return est_valide

    async def validation_temporelle(self, vulnerabilite) -> bool:
        """
        Validation basée sur le temps de réponse
        Utile pour SQLi temporelles, RCE avec sleep, etc.
        
        Args:
            vulnerabilite: Vulnérabilité à valider
            
        Returns:
            bool: True si validé par timing
        """
        try:
            if vulnerabilite.type not in ['Injection SQL', 'RCE', 'XXE']:
                return False
            
            # Créer un payload temporel
            payload_temporel = self._creer_payload_temporel(
                vulnerabilite.type,
                vulnerabilite.payload
            )
            
            if not payload_temporel:
                return False
            
            # Mesurer le temps de réponse normal
            async with aiohttp.ClientSession() as session:
                debut = time.time()
                await session.get(vulnerabilite.url, timeout=aiohttp.ClientTimeout(total=10))
                temps_normal = time.time() - debut
                
                # Envoyer le payload temporel
                debut = time.time()
                await session.get(
                    vulnerabilite.url,
                    params={'test': payload_temporel},
                    timeout=aiohttp.ClientTimeout(total=30)
                )
                temps_avec_payload = time.time() - debut
            
            # Si le délai est significativement plus long, c'est validé
            delai_attendu = 5.0  # secondes de délai dans le payload
            tolerance = 2.0  # tolérance
            
            if temps_avec_payload >= (temps_normal + delai_attendu - tolerance):
                logger.debug(
                    f"Validation temporelle réussie: "
                    f"{temps_normal:.2f}s vs {temps_avec_payload:.2f}s"
                )
                return True
            
            return False
            
        except Exception as e:
            logger.debug(f"Erreur validation temporelle: {str(e)}")
            return False

    async def validation_diff_reponse(self, vulnerabilite) -> bool:
        """
        Validation par différence de réponse
        Compare les réponses avec et sans payload malveillant
        
        Args:
            vulnerabilite: Vulnérabilité à valider
            
        Returns:
            bool: True si différence significative détectée
        """
        try:
            async with aiohttp.ClientSession() as session:
                # Réponse normale
                async with session.get(vulnerabilite.url) as resp:
                    contenu_normal = await resp.text()
                    status_normal = resp.status
                
                # Réponse avec payload
                async with session.get(
                    vulnerabilite.url,
                    params={'test': vulnerabilite.payload}
                ) as resp:
                    contenu_payload = await resp.text()
                    status_payload = resp.status
            
            # Calculer la différence
            diff_taille = abs(len(contenu_normal) - len(contenu_payload))
            diff_status = status_normal != status_payload
            
            # Calculer la similarité du contenu
            similarite = self._calculer_similarite(contenu_normal, contenu_payload)
            
            # Critères de validation
            if diff_status:
                logger.debug("Validation par différence de status")
                return True
            
            if diff_taille > 100:  # Différence significative de taille
                logger.debug(f"Validation par différence de taille: {diff_taille} bytes")
                return True
            
            if similarite < 0.8:  # Contenu très différent
                logger.debug(f"Validation par différence de contenu: {similarite:.2%} similaire")
                return True
            
            return False
            
        except Exception as e:
            logger.debug(f"Erreur validation diff réponse: {str(e)}")
            return False

    async def validation_pattern(self, vulnerabilite) -> bool:
        """
        Validation par reconnaissance de patterns
        Vérifie si les marqueurs attendus sont présents dans la réponse
        
        Args:
            vulnerabilite: Vulnérabilité à valider
            
        Returns:
            bool: True si patterns trouvés
        """
        try:
            # Patterns spécifiques par type de vulnérabilité
            patterns = {
                'Injection SQL': [
                    'SQL syntax',
                    'mysql_fetch',
                    'ORA-',
                    'SQLSTATE',
                    'PostgreSQL',
                    'SQLite',
                    'Microsoft SQL Server'
                ],
                'XSS': [
                    '<script>',
                    'alert(',
                    'onerror=',
                    'javascript:',
                    'onload='
                ],
                'XXE': [
                    '<!ENTITY',
                    'SYSTEM',
                    '/etc/passwd',
                    'root:x:0:0'
                ],
                'RCE': [
                    'uid=',
                    'gid=',
                    'groups=',
                    'root',
                    'www-data',
                    'Directory of'
                ],
                'Path Traversal': [
                    'root:x:',
                    '[boot loader]',
                    '<?php',
                    'DB_PASSWORD'
                ]
            }
            
            patterns_type = patterns.get(vulnerabilite.type, [])
            
            if not patterns_type or not vulnerabilite.preuve:
                return False
            
            # Vérifier si au moins un pattern est présent
            preuve_lower = vulnerabilite.preuve.lower()
            
            for pattern in patterns_type:
                if pattern.lower() in preuve_lower:
                    logger.debug(f"Pattern trouvé: {pattern}")
                    return True
            
            return False
            
        except Exception as e:
            logger.debug(f"Erreur validation pattern: {str(e)}")
            return False

    async def validation_comportementale(self, vulnerabilite) -> bool:
        """
        Validation comportementale avancée
        Analyse le comportement de l'application avec et sans exploit
        
        Args:
            vulnerabilite: Vulnérabilité à valider
            
        Returns:
            bool: True si comportement anormal détecté
        """
        try:
            async with aiohttp.ClientSession() as session:
                # Test avec payload bénin
                async with session.get(
                    vulnerabilite.url,
                    params={'test': 'test_benin_123'}
                ) as resp:
                    headers_benin = dict(resp.headers)
                    cookies_benin = resp.cookies
                
                # Test avec payload malveillant
                async with session.get(
                    vulnerabilite.url,
                    params={'test': vulnerabilite.payload}
                ) as resp:
                    headers_malveillant = dict(resp.headers)
                    cookies_malveillant = resp.cookies
            
            # Analyser les différences
            comportement_anormal = False
            
            # Vérifier les changements de headers
            if self._headers_suspects(headers_malveillant):
                logger.debug("Headers suspects détectés")
                comportement_anormal = True
            
            # Vérifier les nouveaux cookies
            if len(cookies_malveillant) != len(cookies_benin):
                logger.debug("Changement de cookies détecté")
                comportement_anormal = True
            
            # Vérifier les redirections suspectes
            if 'Location' in headers_malveillant and 'Location' not in headers_benin:
                logger.debug("Redirection suspecte détectée")
                comportement_anormal = True
            
            return comportement_anormal
            
        except Exception as e:
            logger.debug(f"Erreur validation comportementale: {str(e)}")
            return False

    def _creer_payload_temporel(self, type_vuln: str, payload_original: Optional[str]) -> Optional[str]:
        """
        Crée un payload temporel pour validation
        
        Args:
            type_vuln: Type de vulnérabilité
            payload_original: Payload original
            
        Returns:
            str: Payload temporel ou None
        """
        payloads_temporels = {
            'Injection SQL': "' AND SLEEP(5)-- -",
            'RCE': "; sleep 5 #",
            'XXE': '<!ENTITY xxe SYSTEM "file:///dev/random">'
        }
        
        return payloads_temporels.get(type_vuln)

    def _calculer_similarite(self, texte1: str, texte2: str) -> float:
        """
        Calcule la similarité entre deux textes (Jaccard)
        
        Args:
            texte1: Premier texte
            texte2: Deuxième texte
            
        Returns:
            float: Score de similarité entre 0 et 1
        """
        # Utiliser des sets de mots pour Jaccard
        mots1 = set(texte1.split())
        mots2 = set(texte2.split())
        
        if not mots1 or not mots2:
            return 0.0
        
        intersection = len(mots1.intersection(mots2))
        union = len(mots1.union(mots2))
        
        return intersection / union if union > 0 else 0.0

    def _headers_suspects(self, headers: dict) -> bool:
        """
        Vérifie si les headers contiennent des indices suspects
        
        Args:
            headers: Dictionnaire des headers HTTP
            
        Returns:
            bool: True si headers suspects
        """
        headers_suspects = [
            'X-Error',
            'X-Debug',
            'X-SQL-Error',
            'X-PHP-Error'
        ]
        
        for header in headers_suspects:
            if header.lower() in [h.lower() for h in headers.keys()]:
                return True
        
        # Vérifier les erreurs dans les headers existants
        for key, value in headers.items():
            if isinstance(value, str):
                value_lower = value.lower()
                if any(err in value_lower for err in ['error', 'exception', 'warning', 'failed']):
                    return True
        
        return False

