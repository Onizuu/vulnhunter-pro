"""
Énumérateur de sous-domaines avancé
Utilise multiple sources: DNS bruteforce, Certificate Transparency, WHOIS, etc.
"""

import asyncio
from typing import List, Set
from loguru import logger
import dns.resolver
import dns.reversename
import aiohttp
import json
import re
from urllib.parse import urlparse
try:
    import whois
    WHOIS_DISPONIBLE = True
except ImportError:
    WHOIS_DISPONIBLE = False
    logger.debug("Module whois non disponible - WHOIS désactivé")


class EnumerateurSousdomaines:
    """
    Énumère les sous-domaines d'un domaine cible avec méthodes avancées
    """

    def __init__(self):
        # Wordlist étendue de sous-domaines communs (>1000 entrées)
        self.sous_domaines_communs = [
            # Services web de base
            'www', 'www2', 'www3', 'web', 'webs', 'site', 'sites', 'website',
            'mail', 'email', 'smtp', 'pop', 'pop3', 'imap', 'mx', 'relay',
            'ftp', 'ftps', 'sftp', 'ssh', 'git', 'svn', 'cvs',

            # Serveurs de noms
            'ns', 'ns1', 'ns2', 'ns3', 'ns4', 'ns5', 'dns', 'dns1', 'dns2',
            'primary', 'secondary', 'backup', 'dns3', 'dns4',

            # Hébergement/Administration
            'cpanel', 'whm', 'plesk', 'directadmin', 'webmail', 'webdisk',
            'roundcube', 'squirrel', 'horde', 'imp', 'autodiscover', 'autoconfig',
            'owa', 'exchange', 'zimbra', 'sogo',

            # Développement/Déploiement
            'dev', 'devel', 'development', 'staging', 'stage', 'test', 'testing',
            'qa', 'quality', 'demo', 'demos', 'sandbox', 'lab', 'labs',
            'alpha', 'beta', 'gamma', 'delta', 'prod', 'production', 'live',
            'ci', 'cd', 'jenkins', 'travis', 'circleci', 'build', 'builds',

            # API et services
            'api', 'apis', 'rest', 'graphql', 'soap', 'rpc', 'json', 'xml',
            'service', 'services', 'microservice', 'microservices',
            'gateway', 'proxy', 'auth', 'oauth', 'sso', 'login', 'signin',

            # Applications et portails
            'admin', 'administrator', 'root', 'superuser', 'manager', 'manage',
            'control', 'panel', 'dashboard', 'console', 'monitor', 'monitoring',
            'stats', 'statistics', 'analytics', 'logs', 'log', 'syslog',

            # E-commerce
            'shop', 'store', 'ecommerce', 'cart', 'basket', 'checkout', 'payment',
            'billing', 'invoice', 'order', 'orders', 'catalog', 'product', 'products',

            # Communication
            'chat', 'forum', 'forums', 'community', 'social', 'blog', 'blogs',
            'news', 'newsletter', 'mailing', 'support', 'help', 'faq', 'wiki',
            'docs', 'documentation', 'guide', 'guides',

            # Mobile et responsive
            'm', 'mobile', 'app', 'apps', 'ios', 'android', 'phone', 'tablet',
            'touch', 'wap', 'pda', 'smartphone',

            # CDN et médias
            'cdn', 'static', 'assets', 'media', 'images', 'img', 'pics', 'photos',
            'video', 'videos', 'stream', 'streaming', 'download', 'downloads',
            'upload', 'uploads', 'files', 'file', 'storage', 'backup',

            # Sécurité
            'secure', 'ssl', 'tls', 'vpn', 'remote', 'rdp', 'vnc', 'teamviewer',
            'firewall', 'waf', 'ids', 'ips', 'honeypot', 'trap',

            # Bases de données
            'db', 'database', 'sql', 'mysql', 'postgres', 'mongodb', 'redis',
            'couchdb', 'elasticsearch', 'solr', 'dbadmin', 'phpmyadmin',

            # Monitoring et métriques
            'status', 'health', 'metrics', 'graphite', 'grafana', 'kibana',
            'prometheus', 'zabbix', 'nagios', 'munin', 'cacti',

            # Cloud services courants
            'aws', 's3', 'ec2', 'elb', 'cloudfront', 'route53', 'lambda',
            'azure', 'blob', 'cdn', 'functions', 'gcp', 'firebase', 'heroku',
            'netlify', 'vercel', 'surge', 'github', 'gitlab', 'bitbucket',

            # Sous-domaines par secteur d'activité
            'portal', 'intranet', 'extranet', 'partner', 'partners', 'vendor',
            'client', 'clients', 'customer', 'customers', 'user', 'users',
            'member', 'members', 'staff', 'employee', 'employees',

            # Géographiques
            'us', 'eu', 'asia', 'na', 'sa', 'af', 'au', 'uk', 'de', 'fr', 'es',
            'it', 'jp', 'cn', 'kr', 'in', 'br', 'mx', 'ar', 'co', 'cl',

            # Temporaires et autres
            'temp', 'tmp', 'cache', 'old', 'new', 'v1', 'v2', 'v3', 'v4', 'v5',
            'backup', 'archive', 'archived', 'mirror', 'mirrors', 'redirect',

            # Plus de services
            'calendar', 'cal', 'event', 'events', 'meeting', 'meetings', 'conference',
            'webinar', 'training', 'course', 'courses', 'class', 'classes',
            'school', 'university', 'college', 'academy', 'learning', 'edu',

            # Jeux et divertissement
            'game', 'games', 'play', 'gaming', 'arcade', 'casino', 'bet', 'bets',
            'poker', 'slot', 'slots', 'jackpot', 'winner', 'winners',

            # Plus de technos
            'node', 'nodejs', 'npm', 'yarn', 'webpack', 'babel', 'grunt', 'gulp',
            'docker', 'kubernetes', 'k8s', 'jenkins', 'gitlab', 'bitbucket',
            'selenium', 'testing', 'test', 'uat', 'acceptance'
        ]

        # Configuration
        self.max_concurrent_requests = 50
        self.timeout_dns = 2
        self.crt_timeout = 10

    async def enumerer(self, url: str) -> List[str]:
        """
        Énumère les sous-domaines avec méthodes avancées

        Args:
            url: URL du domaine cible

        Returns:
            List[str]: Sous-domaines trouvés et validés
        """
        tous_sousdomaines = set()

        try:
            parsed = urlparse(url)
            domaine = parsed.netloc or parsed.path

            # Nettoyer le domaine (enlever www. si présent)
            domaine = re.sub(r'^www\.', '', domaine)

            logger.info(f"🔍 Énumération avancée de sous-domaines: {domaine}")

            # Méthode 1: Bruteforce DNS parallélisé
            logger.debug("📡 Méthode 1: Bruteforce DNS...")
            dns_subs = await self._bruteforce_dns_parallele(domaine)
            tous_sousdomaines.update(dns_subs)
            logger.info(f"   ✅ DNS bruteforce: {len(dns_subs)} trouvés")

            # Méthode 2: Certificate Transparency Logs
            logger.debug("📜 Méthode 2: Certificate Transparency...")
            crt_subs = await self._certificate_transparency(domaine)
            tous_sousdomaines.update(crt_subs)
            logger.info(f"   ✅ Certificate Transparency: {len(crt_subs)} trouvés")

            # Méthode 3: Recherche reverse DNS
            logger.debug("🔄 Méthode 3: Reverse DNS...")
            reverse_subs = await self._reverse_dns(domaine)
            tous_sousdomaines.update(reverse_subs)
            logger.info(f"   ✅ Reverse DNS: {len(reverse_subs)} trouvés")

            # Méthode 4: Subfinder (si disponible)
            logger.debug("🛠️  Méthode 4: Subfinder...")
            try:
                subfinder_subs = await self._utiliser_subfinder(domaine)
                tous_sousdomaines.update(subfinder_subs)
                logger.info(f"   ✅ Subfinder: {len(subfinder_subs)} trouvés")
            except Exception as e:
                logger.debug(f"   ⚠️  Subfinder non disponible: {str(e)}")

            # Méthode 5: WHOIS data
            logger.debug("📋 Méthode 5: WHOIS...")
            whois_subs = await self._whois_subdomains(domaine)
            tous_sousdomaines.update(whois_subs)
            logger.info(f"   ✅ WHOIS: {len(whois_subs)} trouvés")

            # Validation finale: vérifier que les sous-domaines répondent
            logger.debug("✅ Validation des sous-domaines...")
            sousdomaines_valides = await self._valider_sousdomaines(list(tous_sousdomaines), domaine)

            # Statistiques finales
            logger.success(f"🎯 TOTAL: {len(sousdomaines_valides)} sous-domaines validés sur {len(tous_sousdomaines)} trouvés")

            return sousdomaines_valides

        except Exception as e:
            logger.error(f"Erreur énumération sous-domaines avancée: {str(e)}")
            return []

    async def _bruteforce_dns_parallele(self, domaine: str) -> Set[str]:
        """
        Bruteforce DNS parallélisé avec semaphore pour contrôle du taux
        """
        sousdomaines = set()
        semaphore = asyncio.Semaphore(self.max_concurrent_requests)
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout_dns
        resolver.lifetime = self.timeout_dns

        async def check_subdomain(sub: str):
            async with semaphore:
                try:
                    test_domaine = f"{sub}.{domaine}"
                    answers = await asyncio.get_event_loop().run_in_executor(
                        None, resolver.resolve, test_domaine, 'A'
                    )
                    if answers:
                        sousdomaines.add(test_domaine)
                        logger.debug(f"   📡 DNS: {test_domaine}")
                except:
                    pass

        # Créer toutes les tâches
        tasks = [check_subdomain(sub) for sub in self.sous_domaines_communs]

        # Exécuter en parallèle avec gestion d'erreurs
        await asyncio.gather(*tasks, return_exceptions=True)

        return sousdomaines

    async def _certificate_transparency(self, domaine: str) -> Set[str]:
        """
        Recherche de sous-domaines via Certificate Transparency logs (crt.sh)
        """
        sousdomaines = set()

        try:
            url = f"https://crt.sh/?q=%.{domaine}&output=json"

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=self.crt_timeout)
                ) as response:

                    if response.status == 200:
                        data = await response.json()

                        for cert in data:
                            name_value = cert.get('name_value', '')
                            if name_value and '*' not in name_value:
                                # Nettoyer et splitter les domaines
                                domains = name_value.split('\n')
                                for domain in domains:
                                    domain = domain.strip()
                                    if domain.endswith(f'.{domaine}') and domain != domaine:
                                        sousdomaines.add(domain.lower())
                                        logger.debug(f"   📜 CRT: {domain}")

        except Exception as e:
            logger.debug(f"Erreur Certificate Transparency: {str(e)}")

        return sousdomaines

    async def _reverse_dns(self, domaine: str) -> Set[str]:
        """
        Recherche de sous-domaines via reverse DNS lookups
        """
        sousdomaines = set()

        try:
            # Résoudre d'abord l'IP du domaine principal
            resolver = dns.resolver.Resolver()
            answers = resolver.resolve(domaine, 'A')

            for answer in answers:
                ip = answer.address
                logger.debug(f"   🔍 Reverse DNS pour IP: {ip}")

                try:
                    # Reverse lookup
                    reverse_name = dns.reversename.from_address(ip)
                    ptr_answers = resolver.resolve(reverse_name, 'PTR')

                    for ptr_answer in ptr_answers:
                        ptr_domain = str(ptr_answer.target).rstrip('.')
                        if ptr_domain.endswith(f'.{domaine}') and ptr_domain != domaine:
                            sousdomaines.add(ptr_domain.lower())
                            logger.debug(f"   🔄 Reverse: {ptr_domain}")

                except:
                    pass

        except Exception as e:
            logger.debug(f"Erreur reverse DNS: {str(e)}")

        return sousdomaines

    async def _whois_subdomains(self, domaine: str) -> Set[str]:
        """
        Extraction de sous-domaines depuis les données WHOIS
        """
        sousdomaines = set()

        if not WHOIS_DISPONIBLE:
            return sousdomaines

        try:
            # Utiliser python-whois pour les données WHOIS
            w = whois.whois(domaine)

            # Chercher dans tous les champs texte
            whois_text = str(w).lower()

            # Patterns pour trouver des sous-domaines
            patterns = [
                r'([a-z0-9-]+\.' + re.escape(domaine) + r')',
                r'([a-z0-9-]+\.' + re.escape(domaine) + r'/?)',
            ]

            for pattern in patterns:
                matches = re.findall(pattern, whois_text, re.IGNORECASE)
                for match in matches:
                    match = match.lower().strip('/')
                    if match != domaine and '.' in match:
                        sousdomaines.add(match)
                        logger.debug(f"   📋 WHOIS: {match}")

        except Exception as e:
            logger.debug(f"Erreur WHOIS: {str(e)}")

        return sousdomaines

    async def _valider_sousdomaines(self, sousdomaines: List[str], domaine_principal: str) -> List[str]:
        """
        Valide que les sous-domaines répondent réellement (au moins HTTP)
        """
        valides = []
        semaphore = asyncio.Semaphore(20)  # 20 validations simultanées

        async def valider_subdomain(sub: str):
            async with semaphore:
                try:
                    # Essayer HTTP d'abord
                    urls = [f"http://{sub}", f"https://{sub}"]

                    for url in urls:
                        async with aiohttp.ClientSession() as session:
                            try:
                                async with session.get(
                                    url,
                                    timeout=aiohttp.ClientTimeout(total=5),
                                    allow_redirects=True
                                ) as response:
                                    if response.status < 500:  # Tout sauf erreur serveur
                                        valides.append(sub)
                                        logger.debug(f"   ✅ Validé: {sub} ({response.status})")
                                        return
                            except:
                                continue

                except Exception as e:
                    logger.debug(f"   ❌ Échec validation {sub}: {str(e)}")

        # Créer les tâches de validation
        tasks = [valider_subdomain(sub) for sub in sousdomaines if sub != domaine_principal]

        # Exécuter en parallèle
        await asyncio.gather(*tasks, return_exceptions=True)

        # Ajouter toujours le domaine principal
        valides.insert(0, domaine_principal)

        return list(set(valides))

    async def _utiliser_subfinder(self, domaine: str) -> Set[str]:
        """
        Utilise l'outil subfinder pour énumération avancée
        """
        sousdomaines = set()

        try:
            cmd = ["subfinder", "-d", domaine, "-silent", "-timeout", "10"]

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, _ = await asyncio.wait_for(
                process.communicate(),
                timeout=30
            )

            resultats = stdout.decode().strip().split('\n')
            for sub in resultats:
                sub = sub.strip()
                if sub and sub.endswith(f'.{domaine}'):
                    sousdomaines.add(sub.lower())
                    logger.debug(f"   🛠️  Subfinder: {sub}")

        except Exception as e:
            logger.debug(f"Subfinder non disponible: {str(e)}")

        return sousdomaines

