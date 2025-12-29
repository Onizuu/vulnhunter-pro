"""
Détecteur de Race Conditions
TOCTOU (Time-Of-Check-Time-Of-Use) et autres race conditions
"""

import asyncio
import time
from typing import Optional, List, Dict
from loguru import logger
import aiohttp

from core.models import Vulnerabilite


class DetecteurRaceConditions:
    """
    Détecte les vulnérabilités Race Condition
    TOCTOU, concurrent requests, resource exhaustion
    """

    def __init__(self, auth_config: Dict = None):
        """
        Initialise le détecteur
        
        Args:
            auth_config: Configuration d'authentification
        """
        self.auth_config = auth_config or {}
        self.concurrent_requests = 20  # Nombre de requêtes parallèles

    async def detecter(self, url: str, params: Dict = None) -> List[Vulnerabilite]:
        """
        Détecte les vulnérabilités Race Condition
        
        Args:
            url: URL à tester
            params: Paramètres découverts
            
        Returns:
            List[Vulnerabilite]: Vulnérabilités trouvées
        """
        vulnerabilites = []
        
        logger.info(f"🔍 Test Race Conditions: {url}")
        
        try:
            # Test 1: Double spending / multi-use voucher
            vuln = await self._test_double_spending(url, params)
            if vuln:
                vulnerabilites.append(vuln)
            
            # Test 2: Concurrent account creation
            vuln2 = await self._test_duplicate_registration(url, params)
            if vuln2:
                vulnerabilites.append(vuln2)
            
            # Test 3: Rate limit bypass
            vuln3 = await self._test_rate_limit_race(url, params)
            if vuln3:
                vulnerabilites.append(vuln3)
        
        except Exception as e:
            logger.debug(f"Erreur test Race Conditions: {str(e)}")
        
        return vulnerabilites

    async def _test_double_spending(
        self, url: str, params: Dict
    ) -> Optional[Vulnerabilite]:
        """
        Teste le double spending / multi-use de ressources
        Ex: utiliser un coupon plusieurs fois simultanément
        """
        if not params:
            return None
        
        try:
            async with aiohttp.ClientSession(
                cookies=self.auth_config.get('cookies'),
                headers=self.auth_config.get('headers')
            ) as session:
                # Envoyer N requêtes simultanées avec les mêmes données
                tasks = []
                for _ in range(self.concurrent_requests):
                    task = self._send_request(session, url, params, 'POST')
                    tasks.append(task)
                
                # Exécuter en parallèle
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Analyser les résultats
                success_count = sum(
                    1 for r in results 
                    if isinstance(r, dict) and r.get('status') == 200
                )
                
                # Si plus d'une requête réussit → race condition possible
                if success_count > 1:
                    return Vulnerabilite(
                        type="Race_Condition_TOCTOU",
                        severite="HAUTE",
                        url=url,
                        description=f"Race Condition détectée: {success_count}/{self.concurrent_requests} requêtes simultanées ont réussi. Permet double spending, multi-use de vouchers, etc.",
                        payload=f"Concurrent requests: {self.concurrent_requests}",
                        preuve=f"{success_count} successful concurrent operations",
                        cvss_score=8.0,
                        remediation=self._get_remediation()
                    )
        
        except Exception as e:
            logger.debug(f"Erreur double spending: {str(e)}")
        
        return None

    async def _test_duplicate_registration(
        self, url: str, params: Dict
    ) -> Optional[Vulnerabilite]:
        """
        Teste l'enregistrement duplicate simultané
        Ex: créer plusieurs comptes avec le même email
        """
        # Détecter si c'est un endpoint de registration
        if not any(word in url.lower() for word in ['register', 'signup', 'create']):
            return None
        
        try:
            async with aiohttp.ClientSession() as session:
                # Créer des données d'enregistrement
                import random
                test_email = f"race{random.randint(1000, 9999)}@test.com"
                
                test_data = {
                    'email': test_email,
                    'username': f"race_user_{random.randint(1000, 9999)}",
                    'password': 'TestPassword123!'
                }
                
                # Envoyer requêtes simultanées avec les MÊMES données
                tasks = []
                for _ in range(10):
                    task = self._send_request(session, url, test_data, 'POST')
                    tasks.append(task)
                
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Compter les succès
                success_count = sum(
                    1 for r in results 
                    if isinstance(r, dict) and r.get('status') in [200, 201]
                )
                
                if success_count > 1:
                    return Vulnerabilite(
                        type="Race_Condition_Duplicate",
                        severite="MOYENNE",
                        url=url,
                        description=f"Race Condition sur registration: Multiple comptes créés avec les mêmes données ({success_count} succès)",
                        payload=f"Concurrent registrations with same email: {test_email}",
                        preuve=f"{success_count} duplicate accounts created",
                        cvss_score=6.5,
                        remediation=self._get_remediation()
                    )
        
        except Exception as e:
            logger.debug(f"Erreur duplicate registration: {str(e)}")
        
        return None

    async def _test_rate_limit_race(
        self, url: str, params: Dict
    ) -> Optional[Vulnerabilite]:
        """
        Teste le bypass de rate limiting via race conditions
        """
        try:
            async with aiohttp.ClientSession(
                cookies=self.auth_config.get('cookies'),
                headers=self.auth_config.get('headers')
            ) as session:
                # Envoyer burst de requêtes
                start_time = time.time()
                
                tasks = []
                burst_size = 50
                for _ in range(burst_size):
                    task = self._send_request(session, url, params, 'GET')
                    tasks.append(task)
                
                results = await asyncio.gather(*tasks, return_exceptions=True)
                elapsed = time.time() - start_time
                
                # Analyser
                success_count = sum(
                    1 for r in results 
                    if isinstance(r, dict) and r.get('status') == 200
                )
                rate_limited = sum(
                    1 for r in results 
                    if isinstance(r, dict) and r.get('status') == 429
                )
                
                # Si la plupart des requêtes passent malgré le burst → rate limit faible
                if success_count > burst_size * 0.8:  # 80%+
                    return Vulnerabilite(
                        type="Race_Condition_RateLimit",
                        severite="BASSE",
                        url=url,
                        description=f"Rate limiting faible ou bypassable. {success_count}/{burst_size} requêtes en {elapsed:.2f}s ont réussi.",
                        payload=f"Burst: {burst_size} requests in {elapsed:.2f}s",
                        preuve=f"Success: {success_count}, Rate Limited: {rate_limited}",
                        cvss_score=4.5,
                        remediation=self._get_remediation()
                    )
        
        except Exception as e:
            logger.debug(f"Erreur rate limit test: {str(e)}")
        
        return None

    async def _send_request(
        self,
        session: aiohttp.ClientSession,
        url: str,
        data: Dict,
        method: str
    ) -> Dict:
        """Envoie une requête et retourne le résultat"""
        try:
            if method == 'POST':
                async with session.post(
                    url,
                    data=data,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    return {
                        'status': response.status,
                        'body': await response.text()
                    }
            else:
                async with session.get(
                    url,
                    params=data,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    return {
                        'status': response.status,
                        'body': await response.text()
                    }
        except Exception as e:
            return {'error': str(e)}

    def _get_remediation(self) -> str:
        """Recommandations de remediation"""
        return """
Remediation Race Conditions:

1. Utiliser des transactions atomiques (database)
2. Implémenter des locks (mutex, semaphores)
3. Utiliser des opérations idempotentes
4. Token unique par transaction (nonce)
5. Rate limiting strict avec burst protection
6. Distributed locks (Redis, Memcached)
7. Optimistic locking avec version checking
8. Queue-based processing pour opérations critiques
9. Logs et monitoring des détections de race
10. Tests de charge pour identifier les races

Exemple sécurisé (Python/Redis):
```python
import redis
import uuid

r = redis.Redis()

def use_voucher(voucher_code, user_id):
    # 1. Créer un lock unique
    lock_key = f"lock:voucher:{voucher_code}"
    lock_value = str(uuid.uuid4())
    
    # 2. Acquérir le lock avec TTL
    acquired = r.set(lock_key, lock_value, nx=True, ex=10)
    
    if not acquired:
        return {"error": "Voucher being processed"}
    
    try:
        # 3. Vérifier si déjà utilisé (double check)
        if r.exists(f"used:{voucher_code}"):
            return {"error": "Voucher already used"}
        
        # 4. Utiliser le voucher (transaction atomique)
        with r.pipeline() as pipe:
            pipe.set(f"used:{voucher_code}", user_id)
            pipe.execute()
        
        return {"success": True}
    finally:
        # 5. Libérer le lock
        if r.get(lock_key) == lock_value:
            r.delete(lock_key)
```

Database Transaction (SQL):
```sql
BEGIN TRANSACTION;

-- Lock la ligne
SELECT * FROM vouchers 
WHERE code = 'ABC123' 
FOR UPDATE;

-- Vérifier disponibilité
UPDATE vouchers 
SET used = TRUE, used_by = 'user123'
WHERE code = 'ABC123' AND used = FALSE;

-- Si 0 rows affected → déjà utilisé
COMMIT;
```

Références:
- OWASP Race Condition
- CWE-362: Concurrent Execution using Shared Resource
- Time-of-check Time-of-use (TOCTOU)
"""


# Test
async def test_race_conditions():
    """Test du détecteur"""
    detector = DetecteurRaceConditions()
    test_url = "http://localhost:8080/api/use-voucher"
    test_params = {'voucher': 'TEST123'}
    
    vulns = await detector.detecter(test_url, test_params)
    print(f"{'✅' if vulns else '❌'} {len(vulns)} vulnérabilités Race Conditions trouvées")


if __name__ == "__main__":
    asyncio.run(test_race_conditions())
