"""
Détecteur de Business Logic Flaws
Failles métier et logiques d'application
"""

import asyncio
from typing import Optional, List, Dict
from loguru import logger
import aiohttp

from core.models import Vulnerabilite


class DetecteurBusinessLogic:
    """
    Détecte les vulnérabilités Business Logic
    Price manipulation, workflow bypass, privilege escalation, etc.
    """

    def __init__(self, auth_config: Dict = None):
        """
        Initialise le détecteur
        
        Args:
            auth_config: Configuration d'authentification
        """
        self.auth_config = auth_config or {}

    async def detecter(self, url: str, params: Dict = None) -> List[Vulnerabilite]:
        """
        Détecte les vulnérabilités Business Logic
        
        Args:
            url: URL à tester
            params: Paramètres découverts
            
        Returns:
            List[Vulnerabilite]: Vulnérabilités trouvées
        """
        vulnerabilites = []
        
        logger.info(f"🔍 Test Business Logic: {url}")
        
        if not params:
            return vulnerabilites
        
        try:
            async with aiohttp.ClientSession(
                cookies=self.auth_config.get('cookies'),
                headers=self.auth_config.get('headers')
            ) as session:
                # Test 1: Price manipulation
                price_vulns = await self._test_price_manipulation(session, url, params)
                vulnerabilites.extend(price_vulns)
                
                # Test 2: Negative quantities
                negative_vulns = await self._test_negative_values(session, url, params)
                vulnerabilites.extend(negative_vulns)
                
                # Test 3: Workflow bypass
                workflow_vulns = await self._test_workflow_bypass(session, url, params)
                vulnerabilites.extend(workflow_vulns)
                
                # Test 4: Privilege escalation via parameters
                priv_vulns = await self._test_privilege_escalation(session, url, params)
                vulnerabilites.extend(priv_vulns)
        
        except Exception as e:
            logger.debug(f"Erreur test Business Logic: {str(e)}")
        
        return vulnerabilites

    async def _test_price_manipulation(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict
    ) -> List[Vulnerabilite]:
        """Teste la manipulation de prix"""
        vulnerabilites = []
        
        # Chercher paramètres de prix
        price_params = ['price', 'amount', 'total', 'cost', 'value']
        
        for param_name in params.keys():
            if any(p in param_name.lower() for p in price_params):
                # Tester manipulation
                test_data = params.copy()
                
                # Test 1: Prix à 0
                test_data[param_name] = 0
                vuln = await self._check_business_logic_vuln(
                    session, url, test_data,
                    "Price_Manipulation_Zero",
                    f"Prix manipulé à 0 via '{param_name}'",
                    8.5
                )
                if vuln:
                    vulnerabilites.append(vuln)
                
                # Test 2: Prix à 0.01
                test_data[param_name] = 0.01
                vuln = await self._check_business_logic_vuln(
                    session, url, test_data,
                    "Price_Manipulation_Low",
                    f"Prix manipulé à 0.01 via '{param_name}'",
                    7.5
                )
                if vuln:
                    vulnerabilites.append(vuln)
                
                break  # Un test suffit
        
        return vulnerabilites

    async def _test_negative_values(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict
    ) -> List[Vulnerabilite]:
        """Teste les valeurs négatives"""
        vulnerabilites = []
        
        # Paramètres de quantité
        quantity_params = ['quantity', 'qty', 'amount', 'count']
        
        for param_name in params.keys():
            if any(q in param_name.lower() for q in quantity_params):
                test_data = params.copy()
                test_data[param_name] = -1
                
                vuln = await self._check_business_logic_vuln(
                    session, url, test_data,
                    "Negative_Quantity",
                    f"Quantité négative acceptée via '{param_name}'. Peut causer refund abuse.",
                    7.0
                )
                if vuln:
                    vulnerabilites.append(vuln)
                break
        
        return vulnerabilites

    async def _test_workflow_bypass(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict
    ) -> List[Vulnerabilite]:
        """Teste le bypass de workflow"""
        vulnerabilites = []
        
        # Paramètres de state/status
        state_params = ['status', 'state', 'step', 'stage']
        
        for param_name in params.keys():
            if any(s in param_name.lower() for s in state_params):
                # Tenter de skip des étapes
                test_states = ['completed', 'approved', 'confirmed', 'paid', 'shipped']
                
                for test_state in test_states:
                    test_data = params.copy()
                    test_data[param_name] = test_state
                    
                    vuln = await self._check_business_logic_vuln(
                        session, url, test_data,
                        "Workflow_Bypass",
                        f"Bypass de workflow via '{param_name}={test_state}'",
                        8.0
                    )
                    if vuln:
                        vulnerabilites.append(vuln)
                        break
                break
        
        return vulnerabilites

    async def _test_privilege_escalation(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: Dict
    ) -> List[Vulnerabilite]:
        """Teste l'escalation de privilèges via paramètres"""
        vulnerabilites = []
        
        # Paramètres de rôle
        role_params = ['role', 'usertype', 'level', 'privilege', 'permission']
        
        for param_name in params.keys():
            if any(r in param_name.lower() for r in role_params):
                # Tenter élévation
                test_roles = ['admin', 'administrator', 'root', 'superuser']
                
                for test_role in test_roles:
                    test_data = params.copy()
                    test_data[param_name] = test_role
                    
                    vuln = await self._check_business_logic_vuln(
                        session, url, test_data,
                        "Privilege_Escalation_Param",
                        f"Escalation de privilèges via '{param_name}={test_role}'",
                        9.0
                    )
                    if vuln:
                        vulnerabilites.append(vuln)
                        break
                break
        
        return vulnerabilites

    async def _check_business_logic_vuln(
        self,
        session: aiohttp.ClientSession,
        url: str,
        test_data: Dict,
        vuln_type: str,
        description: str,
        cvss_score: float
    ) -> Optional[Vulnerabilite]:
        """Vérifie si une logique métier est vulnérable"""
        try:
            async with session.post(
                url,
                data=test_data,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                content = await response.text()
                
                # Indicateurs de succès
                success_indicators = [
                    'success', 'completed', 'approved', 'confirmed',
                    'thank you', 'order placed', 'payment successful'
                ]
                
                # Si status 200 et indicateurs positifs → vulnérable
                if response.status == 200 and any(
                    ind in content.lower() for ind in success_indicators
                ):
                    logger.success(f"✅ Business Logic flaw trouvé: {vuln_type}")
                    
                    return Vulnerabilite(
                        type=vuln_type,
                        severite="HAUTE",
                        url=url,
                        description=description,
                        payload=str(test_data),
                        preuve=content[:400],
                        cvss_score=cvss_score,
                        remediation=self._get_remediation()
                    )
        
        except Exception:
            pass
        
        return None

    def _get_remediation(self) -> str:
        """Recommandations de remediation"""
        return """
Remediation Business Logic Flaws:

1. Validation côté serveur OBLIGATOIRE (jamais uniquement client)
2. Valider TOUS les paramètres (prix, quantité, status, etc.)
3. Implémenter des contraintes métier strictes
4. Vérifier les workflows à chaque étape
5. Logs détaillés des opérations critiques
6. Montants/quantités: validation de plage (min/max)
7. State machine pour workflows complexes
8. Tests de sécurité métier dans CI/CD
9. Principe du moindre privilège
10. Monitoring des anomalies métier

Exemples de validation:

**Prix / Montants:**
```python
def validate_price(price):
    if not isinstance(price, (int, float)):
        raise ValueError("Invalid price type")
    
    if price <= 0:
        raise ValueError("Price must be positive")
    
    if price > MAX_PRICE:
        raise ValueError("Price too high")
    
    # Vérifier cohérence avec base de données
    db_price = get_product_price(product_id)
    if abs(price - db_price) > 0.01:
        raise ValueError("Price mismatch")
    
    return price
```

**Quantités:**
```python
def validate_quantity(qty):
    if not isinstance(qty, int):
        raise ValueError("Quantity must be integer")
    
    if qty < 1:
        raise ValueError("Quantity must be positive")
    
    if qty > MAX_QUANTITY:
        raise ValueError("Quantity too high")
    
    # Vérifier stock
    if qty > available_stock:
        raise ValueError("Insufficient stock")
    
    return qty
```

**Workflow / State:**
```python
class OrderStateMachine:
    VALID_TRANSITIONS = {
        'pending': ['processing'],
        'processing': ['shipped', 'cancelled'],
        'shipped': ['delivered'],
        'cancelled': [],
        'delivered': []
    }
    
    def transition(self, current_state, new_state):
        if new_state not in self.VALID_TRANSITIONS.get(current_state, []):
            raise ValueError(f"Invalid transition: {current_state} → {new_state}")
        
        # Log transition
        log_state_change(current_state, new_state)
        
        return new_state
```

**Privilèges:**
```python
def update_user(user_id, updates):
    # JAMAIS accepter role/privilege depuis input utilisateur
    forbidden_fields = ['role', 'is_admin', 'permissions']
    
    for field in forbidden_fields:
        if field in updates:
            raise ValueError(f"Cannot update {field}")
    
    # Validation stricte
    allowed_fields = ['name', 'email', 'phone']
    filtered_updates = {
        k: v for k, v in updates.items() 
        if k in allowed_fields
    }
    
    db.update_user(user_id, filtered_updates)
```

Testing Business Logic:
```python
# Test cases critiques
def test_price_manipulation():
    # Tentative prix négatif
    response = client.post('/cart/add', {
        'product_id': 123,
        'price': -10  # ❌ Doit être rejeté
    })
    assert response.status_code == 400
    
    # Tentative prix modifié
    response = client.post('/cart/add', {
        'product_id': 123,
        'price': 1  # Au lieu de 99.99
    })
    assert response.status_code == 400
```

Références:
- OWASP Testing for Business Logic
- CWE-840: Business Logic Errors
- OWASP Top 10 API Security (Mass Assignment)
"""


# Test
async def test_business_logic():
    """Test du détecteur"""
    detector = DetecteurBusinessLogic()
    test_url = "http://localhost:8080/api/checkout"
    test_params = {'price': '99.99', 'quantity': '1'}
    
    vulns = await detector.detecter(test_url, test_params)
    print(f"{'✅' if vulns else '❌'} {len(vulns)} vulnérabilités Business Logic trouvées")


if __name__ == "__main__":
    asyncio.run(test_business_logic())
