"""
Détecteur de Clickjacking
X-Frame-Options et CSP frame-ancestors
"""

import asyncio
from typing import Optional, Dict
from loguru import logger
import aiohttp

from core.models import Vulnerabilite


class DetecteurClickjacking:
    """
    Détecte les vulnérabilités Clickjacking
    Vérifie X-Frame-Options et CSP frame-ancestors
    """

    def __init__(self):
        """Initialise le détecteur"""
        pass

    async def detecter(self, url: str) -> Optional[Vulnerabilite]:
        """
        Détecte les vulnérabilités Clickjacking
        
        Args:
            url: URL à tester
            
        Returns:
            Vulnerabilite si trouvée, None sinon
        """
        logger.info(f"🔍 Test Clickjacking: {url}")
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    headers = dict(response.headers)
                    
                    # Vérifier X-Frame-Options
                    x_frame_options = headers.get('X-Frame-Options', '').upper()
                    
                    # Vérifier CSP frame-ancestors
                    csp = headers.get('Content-Security-Policy', '')
                    
                    # Analyser la protection
                    protection_status = self._analyze_protection(
                        x_frame_options, csp
                    )
                    
                    if protection_status['vulnerable']:
                        return Vulnerabilite(
                            type="Clickjacking",
                            severite=protection_status['severite'],
                            url=url,
                            description=protection_status['description'],
                            payload="<iframe src='{url}'></iframe>".format(url=url),
                            preuve=protection_status['preuve'],
                            cvss_score=protection_status['cvss_score'],
                            remediation=self._get_remediation()
                        )
        
        except Exception as e:
            logger.debug(f"Erreur test Clickjacking: {str(e)}")
        
        return None

    def _analyze_protection(
        self, x_frame_options: str, csp: str
    ) -> Dict:
        """Analyse la protection contre clickjacking"""
        
        # Cas 1: Aucune protection
        if not x_frame_options and 'frame-ancestors' not in csp:
            return {
                'vulnerable': True,
                'severite': 'MOYENNE',
                'description': "Aucune protection Clickjacking. X-Frame-Options et CSP frame-ancestors absents.",
                'preuve': "X-Frame-Options: None, CSP frame-ancestors: None",
                'cvss_score': 5.5
            }
        
        # Cas 2: X-Frame-Options faible
        if x_frame_options in ['ALLOW-FROM', 'ALLOWALL']:
            return {
                'vulnerable': True,
                'severite': 'MOYENNE',
                'description': f"Protection Clickjacking faible: X-Frame-Options={x_frame_options}",
                'preuve': f"X-Frame-Options: {x_frame_options}",
                'cvss_score': 4.5
            }
        
        # Cas 3: CSP frame-ancestors permissif
        if 'frame-ancestors' in csp:
            if '*' in csp or 'unsafe' in csp:
                return {
                    'vulnerable': True,
                    'severite': 'BASSE',
                    'description': "CSP frame-ancestors trop permissif (wildcard ou unsafe)",
                    'preuve': f"CSP: {csp[:100]}...",
                    'cvss_score': 3.5
                }
        
        # Pas vulnérable
        return {
            'vulnerable': False,
            'severite': 'INFO',
            'description': 'Protection Clickjacking correcte',
            'preuve': '',
            'cvss_score': 0.0
        }

    def _get_remediation(self) -> str:
        """Recommandations de remediation"""
        return """
Remediation Clickjacking:

1. Implémenter X-Frame-Options: DENY ou SAMEORIGIN
2. Utiliser CSP frame-ancestors (remplace X-Frame-Options)
3. JavaScript framebuster (défense en profondeur)
4. Vérifier sur toutes les pages sensibles
5. Tester avec OWASP Clickjacking tool

Headers recommandés:
```
X-Frame-Options: DENY
Content-Security-Policy: frame-ancestors 'none'
```

Ou pour SAMEORIGIN:
```
X-Frame-Options: SAMEORIGIN
Content-Security-Policy: frame-ancestors 'self'
```

JavaScript framebuster (défense additionnelle):
```html
<style id="antiClickjack">
  body{display:none !important;}
</style>
<script type="text/javascript">
  if (self === top) {
    var antiClickjack = document.getElementById("antiClickjack");
    antiClickjack.parentNode.removeChild(antiClickjack);
  } else {
    top.location = self.location;
  }
</script>
```

Exemples par framework:

**Express.js (Node.js):**
```javascript
const helmet = require('helmet');
app.use(helmet.frameguard({ action: 'deny' }));
```

**Flask (Python):**
```python
@app.after_request
def set_frame_options(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = "frame-ancestors 'none'"
    return response
```

**Spring Boot (Java):**
```java
http.headers().frameOptions().deny();
```

Références:
- OWASP Clickjacking Defense Cheat Sheet
- MDN X-Frame-Options
- CSP frame-ancestors
"""


# Test
async def test_clickjacking():
    """Test du détecteur"""
    detector = DetecteurClickjacking()
    test_url = "https://example.com"
    
    vuln = await detector.detecter(test_url)
    if vuln:
        print(f"✅ Clickjacking trouvé: {vuln.description}")
    else:
        print("❌ Site protégé contre clickjacking")


if __name__ == "__main__":
    asyncio.run(test_clickjacking())
