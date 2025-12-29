"""
Détecteur de vulnérabilités WebSocket
Protocol WS/WSS security testing
"""

import asyncio
import json
from typing import Optional, List, Dict
from loguru import logger
import aiohttp

from core.models import Vulnerabilite


class DetecteurWebSocket:
    """
    Détecte les vulnérabilités WebSocket
    CSRF, injection, lack of authentication, etc.
    """

    def __init__(self, auth_config: Dict = None):
        """
        Initialise le détecteur
        
        Args:
            auth_config: Configuration d'authentification
        """
        self.auth_config = auth_config or {}
        
        # Payloads WebSocket
        self.payloads_ws = [
            # XSS via WebSocket
            '{"message": "<script>alert(1)</script>"}',
            '{"data": "<img src=x onerror=alert(1)>"}',
            
            # SQL Injection via WebSocket
            '{"query": "\' OR 1=1--"}',
            
            # Command injection
            '{"cmd": "; cat /etc/passwd"}',
            
            # JSON injection
            '{"user": {"role": "admin"}}',
        ]

    async def detecter(self, url: str) -> List[Vulnerabilite]:
        """
        Détecte les vulnérabilités WebSocket
        
        Args:
            url: URL de base (sera convertie en ws://)
            
        Returns:
            List[Vulnerabilite]: Vulnérabilités trouvées
        """
        vulnerabilites = []
        
        logger.info(f"🔍 Test WebSocket: {url}")
        
        # Détecter les endpoints WebSocket
        ws_endpoints = await self._discover_websocket_endpoints(url)
        
        for ws_url in ws_endpoints:
            # Test 1: Authentification manquante
            auth_vuln = await self._test_auth_missing(ws_url)
            if auth_vuln:
                vulnerabilites.append(auth_vuln)
            
            # Test 2: CSRF sur WebSocket
            csrf_vuln = await self._test_ws_csrf(ws_url)
            if csrf_vuln:
                vulnerabilites.append(csrf_vuln)
            
            # Test 3: Injection via messages
            injection_vulns = await self._test_ws_injection(ws_url)
            vulnerabilites.extend(injection_vulns)
        
        return vulnerabilites

    async def _discover_websocket_endpoints(self, url: str) -> List[str]:
        """Découvre les endpoints WebSocket"""
        ws_endpoints = []
        
        # Patterns communs
        ws_paths = [
            '/ws',
            '/websocket',
            '/socket.io',
            '/chat',
            '/api/ws',
            '/notifications',
        ]
        
        # Convertir HTTP → WS
        ws_base = url.replace('https://', 'wss://').replace('http://', 'ws://')
        
        for path in ws_paths:
            ws_url = f"{ws_base.rstrip('/')}{path}"
            
            # Vérifier si endpoint existe
            try:
                async with aiohttp.ClientSession() as session:
                    ws = await session.ws_connect(
                        ws_url,
                        timeout=aiohttp.ClientTimeout(total=5)
                    )
                    ws_endpoints.append(ws_url)
                    await ws.close()
                    logger.info(f"✅ WebSocket trouvé: {ws_url}")
            except Exception:
                continue
        
        return ws_endpoints

    async def _test_auth_missing(self, ws_url: str) -> Optional[Vulnerabilite]:
        """Teste l'absence d'authentification"""
        try:
            async with aiohttp.ClientSession() as session:
                # Connexion SANS cookies/tokens
                ws = await session.ws_connect(ws_url)
                
                # Envoyer un message test
                await ws.send_str('{"type": "test"}')
                
                # Recevoir réponse
                msg = await ws.receive(timeout=3)
                
                await ws.close()
                
                # Si connexion réussie sans auth → vulnérable
                if msg.type == aiohttp.WSMsgType.TEXT:
                    return Vulnerabilite(
                        type="WebSocket_No_Auth",
                        severite="HAUTE",
                        url=ws_url,
                        description="WebSocket accessible sans authentification. Permet l'accès non autorisé.",
                        payload="ws.connect(url)",
                        preuve=str(msg.data)[:200],
                        cvss_score=7.5,
                        remediation=self._get_remediation()
                    )
        
        except Exception as e:
            logger.debug(f"Erreur auth WebSocket: {str(e)}")
        
        return None

    async def _test_ws_csrf(self, ws_url: str) -> Optional[Vulnerabilite]:
        """Teste CSRF sur WebSocket"""
        try:
            async with aiohttp.ClientSession() as session:
                # Connexion depuis "origine malveillante"
                headers = {
                    'Origin': 'http://evil.com'
                }
                
                ws = await session.ws_connect(ws_url, headers=headers)
                
                # Si connexion réussie depuis origine externe → CSRF possible
                await ws.send_str('{"action": "test"}')
                msg = await ws.receive(timeout=3)
                await ws.close()
                
                if msg.type == aiohttp.WSMsgType.TEXT:
                    return Vulnerabilite(
                        type="WebSocket_CSRF",
                        severite="HAUTE",
                        url=ws_url,
                        description="WebSocket vulnérable à CSRF. Pas de vérification d'origine.",
                        payload="ws.connect(url, {origin: 'http://evil.com'})",
                        preuve=f"Origin: http://evil.com accepted",
                        cvss_score=7.0,
                        remediation=self._get_remediation()
                    )
        
        except Exception:
            pass
        
        return None

    async def _test_ws_injection(self, ws_url: str) -> List[Vulnerabilite]:
        """Teste injections via messages WebSocket"""
        vulnerabilites = []
        
        try:
            async with aiohttp.ClientSession() as session:
                ws = await session.ws_connect(ws_url)
                
                for payload in self.payloads_ws:
                    try:
                        await ws.send_str(payload)
                        msg = await ws.receive(timeout=2)
                        
                        if msg.type == aiohttp.WSMsgType.TEXT:
                            response = msg.data
                            
                            # Vérifier si payload reflété (XSS)
                            if '<script>' in response or 'alert(1)' in response:
                                vulnerabilites.append(
                                    Vulnerabilite(
                                        type="WebSocket_XSS",
                                        severite="HAUTE",
                                        url=ws_url,
                                        description="XSS via WebSocket messages",
                                        payload=payload,
                                        preuve=response[:200],
                                        cvss_score=7.5,
                                        remediation=self._get_remediation()
                                    )
                                )
                                break
                    
                    except asyncio.TimeoutError:
                        continue
                
                await ws.close()
        
        except Exception as e:
            logger.debug(f"Erreur injection WebSocket: {str(e)}")
        
        return vulnerabilites

    def _get_remediation(self) -> str:
        """Recommandations de remediation"""
        return """
Remediation WebSocket:

1. Authentification obligatoire sur connexion WS
2. Vérifier l'origine (Origin header)
3. Utiliser des tokens (JWT, session)
4. Valider et sanitizer tous les messages
5. Rate limiting sur messages WS
6. TLS obligatoire (wss:// uniquement)
7. CSP connect-src restrictif
8. Logs et monitoring des connexions WS
9. Timeout sur connexions inactives
10. Pas de données sensibles dans messages JSON bruts

Exemple sécurisé (Node.js):
```javascript
const WebSocket = require('ws');
const wss = new WebSocket.Server({ 
    port: 8080,
    verifyClient: (info, callback) => {
        // 1. Vérifier origin
        const origin = info.origin;
        if (!isAllowedOrigin(origin)) {
            callback(false, 401, 'Origin not allowed');
            return;
        }
        
        // 2. Vérifier token dans query
        const token = info.req.url.split('token=')[1];
        if (!verifyToken(token)) {
            callback(false, 401, 'Invalid token');
            return;
        }
        
        callback(true);
    }
});

wss.on('connection', (ws, req) => {
    // 3. Associer session au WS
    ws.userId = extractUserFromToken(req.url);
    
    ws.on('message', (message) => {
        // 4. Valider le message
        try {
            const data = JSON.parse(message);
            
            // 5. Sanitizer
            const cleanData = sanitize(data);
            
            // 6. Traiter
            handleMessage(ws, cleanData);
        } catch (err) {
            ws.send(JSON.stringify({error: 'Invalid message'}));
        }
    });
});
```

CSP pour WebSocket:
```
Content-Security-Policy: connect-src 'self' wss://trusted.com
```

Références:
- OWASP WebSocket Security
- RFC 6455: WebSocket Protocol
"""


# Test
async def test_websocket():
    """Test du détecteur"""
    detector = DetecteurWebSocket()
    test_url = "http://localhost:8080"
    
    vulns = await detector.detecter(test_url)
    print(f"{'✅' if vulns else '❌'} {len(vulns)} vulnérabilités WebSocket trouvées")


if __name__ == "__main__":
    asyncio.run(test_websocket())
