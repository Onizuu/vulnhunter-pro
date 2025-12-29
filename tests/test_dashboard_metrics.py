from unittest.mock import MagicMock, AsyncMock
from core.scanner_engine import MoteurScanIntelligent
from core.models import Vulnerabilite

async def test_callback_vulnerabilite():
    # Mock callback
    mock_callback = MagicMock()
    
    # Config with callback
    config = {
        'callback_vulnerabilite': mock_callback,
        'ia_active': False
    }
    
    # Initialize engine
    engine = MoteurScanIntelligent(config)
    
    # Create a dummy vulnerability
    vuln = Vulnerabilite(
        type="SQL Injection",
        severite="High",
        description="Test SQLi",
        url="http://test.com",
        payload="' OR 1=1 --"
    )
    
    # Simulate finding a vulnerability (manually adding to list as if scanner found it)
    # Since we can't easily run the full scan in unit test without mocking everything,
    # we'll test the logic by mocking the scanner_sql.scanner to return this vuln
    
    engine.scanner_sql.scanner = AsyncMock(return_value=[vuln])
    
    # Mock all scanners to return empty lists/dicts
    engine.scanner_xss.scanner = AsyncMock(return_value=[])
    engine.api_fuzzer.scanner = AsyncMock(return_value=[])
    engine.decouvreur_params.analyser_page = AsyncMock(return_value={'http://test.com': ['id']})
    engine.scanner_cve.scanner = AsyncMock(return_value=[])
    engine.verif_idor.verifier = AsyncMock(return_value=[])
    engine.analyseur_cors.analyser = AsyncMock(return_value=[])
    engine.analyseur_headers.analyser = AsyncMock(return_value=[])
    engine.detecteur_xxe.detecter = AsyncMock(return_value=[])
    engine.chercheur_rce.chercher = AsyncMock(return_value=[])
    engine.testeur_auth.tester = AsyncMock(return_value=[])
    engine.analyseur_config.analyser = AsyncMock(return_value=[])
    engine.detecteur_csrf.detecter = AsyncMock(return_value=[])
    engine.scanner_upload.scanner = AsyncMock(return_value=[]) # Was tester, is scanner
    # Remove non-existent scanners from init
    # Remove non-existent scanners from init
    # engine.scanner_jwt.analyser = AsyncMock(return_value=[])
    # engine.scanner_lfi.scanner = AsyncMock(return_value=[])
    # engine.scanner_ssrf.scanner = AsyncMock(return_value=[])
    # engine.scanner_nosql.scanner = AsyncMock(return_value=[])
    # engine.scanner_graphql.scanner = AsyncMock(return_value=[])
    # engine.scanner_business.tester = AsyncMock(return_value=[])
    # engine.scanner_ws.tester = AsyncMock(return_value=[])
    
    # Mock _filtrer_endpoints_existants to avoid network calls and filtering
    engine._filtrer_endpoints_existants = AsyncMock(return_value=['http://test.com'])
    
    # Run detection phase (which uses the callback)
    # We need to mock DonneesReconnaissance
    mock_recon = MagicMock()
    mock_recon.endpoints = ['http://test.com']
    mock_recon.repertoires = ['http://test.com']
    mock_recon.urls = ['http://test.com']
    
    # Call phase_detection_vulnerabilites
    await engine.phase_detection_vulnerabilites('http://test.com', mock_recon)
    
    # Verify callback was called
    mock_callback.assert_called()
    args, _ = mock_callback.call_args
    assert args[0].type == "SQL Injection"
    print("✅ Callback verification successful!")

if __name__ == "__main__":
    import asyncio
    asyncio.run(test_callback_vulnerabilite())
