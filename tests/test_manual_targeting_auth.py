import asyncio
from unittest.mock import MagicMock, patch, AsyncMock
from core.scanner_engine import MoteurScanIntelligent
from core.models import DonneesReconnaissance

async def test_manual_targeting_mode():
    """Test that manual targeting mode skips reconnaissance and scans only the target URL"""
    config = {
        'scan_type': 'specific_url',
        'auth': {'cookies': {'session': 'test'}, 'headers': {'Authorization': 'Bearer token'}}
    }
    
    engine = MoteurScanIntelligent(config)
    
    # Mock dependencies
    engine.phase_reconnaissance = AsyncMock()
    engine.phase_detection_vulnerabilites = AsyncMock(return_value=[])
    engine.phase_validation = AsyncMock(return_value=[])
    engine.phase_generation_exploits = AsyncMock()
    engine.phase_chaines_exploit = AsyncMock(return_value=[])
    engine.calculer_score_risque_global = MagicMock(return_value=0.0)
    
    url = "http://example.com/vulnerable.php"
    await engine.scanner_complet(url)
    
    # Verify reconnaissance was skipped (or mocked one wasn't called if logic is correct)
    # Actually, in the code: if scan_type == 'specific_url', it skips phase_reconnaissance
    engine.phase_reconnaissance.assert_not_called()
    
    # Verify detection was called with correct args
    engine.phase_detection_vulnerabilites.assert_called_once()
    call_args = engine.phase_detection_vulnerabilites.call_args
    assert call_args[0][0] == url
    assert call_args[0][1].url_cible == url
    assert call_args[0][1].repertoires == []

async def test_auth_config_propagation():
    """Test that auth config is correctly propagated to modules"""
    auth_config = {'cookies': {'session': 'test'}, 'headers': {'Authorization': 'Bearer token'}}
    config = {
        'scan_type': 'full',
        'auth': auth_config
    }
    
    engine = MoteurScanIntelligent(config)
    
    # Check if modules received the auth config
    assert engine.scanner_sql.auth_config == auth_config
    assert engine.scanner_xss.auth_config == auth_config
    assert engine.api_fuzzer.auth_config == auth_config
    assert engine.decouvreur_params.auth_config == auth_config
    
    # Check if cookies/headers are set in modules
    assert engine.scanner_sql.cookies == auth_config['cookies']
    assert engine.scanner_sql.headers == auth_config['headers']

async def test_api_fuzzer_integration():
    """Test that API fuzzer is initialized and integrated"""
    config = {'modules_cibles': ['api']}
    engine = MoteurScanIntelligent(config)
    
    assert hasattr(engine, 'api_fuzzer')
    assert engine.api_fuzzer is not None

if __name__ == "__main__":
    # Manual run for quick verification
    asyncio.run(test_manual_targeting_mode())
    asyncio.run(test_auth_config_propagation())
    asyncio.run(test_api_fuzzer_integration())
    print("✅ All tests passed!")
