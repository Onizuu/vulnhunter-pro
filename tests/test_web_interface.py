import asyncio
import json
from unittest.mock import MagicMock, patch
from main import app, moteurs_en_cours
from core.scanner_engine import MoteurScanIntelligent

async def test_pause_resume_logic():
    """Test the pause/resume logic in the scanner engine"""
    print("Testing Pause/Resume Logic...")
    config = {'ia_active': False}
    engine = MoteurScanIntelligent(config)
    
    assert not engine.est_en_pause
    assert engine.pause_event.is_set()
    
    engine.pauser()
    assert engine.est_en_pause
    assert not engine.pause_event.is_set()
    
    engine.reprendre()
    assert not engine.est_en_pause
    assert engine.pause_event.is_set()
    print("✅ Pause/Resume Logic Passed")

def test_api_endpoints():
    """Test the Flask API endpoints for pause/resume"""
    print("Testing API Endpoints...")
    client = app.test_client()
    
    # Mock a running scan
    scan_id = "test-scan-id"
    mock_engine = MagicMock()
    moteurs_en_cours[scan_id] = mock_engine
    
    # Test Pause
    response = client.post(f'/api/scan/pause/{scan_id}')
    assert response.status_code == 200
    assert json.loads(response.data)['status'] == 'success'
    mock_engine.pauser.assert_called_once()
    
    # Test Resume
    response = client.post(f'/api/scan/resume/{scan_id}')
    assert response.status_code == 200
    assert json.loads(response.data)['status'] == 'success'
    mock_engine.reprendre.assert_called_once()
    
    # Test Invalid ID
    response = client.post('/api/scan/pause/invalid-id')
    assert response.status_code == 404
    
    print("✅ API Endpoints Passed")

if __name__ == "__main__":
    # Run async test
    asyncio.run(test_pause_resume_logic())
    # Run sync test
    test_api_endpoints()
    print("🚀 All Web Interface Tests Passed!")
