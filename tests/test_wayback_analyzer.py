"""
Test Wayback Machine Analyzer
"""

import asyncio
from modules.reconnaissance.wayback_analyzer import WaybackAnalyzer

def test_wayback_urls():
    """Test découverte d'URLs via Wayback"""
    analyzer = WaybackAnalyzer()
    
    # Test avec un domaine connu
    domain = "testphp.vulnweb.com"
    
    print(f"\n🔍 Test Wayback URLs pour: {domain}\n")
    urls = analyzer.wayback_urls(domain, limit=50)
    
    print(f"✅ {len(urls)} URLs découvertes")
    if urls:
        print("\nPremières URLs:")
        for url in urls[:10]:
            print(f"  - {url}")
    
    return len(urls) > 0

def test_wayback_robots():
    """Test analyse robots.txt historiques"""
    analyzer = WaybackAnalyzer()
    
    domain = "testphp.vulnweb.com"
    
    print(f"\n🤖 Test Wayback robots.txt pour: {domain}\n")
    paths = analyzer.wayback_robots(domain)
    
    print(f"✅ {len(paths)} chemins découverts")
    if paths:
        print("\nChemins trouvés:")
        for path in paths[:15]:
            print(f"  - {path}")
    
    return True

def test_hidden_endpoints():
    """Test recherche d'endpoints sensibles"""
    analyzer = WaybackAnalyzer()
    
    domain = "testphp.vulnweb.com"
    
    print(f"\n🔎 Test Hidden Endpoints pour: {domain}\n")
    results = analyzer.find_hidden_endpoints(domain)
    
    for pattern, urls in results.items():
        if urls:
            print(f"⚠️  Pattern '{pattern}': {len(urls)} URLs")
            for url in urls[:5]:
                print(f"    - {url}")
    
    return True

def test_parameters():
    """Test analyse des paramètres GET"""
    analyzer = WaybackAnalyzer()
    
    domain = "testphp.vulnweb.com"
    
    print(f"\n📊 Test Analyse Paramètres pour: {domain}\n")
    params = analyzer.analyze_parameters(domain)
    
    print(f"✅ {len(params)} paramètres uniques")
    if params:
        print("\nTop 10 paramètres:")
        for param, count in list(params.items())[:10]:
            print(f"  - {param}: {count}x")
    
    return True

if __name__ == "__main__":
    print("=" * 60)
    print("🧪 TEST WAYBACK MACHINE ANALYZER")
    print("=" * 60)
    
    try:
        assert test_wayback_urls(), "Test Wayback URLs échoué"
        assert test_wayback_robots(), "Test Wayback robots échoué"
        assert test_hidden_endpoints(), "Test Hidden Endpoints échoué"
        assert test_parameters(), "Test Parameters échoué"
        
        print("\n" + "=" * 60)
        print("✅ TOUS LES TESTS RÉUSSIS")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n❌ ERREUR: {str(e)}")
        import traceback
        traceback.print_exc()
