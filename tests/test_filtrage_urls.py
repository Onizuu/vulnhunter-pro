#!/usr/bin/env python3
"""
Test du filtrage des URLs pour vérifier que seules les vraies pages sont scannées
"""
import asyncio
import aiohttp
from loguru import logger

logger.remove()
logger.add(lambda msg: print(msg, end=''), colorize=True, format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <level>{message}</level>")

async def filtrer_endpoints_existants(urls: list) -> list:
    """
    Copie de la méthode de filtrage pour test
    """
    urls_existantes = []

    async with aiohttp.ClientSession() as session:
        for url in urls:
            try:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=3),
                    allow_redirects=False
                ) as response:
                    if response.status == 200:
                        contenu = await response.text()
                        contenu_lower = contenu.lower()

                        indicateurs_erreur = [
                            '404 not found', 'page not found', 'error 404',
                            'file not found', 'does not exist', 'not found',
                            'nginx', 'apache', 'iis', 'server error',
                            'cannot find the page', 'the page you requested',
                            'page unavailable', 'resource not found'
                        ]

                        contenu_trop_court = len(contenu.strip()) < 100

                        if not any(indicateur in contenu_lower for indicateur in indicateurs_erreur) and not contenu_trop_court:
                            urls_existantes.append(url)
                            print(f"✅ URL existante: {url}")
                        else:
                            print(f"❌ URL d'erreur exclue: {url}")
                    else:
                        print(f"❌ URL non accessible ({response.status}): {url}")

            except Exception as e:
                print(f"❌ Erreur vérification {url}: {str(e)}")

    return urls_existantes

async def test_juice_shop():
    """Test du filtrage sur Juice Shop"""

    print("🧪 TEST DE FILTRAGE DES URLs - JUICE SHOP")
    print("=" * 50)

    # URLs qui seraient "découvertes" par le fuzzer
    urls_potentiels = [
        "https://juice-shop.herokuapp.com/",  # Page principale (existe)
        "https://juice-shop.herokuapp.com/artists.php",  # N'existe pas
        "https://juice-shop.herokuapp.com/listproducts.php",  # N'existe pas
        "https://juice-shop.herokuapp.com/rest/products",  # API qui existe probablement
        "https://juice-shop.herokuapp.com/api",  # API qui existe probablement
    ]

    print(f"📋 Test de {len(urls_potentiels)} URLs potentiels:")
    for url in urls_potentiels:
        print(f"   {url}")

    print("\n🔍 Filtrage en cours...")
    print("-" * 30)

    urls_existantes = await filtrer_endpoints_existants(urls_potentiels)

    print("\n" + "=" * 50)
    print(f"✅ RÉSULTAT: {len(urls_existantes)}/{len(urls_potentiels)} URLs existent réellement")

    if urls_existantes:
        print("\nURLs qui seront scannées:")
        for url in urls_existantes:
            print(f"   ✅ {url}")
    else:
        print("   ❌ Aucune URL valide trouvée")

    # Test rapide pour voir si Juice Shop répond
    print("\n🌐 Test de connectivité Juice Shop...")
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get("https://juice-shop.herokuapp.com/", timeout=5) as response:
                print(f"✅ Juice Shop accessible (status: {response.status})")
    except Exception as e:
        print(f"❌ Juice Shop inaccessible: {str(e)}")

if __name__ == "__main__":
    asyncio.run(test_juice_shop())
