#!/usr/bin/env python3
"""
Test du filtrage amélioré pour les apps modernes (React/SPA)
"""
import asyncio
import aiohttp
from loguru import logger

logger.remove()
logger.add(lambda msg: print(msg, end=''), colorize=True, format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <level>{message}</level>")

async def filtrer_endpoints_existants_ameliore(urls: list) -> list:
    """
    Version améliorée du filtrage pour les apps modernes
    """
    urls_existantes = []
    url_base = urls[0] if urls else ""

    # Récupérer le contenu de la page principale
    contenu_principal = ""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url_base, timeout=aiohttp.ClientTimeout(total=5)) as response:
                if response.status == 200:
                    contenu_principal = await response.text()
                    print(f"📄 Contenu principal récupéré: {len(contenu_principal)} caractères")
    except Exception as e:
        print(f"❌ Erreur récupération page principale: {e}")

    async with aiohttp.ClientSession() as session:
        for url in urls:
            if url == url_base:
                urls_existantes.append(url)
                print(f"✅ URL principale conservée: {url}")
                continue

            try:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=3),
                    allow_redirects=False
                ) as response:
                    if response.status == 200:
                        contenu = await response.text()

                        # 1. Pages d'erreur classiques
                        indicateurs_erreur = [
                            '404 not found', 'page not found', 'error 404',
                            'file not found', 'does not exist', 'not found',
                            'nginx', 'apache', 'iis', 'server error',
                            'cannot find the page', 'the page you requested',
                            'page unavailable', 'resource not found',
                            'not found', 'error', 'forbidden', 'access denied'
                        ]
                        contient_erreur = any(indicateur in contenu.lower() for indicateur in indicateurs_erreur)

                        # 2. SPA Detection - contenu identique à la page principale
                        contenu_identique_principal = (
                            contenu_principal and
                            contenu.strip() == contenu_principal.strip() and
                            len(contenu.strip()) > 500
                        )

                        # 3. API endpoints
                        est_api_endpoint = any(pattern in url.lower() for pattern in [
                            '/api/', '/rest/', '/graphql', '/v1/', '/v2/', '/v3/',
                            '.json', '.xml', '/data/', '/endpoint'
                        ])

                        # 4. Contenu trop court
                        contenu_trop_court = len(contenu.strip()) < 50

                        # Décision
                        if contient_erreur:
                            print(f"❌ Erreur détectée: {url}")
                        elif contenu_identique_principal and not est_api_endpoint:
                            print(f"❌ SPA routing (contenu identique): {url}")
                        elif contenu_trop_court:
                            print(f"❌ Contenu trop court ({len(contenu.strip())} chars): {url}")
                        else:
                            urls_existantes.append(url)
                            print(f"✅ URL validée: {url} ({len(contenu)} chars)")

                    else:
                        print(f"❌ Status {response.status}: {url}")

            except Exception as e:
                print(f"❌ Erreur: {url} - {e}")

    print(f"\n📊 RÉSULTAT: {len(urls)} URLs testées → {len(urls_existantes)} URLs valides")
    return urls_existantes

async def test_juice_shop_filtrage():
    """Test du filtrage amélioré sur Juice Shop"""

    print("🧪 TEST DU FILTRAGE AMÉLIORÉ - JUICE SHOP")
    print("=" * 60)

    # URLs qui seraient découvertes par le fuzzer
    urls_test = [
        "https://juice-shop.herokuapp.com/",  # Page principale (doit exister)
        "https://juice-shop.herokuapp.com/artists.php",  # PHP sur app React (devrait être exclu)
        "https://juice-shop.herokuapp.com/listproducts.php",  # PHP sur app React (devrait être exclu)
        "https://juice-shop.herokuapp.com/rest/products",  # API (devrait exister)
        "https://juice-shop.herokuapp.com/api",  # API (devrait exister)
        "https://juice-shop.herokuapp.com/admin",  # Routing SPA (devrait être exclu)
        "https://juice-shop.herokuapp.com/login",  # Routing SPA (devrait être exclu)
    ]

    print(f"📋 Test de {len(urls_test)} URLs:")
    for url in urls_test:
        print(f"   {url}")

    print("\n🔍 Analyse en cours...")
    print("-" * 40)

    urls_valides = await filtrer_endpoints_existants_ameliore(urls_test)

    print("\n" + "=" * 60)
    print("🎯 RÉSULTATS ATTENDUS:")
    print("   ✅ https://juice-shop.herokuapp.com/ (page principale)")
    print("   ✅ https://juice-shop.herokuapp.com/rest/products (API)")
    print("   ✅ https://juice-shop.herokuapp.com/api (API)")
    print("   ❌ Tous les .php et routing SPA (contenu identique)")

    print(f"\n🎯 RÉSULTAT OBTENU: {len(urls_valides)} URLs valides")

    if urls_valides:
        print("\nURLs qui seront scannées:")
        for url in urls_valides:
            print(f"   ✅ {url}")
    else:
        print("   ❌ Aucune URL valide trouvée")

    # Vérification que le filtrage a bien exclu les URLs PHP
    urls_php = [url for url in urls_test if url.endswith('.php')]
    urls_php_filtrees = [url for url in urls_valides if url.endswith('.php')]

    print(f"\n🧪 TEST SPÉCIAL:")
    print(f"   URLs PHP testées: {len(urls_php)}")
    print(f"   URLs PHP conservées: {len(urls_php_filtrees)}")

    if len(urls_php_filtrees) == 0:
        print("   ✅ SUCCÈS: Toutes les URLs PHP ont été exclues!")
    else:
        print("   ❌ ÉCHEC: Des URLs PHP ont été conservées")

if __name__ == "__main__":
    asyncio.run(test_juice_shop_filtrage())
