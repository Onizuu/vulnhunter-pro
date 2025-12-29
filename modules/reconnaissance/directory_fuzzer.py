"""
Fuzzer de répertoires et fichiers
"""

import asyncio
from typing import List
from loguru import logger
import aiohttp


class FuzzerRepertoires:
    """
    Découvre les répertoires et fichiers cachés
    """

    def __init__(self):
        # ⭐ AMÉLIORATION: Liste étendue pour découvrir plus d'endpoints
        self.wordlist = [
            # Pages communes vulnérables
            'artists.php', 'listproducts.php', 'listart.php', 'categories.php', 'guestbook.php',
            'products.php', 'product.php', 'showproduct.php', 'items.php', 'item.php',
            'search.php', 'comment.php', 'comments.php', 'contact.php',
            'gallery.php', 'pictures.php', 'showimage.php', 'upload.php',
            'login.php', 'register.php', 'signup.php', 'signin.php',
            'user.php', 'users.php', 'profile.php', 'account.php',
            'cart.php', 'checkout.php', 'order.php', 'orders.php',
            'news.php', 'blog.php', 'post.php', 'posts.php',
            'category.php', 'tag.php', 'tags.php',
            # Admin
            'admin', 'admin.php', 'administrator', 'login', 'api', 'test', 'dev', 'staging', 'backup',
            'config', 'includes', 'uploads', 'images', 'files', 'documents',
            'dashboard', 'panel', 'wp-admin', 'phpmyadmin', 'sql',
            # Fichiers sensibles
            '.git', '.env', '.htaccess', 'robots.txt', 'sitemap.xml',
            'index.php', 'index.html', 'config.php', 'database.php', 'db.php', 'connect.php',
            # Endpoints API courants
            'api.php', 'api', 'rest.php', 'graphql.php', 'v1', 'v2', 'v3'
        ]

    async def fuzzer(self, url: str) -> List[str]:
        """
        Fuzze les répertoires et fichiers
        
        Args:
            url: URL de base
            
        Returns:
            List[str]: Répertoires/fichiers trouvés
        """
        repertoires_trouves = []
        
        try:
            logger.info(f"🔍 Fuzzing répertoires: {url}")
            
            async with aiohttp.ClientSession() as session:
                taches = []
                
                for item in self.wordlist:
                    test_url = f"{url.rstrip('/')}/{item}"
                    taches.append(self._tester_url(session, test_url))
                
                # Exécuter tous les tests en parallèle
                resultats = await asyncio.gather(*taches, return_exceptions=True)
                
                for url_test, resultat in zip(
                    [f"{url.rstrip('/')}/{item}" for item in self.wordlist],
                    resultats
                ):
                    if resultat and not isinstance(resultat, Exception):
                        repertoires_trouves.append(url_test)
                        logger.debug(f"Trouvé: {url_test}")
            
            logger.info(f"✅ {len(repertoires_trouves)} répertoires/fichiers trouvés")
            
            return repertoires_trouves
        
        except Exception as e:
            logger.error(f"Erreur fuzzing: {str(e)}")
            return []

    async def _tester_url(self, session, url: str) -> bool:
        """
        Teste si une URL existe
        """
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=5),
                allow_redirects=False
            ) as response:
                # Considérer 200, 301, 302, 403 comme "trouvé"
                return response.status in [200, 301, 302, 403]
        except:
            return False

