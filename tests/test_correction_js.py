#!/usr/bin/env python3
"""
Test de correction du problème JavaScript dans l'interface web
"""

from main import app

def test_interface_web():
    """Test que l'interface web n'affiche plus le JavaScript en texte brut"""
    print("🧪 Test de l'interface web après correction JavaScript")
    print("=" * 60)

    with app.test_client() as client:
        response = client.get('/')
        content = response.get_data(as_text=True)

        print(f"✅ Page chargée (status: {response.status_code})")

        # Vérifications importantes
        checks = [
            ("JavaScript dans <script>", '<script>' in content and 'getConseilsExploitation' in content),
            ("Balises script équilibrées", (content.count('<script>') + content.count('<script ')) == content.count('</script>')),
            ("Code JS contenu dans script", 'Injectez du code JavaScript:' in content and content.find('Injectez du code JavaScript:') > content.find('<script>') and content.find('Injectez du code JavaScript:') < content.find('</script>', content.find('Injectez du code JavaScript:'))),
            ("Caractères échappés", '&lt;script&gt;' in content and '&quot;XSS&quot;' in content),
            ("Bouton présent", 'Voir les Vulnérabilités Détaillées' in content),
        ]

        for check_name, result in checks:
            status = "✅" if result else "❌"
            print(f"{status} {check_name}")

        print("\n📊 Analyse du contenu :")
        print(f"   • Taille du HTML: {len(content)} caractères")
        print(f"   • Balises <script>: {content.count('<script>')}")
        print(f"   • Fonctions JS: {content.count('function ')}")

        # Vérifier qu'il n'y a pas de texte JavaScript hors des balises script
        script_start = content.find('<script>')
        script_end = content.find('</script>', script_start)

        if script_start != -1 and script_end != -1:
            script_content = content[script_start:script_end + len('</script>')]
            outside_script = content.replace(script_content, '')

            dangerous_patterns = [
                'getConseilsExploitation',
                'Injectez du code JavaScript',
                'Utilisez sqlmap',
                'Échappez toutes les sorties'
            ]

            found_outside = []
            for pattern in dangerous_patterns:
                if pattern in outside_script:
                    found_outside.append(pattern)

            if not found_outside:
                print("✅ Aucun code JavaScript trouvé hors des balises <script>")
            else:
                print(f"❌ Code JavaScript trouvé hors <script>: {found_outside}")
        else:
            print("❌ Structure <script> incorrecte")

        print("\n🎯 Résultat final:")
        if all(result for _, result in checks):
            print("🎉 INTERFACE WEB CORRECTE - Aucun code JavaScript en texte brut !")
            return True
        else:
            print("❌ Problèmes détectés dans l'interface web")
            return False

if __name__ == "__main__":
    test_interface_web()
