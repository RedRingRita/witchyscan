from colors import Colors

def afficher_resultats(filepath, language, total_lines, alerts, alerts_per_category, alerts_per_line, file=None):
    """
    Affiche les résultats d'analyse dans le terminal ou dans un fichier texte si "file" est précisé.
    Utilise les couleurs et les icônes définies dans Colors.
    """

    # Fonction interne pour écrire dans le terminal ou le fichier
    def echo(line):
        print(line, file=file)

    echo(f"\n{Colors.MAGENTA}📄 Analyse du fichier ({language}) : {filepath}{Colors.RESET}")
    
    if not alerts:
        echo(f"\n{Colors.GREEN}✅ Aucun motif suspect détecté.{Colors.RESET}")
        return

    for line_num, category, content in alerts:
        echo(f"  [Ligne {line_num:03}] {Colors.alert(category, content)}")

    echo(f"\n{Colors.YELLOW}📊 Statistiques de l’analyse :{Colors.RESET}")
    echo(f"  - Nombre total de lignes : {total_lines}")
    echo(f"  - Nombre total d’alertes détectées : {len(alerts)}")

    echo("  - Répartition des alertes par catégorie :")
    for cat, count in alerts_per_category.items():
        echo(f"    • {cat} : {count}")

    echo("  - Lignes avec le plus d’alertes :")
    top_lines = sorted(alerts_per_line.items(), key=lambda x: x[1], reverse=True)[:5]
    for line_num, count in top_lines:
        echo(f"    • Ligne {line_num} : {count} alertes")

    echo("\n" + "-" * 60 + "\n")

