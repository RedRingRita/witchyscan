#!/usr/bin/env python3
import sys
import re
import os
import argparse #Pour gérer les arguments en ligne de commande

from patterns import patterns
from ignore_comments import init_comment_state, should_ignore_line
from colors import Colors
from output_csv import output_csv

def afficher_banniere():
    print(r"""
   \ \        / _)  |          |              ___|                    
    \ \  \   /   |  __|   __|  __ \   |   | \___ \   __|   _` |  __ \ 
     \ \  \ /    |  |    (     | | |  |   |       | (     (   |  |   |
      \_/\_/    _| \__| \___| _| |_| \__, | _____/ \___| \__,_| _|  _|
                                     ____/                            
             🧙 WitchyScan - Scan occulte de code source
""")


# Fonction pour détecter le langage d'un fichier en fonction de son extension
def detect_language(filename):
    ext = filename.lower().split('.')[-1]  # Récupère l'extension du fichier
    if ext == "php":
        return "php"
    elif ext == "py":
        return "python"
    elif ext in ["sh", "bash"]:
        return "bash"
    elif ext in ["html", "htm"]:
        return "html"
    elif ext == "js":
        return "javascript"
    return None  # Langage non reconnu

def parse_args():
    """
    Gère les arguments passés au script via la ligne de commande.
    - target : fichier ou dossier à scanner
    - -o / --output : format d’export (pour l’instant, seulement 'csv')
    """
    parser = argparse.ArgumentParser(description="🔍 WitchyScan - Scanner de code magique")
    parser.add_argument("target", help="Fichier ou dossier à scanner")
    parser.add_argument("-o", "--output", choices=["csv"], help="Format d’export (ex : -o csv)")
    return parser.parse_args()

# Fonction principale pour scanner un fichier à la recherche de motifs dangereux
def scan_file(filepath):
    # Vérifie si le fichier existe bien
    if not os.path.isfile(filepath):
        print(Colors.warning(f"❌ Fichier introuvable : {filepath}"))
        return

    alerts = []  # Liste pour stocker les alertes détectées (numéro de ligne, catégorie, contenu)
    alerts_per_category = {}  # Compteur d'alertes par catégorie
    alerts_per_line = {}  # Compteur d'alertes par ligne

    language = detect_language(filepath)  # Détection du langage du fichier
    if not language:
        print(Colors.warning(f"Langage non reconnu pour le fichier : {filepath}"))
        return

    # Ouverture du fichier en lecture, en ignorant les erreurs d'encodage
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()  # Lecture de toutes les lignes
        total_lines = len(lines)

        comment_state = init_comment_state()

        for i, lineContent in enumerate(lines, start=1):
            if should_ignore_line(lineContent, language, comment_state):
                continue

            # -- Analyse des motifs dans la ligne --

            # Compilation automatique des regex avec re.VERBOSE
            compiled_patterns = {}
            
            for lang, rules in patterns.items():
                compiled_patterns[lang] = {}
                for category, pattern in rules.items():
                    compiled_patterns[lang][category] = re.compile(pattern, re.VERBOSE | re.IGNORECASE)

            for category, pattern in compiled_patterns[language].items():
                if re.search(pattern, lineContent):
                    # Ajoute une alerte détectée
                    alerts.append((i, category, lineContent.strip()))
                    alerts_per_category[category] = alerts_per_category.get(category, 0) + 1
                    alerts_per_line[i] = alerts_per_line.get(i, 0) + 1

    # Affichage des résultats d'analyse
    print(f"\n{Colors.MAGENTA}📄 Analyse du fichier ({language}) : {filepath}{Colors.RESET}")
    if not alerts:
        print(f"\n{Colors.GREEN}✅Aucun motif suspect détecté.{Colors.RESET}")
        print(Colors.error("C'est juste un test"))
    else:
        for line_num, category, content in alerts:
            print(f"  [Ligne {line_num:03}] {Colors.alert(category, content)}")

    # -- Statistiques récapitulatives --
    print(f"\n{Colors.YELLOW}📊 Statistiques de l’analyse :{Colors.RESET}")
    print(f"  - Nombre total de lignes : {total_lines}")
    print(f"  - Nombre total d’alertes détectées : {len(alerts)}")
    print("  - Répartition des alertes par catégorie :")
    for cat, count in alerts_per_category.items():
        print(f"    • {cat} : {count}")

    print("  - Lignes avec le plus d’alertes :")
    # Affiche les 5 lignes avec le plus d'alertes, triées par nombre d'alertes décroissant
    top_lines = sorted(alerts_per_line.items(), key=lambda x: x[1], reverse=True)[:5]
    for line_num, count in top_lines:
        print(f"    • Ligne {line_num} : {count} alertes")
    return {
        "filepath": filepath,
        "language": language,
        "alerts": alerts
    }

# -- Point d'entrée du script --
if __name__ == "__main__":
    afficher_banniere()

    # Récupère les arguments de la ligne de commande
    args = parse_args()
    target_path = args.target
    output_format = args.output

    all_results = []
    
    if os.path.isfile(target_path):
        result = scan_file(target_path)
        if result:
            all_results.append(result)

    elif os.path.isdir(target_path):
        print(Colors.info(f"📁 Dossier détecté : analyse récursive en cours...\n"))
        for root, dirs, files in os.walk(target_path):
            for file in files:
                full_path = os.path.join(root, file)
                if detect_language(full_path):  # on ne scanne que les fichiers reconnus
                    print(f"\n{Colors.BLUE}=== Analyse de : {full_path} ==={Colors.RESET}")
                    result = scan_file(full_path)
                    if result :
                        all_results.append(result)
    else:
        print(Colors.error("Le chemin fourni n’est ni un fichier ni un dossier valide."))

    # Si l’option -o csv a été précisée et qu’on a des résultats → on exporte !
    if output_format == "csv" and all_results:
        output_csv(all_results)
