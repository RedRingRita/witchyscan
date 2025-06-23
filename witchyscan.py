#!/usr/bin/env python3
import sys
import re
import os
import argparse #Pour gérer les arguments en ligne de commande

from patterns import patterns
from ignore_comments import init_comment_state, should_ignore_line
from colors import Colors
from output_csv import output_csv
from output_txt import output_txt
from display import afficher_resultats

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
    parser.add_argument("-o", "--output", choices=["csv", "txt"], help="Format d’export (ex : -o csv/txt)")
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
    afficher_resultats(filepath, language, total_lines, alerts, alerts_per_category, alerts_per_line)
    return {
        "filepath": filepath,
        "language": language,
        "total_lines": total_lines,
        "alerts": alerts,
        "alerts_per_category": alerts_per_category,
        "alerts_per_line": alerts_per_line,
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
    elif output_format == "txt" and all_results:
        output_txt(all_results)
