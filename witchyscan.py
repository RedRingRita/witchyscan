#!/usr/bin/env python3
import sys
import re
import os

from patterns import patterns
from ignore_comments import init_comment_state, should_ignore_line
from colors import Colors

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

# Fonction principale pour scanner un fichier à la recherche de motifs dangereux
def scan_file(filepath):
    # Vérifie si le fichier existe bien
    if not os.path.isfile(filepath):
        print(f"❌ Fichier introuvable : {filepath}")
        return

    alerts = []  # Liste pour stocker les alertes détectées (numéro de ligne, catégorie, contenu)
    alerts_per_category = {}  # Compteur d'alertes par catégorie
    alerts_per_line = {}  # Compteur d'alertes par ligne

    language = detect_language(filepath)  # Détection du langage du fichier
    if not language:
        print(f"⚠️ Langage non reconnu pour le fichier : {filepath}")
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
        print(f"\n{Colors.GREEN} ✅Aucun motif suspect détecté.{Colors.RESET}")
    else:
        for line_num, category, content in alerts:
            print(f"  [Ligne {line_num:03}] [{category}] {content}")

    # -- Statistiques récapitulatives --
    print("\n📊 Statistiques de l’analyse :")
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

# -- Point d'entrée du script --
if __name__ == "__main__":
    afficher_banniere()
    # Vérifie que l'utilisateur passe bien un argument (le fichier à analyser)
    if len(sys.argv) != 2:
        print("Usage : python3 vuln_file_revue_v6.py <fichier>")
        sys.exit(1)
    fichier_a_scanner = sys.argv[1]
    scan_file(fichier_a_scanner)
