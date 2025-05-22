#!/usr/bin/env python3
import sys
import re
import os

# Dictionnaire des patterns à détecter, classés par langage et catégorie de vulnérabilité
patterns = {
    "php": {
        "Entrée utilisateur": r"\$_(GET|POST|REQUEST|COOKIE|FILES)",  # Superglobales PHP utilisées pour récupérer des données utilisateur
        "Commande système": r"\b(shell_exec|exec|system|passthru|eval|assert|popen|proc_open)\b",  # Fonctions d'exécution de commandes système
        "SQL non préparé": r"(mysqli?_query|->query\s*\()",  # Requêtes SQL non paramétrées (potentiel risque d'injection SQL)
        "Requête SQL brute": r"(mysql_query|mysqli?_query|pg_query|sqlite_query)",  # Fonctions de requêtes SQL brutes
        "Manipulation de fichier": r"\b(fopen|file_put_contents|file_get_contents|unlink|include|require|include_once|require_once)\b",  # Fonctions de gestion des fichiers et inclusion
        "Cryptographie faible": r"\b(md5|sha1)\b",  # Algorithmes cryptographiques considérés faibles
    },
    "python": {
        "Entrée utilisateur": r"\b(input|sys\.argv|argparse\.ArgumentParser|flask\.request|django\.http\.HttpRequest)\b",  # Entrées utilisateur via input ou frameworks web
        "Commande système": r"\b(os\.system|subprocess\.Popen|subprocess\.call|eval|exec|pexpect\.spawn)\b",  # Exécution de commandes système
        "SQL non préparé": r"\b(cursor\.execute|connection\.execute)\b",  # Requêtes SQL non paramétrées (risque d'injection)
        "Requête SQL brute": r"\b(sqlite3\.connect|psycopg2\.connect|MySQLdb\.connect|pymysql\.connect)\b",  # Connexions à des bases de données
        "Manipulation de fichier": r"\b(open|os\.remove|os\.unlink|shutil\.rmtree|os\.rename|tempfile\.NamedTemporaryFile)\b",  # Opérations fichiers
        "Cryptographie faible": r"\b(hashlib\.md5|hashlib\.sha1|md5|sha1)\b",  # Algorithmes cryptographiques faibles
    },
    "bash": {
        "Entrée utilisateur": r"\$[1-9]|\$@|\$#|\$0|\$\*|\$[A-Z_]+",  # Variables d'entrée en bash (arguments, variables d'environnement)
        "Commande système": r"\b(rm\s+-rf|wget|curl|nc|netcat|bash|sh|chmod|chown|dd|mkfs|mount|umount|eval|exec)\b",  # Commandes système potentiellement dangereuses
        "Manipulation de fichier": r"\b(cp|mv|rm|touch|mkdir|rmdir|cat|echo|printf)\b",  # Commandes basiques de manipulation fichiers
        "Cryptographie faible": r"\b(md5sum|sha1sum|openssl md5|openssl sha1)\b",  # Outils cryptographiques faibles
    },
}

# Fonction pour détecter le langage d'un fichier en fonction de son extension
def detect_language(filename):
    ext = filename.lower().split('.')[-1]  # Récupère l'extension du fichier
    if ext == "php":
        return "php"
    elif ext == "py":
        return "python"
    elif ext in ["sh", "bash"]:
        return "bash"
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

        # Variables pour gérer les commentaires multilignes selon langage
        in_multiline_comment = False
        multiline_comment_delim = None
        in_bash_comment_block = False

        # Parcours ligne par ligne
        for i, line in enumerate(lines, 1):
            stripped = line.strip()  # Ligne sans espaces superflus

            # -- Gestion des commentaires multilignes selon langage --

            if language == "php":
                # Début de commentaire multilignes en PHP
                if '/*' in stripped:
                    in_multiline_comment = True
                # Fin de commentaire multilignes en PHP
                if '*/' in stripped:
                    in_multiline_comment = False
                    continue  # Passe à la ligne suivante
                if in_multiline_comment:
                    continue  # Ignore le contenu des commentaires

            elif language == "python":
                # Détection début/fin de commentaires multilignes en Python avec """ ou '''
                if not in_multiline_comment:
                    if stripped.startswith(('"""', "'''")):
                        delim = stripped[:3]
                        # Cas où le commentaire est sur une seule ligne
                        if stripped.count(delim) == 2:
                            continue
                        in_multiline_comment = True
                        multiline_comment_delim = delim
                        continue
                else:
                    if multiline_comment_delim in stripped:
                        in_multiline_comment = False
                        multiline_comment_delim = None
                    continue

            elif language == "bash":
                # Gestion des blocs commentaires en bash (': ' ' ou ": " ")
                if not in_bash_comment_block:
                    if stripped.startswith(": '") or stripped.startswith(': "'):
                        in_bash_comment_block = True
                        continue
                else:
                    if stripped.endswith("'") or stripped.endswith('"'):
                        in_bash_comment_block = False
                        continue
                # Ignorer les commentaires sur une ligne ou les lignes vides
                if stripped.startswith("#") or stripped == "":
                    continue

            # -- Gestion des commentaires simples --

            if language in ["php", "python"]:
                # Ignorer les lignes commençant par // ou # ou vides
                if stripped.startswith("//") or stripped.startswith("#") or stripped == "":
                    continue

            # -- Analyse des motifs dans la ligne --

            for category, pattern in patterns[language].items():
                if re.search(pattern, line):
                    # Ajoute une alerte détectée
                    alerts.append((i, category, line.strip()))
                    alerts_per_category[category] = alerts_per_category.get(category, 0) + 1
                    alerts_per_line[i] = alerts_per_line.get(i, 0) + 1

    # Affichage des résultats d'analyse
    print(f"\n📄 Analyse du fichier ({language}) : {filepath}")
    if not alerts:
        print("✅ Aucun motif suspect détecté.")
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
    # Vérifie que l'utilisateur passe bien un argument (le fichier à analyser)
    if len(sys.argv) != 2:
        print("Usage : python3 vuln_file_revue_v6.py <fichier>")
        sys.exit(1)
    fichier_a_scanner = sys.argv[1]
    scan_file(fichier_a_scanner)
