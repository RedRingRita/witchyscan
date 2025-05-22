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
