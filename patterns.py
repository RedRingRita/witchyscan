import re

# Dictionnaire des patterns à détecter, classés par langage et catégorie de vulnérabilité
patterns = {
    "php": {
        "User entry": r"\$_(GET|POST|REQUEST|COOKIE|FILES)",  # Superglobales PHP utilisées pour récupérer des données utilisateur
        "System command": r"\b(shell_exec|exec|system|passthru|eval|assert|popen|proc_open)\b",  # Fonctions d'exécution de commandes système
        "Unprepared statement": r"(mysqli?_query|->query\s*\()",  # Requêtes SQL non paramétrées (potentiel risque d'injection SQL)
        "Raw SQL query": r"(mysql_query|mysqli?_query|pg_query|sqlite_query)",  # Fonctions de requêtes SQL brutes
        "File manipulation": r"\b(fopen|file_put_contents|file_get_contents|unlink|include|require|include_once|require_once)\b",  # Fonctions de gestion des fichiers et inclusion
        "Weak cryptography": r"\b(md5|sha1)\b",  # Algorithmes cryptographiques considérés faibles
        "Readable port": r"socket\.bind\s*\(\s*\(?['\"]?[\d\.]*['\"]?\s*,\s*\d+\)?\s*\)",
        "Hardcoded credential": r"""
            \$                                               # variable PHP
            (password|pass|pwd|secret|token|username|user)   # nom sensible
            \s*=\s*                                          # Le signe = peut être entouré d’espaces (ou non), donc ça matche password=, password =, etc.
            (
                ['"].+?['"]                                  # valeur codée en dur
                |                                            # OU
                (getenv|\$_ENV|\$_SERVER|get_cfg_var)        # var env
                \(\s*['"].+?['"]\s*\)
            )
        """,
        },
    "python": {
        "User entry": r"\b(input|sys\.argv|argparse\.ArgumentParser|flask\.request|django\.http\.HttpRequest)\b",  # Entrées utilisateur via input ou frameworks web
        "System command": r"\b(os\.system|subprocess\.Popen|subprocess\.call|eval|exec|pexpect\.spawn)\b",  # Exécution de commandes système
        "Unprepared statement": r"\b(cursor\.execute|connection\.execute)\b",  # Requêtes SQL non paramétrées (risque d'injection)
        "Raw SQL query": r"\b(sqlite3\.connect|psycopg2\.connect|MySQLdb\.connect|pymysql\.connect)\b",  # Connexions à des bases de données
        "File manipulation": r"\b(open|os\.remove|os\.unlink|shutil\.rmtree|os\.rename|tempfile\.NamedTemporaryFile)\b",  # Opérations fichiers
        "Weak cryptography": r"\b(hashlib\.md5|hashlib\.sha1|md5|sha1)\b",  # Algorithmes cryptographiques faibles
        "Readable port": r"socket\.bind\s*\(\s*\(?['\"]?[\d\.]*['\"]?\s*,\s*\d+\)?\s*\)",
        "Hardcoded credential": r"""
            (?i)       # ignore la casse (PASSWORD, Password, password seront valides)
            ^\s*       # ^ signifie début de ligne, \s* autorise les espaces ou tabulations éventuelles avant la variable.
            (password|pass|pwd|secret|token|username|user)
            \s*=\s*
            (
                ['"][^'"]+['"]
                |
                (os\.getenv|getenv)
                \(\s*['"][^'"]+['"]\s*\)
            )
        """,
        },
    "bash": {
        "User entry": r"\$[1-9]|\$@|\$#|\$0|\$\*|\$[A-Z_]+",  # Variables d'entrée en bash (arguments, variables d'environnement)
        "System command": r"\b(rm\s+-rf|wget|curl|nc|netcat|bash|sh|chmod|chown|dd|mkfs|mount|umount|eval|exec)\b",  # Commandes système potentiellement dangereuses
        "File manipulation": r"\b(cp|mv|rm|touch|mkdir|rmdir|cat|echo|printf)\b",  # Commandes basiques de manipulation fichiers
        "Weak cryptography": r"\b(md5sum|sha1sum|openssl md5|openssl sha1)\b",  # Outils cryptographiques faibles
        "Readable port": r"\b(nc|ncat|socat|ssh|python|ruby|perl)\b[^\n]*(?:-p\s*|\s)(\d+)",
        "Hardcoded credential": r"""
            (?i)
            ^\s*
            (export\s+)?    # Le mot-clé export (avec au moins un espace après) est optionnel
            (password|pass|pwd|secret|token|username|user)
            \s*=\s*
            ['"][^'"]+['"]
        """,
        },
    "html": {
        "Inline JS": r"<script[^>]*>.*?</script>",  # JS directement dans HTML
        "Form insecure": r"<form[^>]*action=['\"]http://",  # formulaire en HTTP
        "Inline event": r"<[^>]+on\w+=['\"]",  # onClick, onLoad, etc.
        "Hardcoded credential": r"(user(name)?|pass(word)?)=['\"]\w+['\"]",  # login/pass codés en dur
        "Meta refresh redirect": r"<meta[^>]*http-equiv=['\"]refresh['\"]",  # redirection automatique
        },
    "javascript": {
        "Eval usage": r"\beval\s*\(",  # usage d'eval
        "Document write": r"document\.write\s*\(",  # document.write
        "InnerHTML": r"\.innerHTML\s*=",  # injection DOM
        "LocalStorage secret": r"localStorage\.setItem\s*\(\s*['\"](token|secret|auth)['\"]",  # secret stocké en localStorage
        "Hardcoded API key": r"(api|auth|token)[\w_]*\s*=\s*['\"][A-Za-z0-9_\-]{16,}['\"]"  # API key en dur
        }
}
