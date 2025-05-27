class Colors:
    RESET = "\033[0m"

    # Couleurs de base
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    # Couleurs en gras
    BOLD_RED = "\033[1;31m"
    BOLD_GREEN = "\033[1;32m"
    BOLD_YELLOW = "\033[1;33m"
    BOLD_BLUE = "\033[1;34m"
    BOLD_MAGENTA = "\033[1;35m"
    BOLD_CYAN = "\033[1;36m"
    BOLD_WHITE = "\033[1;37m"

    # Mapping par niveau de log ou type d'alerte
    @staticmethod
    def info(text):
        return f"{Colors.CYAN}[INFO]{Colors.RESET} {text}"

    @staticmethod
    def success(text):
        return f"{Colors.GREEN}[OK]{Colors.RESET} {text}"

    @staticmethod
    def warning(text):
        return f"{Colors.YELLOW}[WARN]{Colors.RESET} {text}"

    @staticmethod
    def error(text):
        return f"{Colors.RED}[ERROR]{Colors.RESET} {text}"

    @staticmethod
    def critical(text):
        return f"{Colors.BOLD_RED}[CRITICAL]{Colors.RESET} {text}"

    @staticmethod
    def alert(category, text):
        return f"{Colors.BOLD_MAGENTA}[ALERTE: {category}]{Colors.RESET} {text}"

