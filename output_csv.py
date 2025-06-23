import csv

from datetime import datetime
from colors import Colors

def output_csv(all_results):
    """
    Exporte toutes les alertes détectées dans un seul fichier CSV,
    avec un nom unique basé sur la date et l’heure du scan.
    """

    # ⏰ Génère un timestamp au format : YYYY-MM-DD_HH-MM
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")

    # 📝 Nom du fichier CSV basé sur le timestamp
    export_name = f"witchyscan_{timestamp}.csv"

    # 📁 Ouvre le fichier en mode écriture (w), avec encodage UTF-8
    with open(export_name, "w", newline='', encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)

        # 🧾 Écrit l’en-tête du tableau CSV
        writer.writerow(["Fichier", "Langage", "Ligne", "Catégorie", "Contenu"])

        # 📦 Parcourt tous les fichiers scannés
        for result in all_results:

            # 🚨 Parcourt toutes les alertes détectées dans ce fichier
            for line_num, category, content in result["alerts"]:

                # 🧙 Écrit une ligne par alerte dans le fichier CSV
                writer.writerow([
                    result["filepath"],     # Chemin complet du fichier scanné
                    result["language"],     # Langage détecté (ex: python, bash, etc.)
                    line_num,               # Numéro de ligne
                    category,               # Type d’alerte détectée
                    content.strip()         # Contenu de la ligne nettoyé
                ])

    # ✅ Message de confirmation à l’écran
    print(Colors.success(f"\n📁 Résultats exportés dans : {export_name}"))

