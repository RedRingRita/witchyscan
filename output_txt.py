from datetime import datetime
from display import afficher_resultats
from colors import Colors

def output_txt(results):
    now = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"witchyscan_{now}.txt"

    with open(filename, "w", encoding="utf-8") as f:
        f.write("🧙 WitchyScan - Rapport d’analyse magique\n")
        f.write("=" * 50 + "\n\n")

        for res in results:
            filepath = res["filepath"]
            total_lines = res["total_lines"]
            alerts = res["alerts"]
            alerts_per_category = res["alerts_per_category"]
            alerts_per_line = res["alerts_per_line"]
            language = res["language"]

            afficher_resultats(filepath, language, total_lines, alerts, alerts_per_category, alerts_per_line, file=f)

    print(Colors.success(f"\n📄 Rapport texte généré dans : {filename}"))
