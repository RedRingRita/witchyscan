Projet à but éducatif.

Cet outil a été conçu pour accélérer les revues de code en détectant automatiquement des patterns de code potentiellement vulnérables dans des fichiers PHP, Python et Bash.

Plutôt que de lire des centaines de lignes à la main, ce script identifie les portions de code sensibles pour vous aider à focaliser votre attention au bon endroit. Idéal pour gagner du temps, améliorer votre rigueur ou simplement éviter de passer à côté d’un appel système mal placé.

Fonctionnalités
  - Prise en charge automatique de l’extension de fichier (.py, .php, .sh, etc.)
  - Détection de plusieurs patterns à risque par langage (injection, exécution arbitraire, fichiers sensibles, etc.)
  - Affichage coloré en ligne de commande pour une lecture rapide
  - Affichage de statistiques de détection en fin de scan (et oui, tout le monde aime les stats)


Fonctionnalités à venir
  - Analyse récursive de dossiers
  - Export des résultats (CSV, JSON…)
  - Paramètres personnalisables (choix des patterns, verbosité, filtres...)

Cet outil n’a pas vocation à remplacer un scanner de sécurité professionnel, mais plutôt à faire un pré-tri intelligent dans le code, servir de checklist rapide pour les relectures manuelles.

![2025-05-30 16_45_34-ParrotOS_RRR  En fonction  - Oracle VirtualBox](https://github.com/user-attachments/assets/6bf0a79e-37e8-4984-a5dd-31c448d450b8)
# witchyscan
Scanner de vulnérabilité potentiel de code source

Ce scan lit les fichier php, python et bash pour y trouver les lignes où il détecte des patterns de code potentiellement vulnérable.
C'est un outils permettant d'accélerer la revue de code ou pour vous aider dans cette tâche.

Il détecte automatique le type de fichier (via son exntesion) qu'on lui met en paramètre et affiche les statistiques récoltées (tout le monde aime les statistiques).
