# Log Analyzer

Analyse les logs Linux, en particulier `auth.log`, pour extraire les événements
SSH, leurs adresses IP, les tentatives réussies/échouées, les sources
fréquentes et les IP présentant des échecs répétés. Les résultats comprennent
des exports JSON/CSV et quatre graphiques PNG.

## Installation et configuration

Le projet demande Python 3.13 ou plus récent. Depuis la racine :

```bash
uv sync
cp .env.example .env
```

Ajoutez votre clé IPinfo dans `.env` sous la forme `IPINFO_TOKEN=votre_token`.
Ne partagez pas ce fichier : `.env` est ignoré par Git. Sans clé, toute
l'analyse et les graphiques fonctionnent ; seul l'enrichissement géographique
est omis. Les IP privées, réservées et invalides ne sont jamais envoyées à
IPinfo. Les réponses réussies sont conservées dans `results/ipinfo_cache.json`.
Les requêtes ont un timeout, les réponses 429 sont réessayées brièvement et
jusqu'à quatre IP sont enrichies en parallèle. Une progression est affichée;
une indisponibilité d'IPinfo n'empêche pas la création des rapports.

## Exécution

```bash
uv run python main.py                  # analyse le dossier data/
uv run python main.py auth.log         # analyse un fichier (gzip détecté aussi)
uv run python main.py ./mes-logs --output ./rapport --year 2025
uv run python main.py data --no-enrich # interdit tout appel IPinfo
```

## Dashboard

Le dashboard Streamlit est lancé depuis la racine du projet :

```bash
uv run streamlit run serving/app.py
```

Il utilise les variables `DB_*` définies dans `.env` pour accéder à la base
de données. Le package `storage/` doit être présent dans le dépôt pour que
le dashboard puisse fonctionner ; il fournit la connexion et les requêtes
utilisées par `serving/app.py`.

Les fichiers syslog usuels omettent l'année ; par défaut l'année courante est
ajoutée aux timestamps. Utilisez `--year` pour les archives d'une autre année.
Une IP est signalée comme suspecte à partir de cinq échecs SSH ; modifiez ce
seuil avec `--threshold 10`. Ce critère explicable est un indicateur, pas une
preuve d'activité malveillante.

## Fichiers du rapport

- `summary.json` : compteurs, top IP, échecs et IP suspectes.
- `events.json` et `events.csv` : événements parsés avec message d'origine.
- `ipinfo.json` et `ipinfo_cache.json` : enrichissement et cache local.
- `ipinfo_status.json` : consommation du compte IPinfo (`/me`), indépendante
  des résultats de géolocalisation enregistrés dans `ipinfo.json`.
- `top_ips.png`, `ssh_outcomes.png`, `events_timeline.png`, `geography.png`.

Le graphe géographique affiche les pays renvoyés par IPinfo. En l'absence de
données, il explique pourquoi la visualisation est vide.
Après l'analyse, le terminal affiche les requêtes utilisées aujourd'hui et ce
mois, la limite mensuelle et le solde restant. Avec `--no-enrich`, aucun appel
IPinfo n'est effectué et le statut indique que les requêtes sont désactivées.

## Architecture

- `ingestion/raw.py` lit un fichier ou tous les fichiers d'un dossier, en
  détectant les flux gzip et archives tar, même avec une extension inhabituelle.
- `process/extract_transforme.py` transforme les lignes syslog en événements
  structurés, classe les événements SSH et calcule les statistiques.
- `process/geolocation.py` valide les IP, filtre les IP non publiques, appelle
  IPinfo avec `requests` et fournit les fonctions de cache.
- `main.py` orchestre l'analyse, les exports et les visualisations Matplotlib.
- `serving/app.py` fournit le dashboard Streamlit à partir des analyses
  enregistrées dans la base de données.

Les fichiers invalides sont ignorés avec un avertissement ; un chemin d'entrée
introuvable est signalé comme erreur CLI.
