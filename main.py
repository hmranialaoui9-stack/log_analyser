"""Point d'entrée CLI de Log Analyzer : analyse, enrichissement et rapports."""
from __future__ import annotations

import argparse
import csv
import json
import os
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter
from pathlib import Path

import matplotlib
# Matplotlib écrit un cache de polices ; son répertoire par défaut peut être
# inaccessible dans des environnements verrouillés.
_mpl_cache = Path(tempfile.gettempdir()) / "log-analyzer-matplotlib"
_mpl_cache.mkdir(parents=True, exist_ok=True)
os.environ.setdefault("MPLCONFIGDIR", str(_mpl_cache))
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from logging_config import get_logger

logger = get_logger("main")


def _load_env_file(path: Path = Path(".env")) -> None:
    """Charge les variables KEY=VALUE de .env sans écraser l'environnement."""
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key, value = key.strip(), value.strip().strip("'\"")
            if key and key not in os.environ:
                os.environ[key] = value
    except OSError as exc:
        logger.debug("Fichier d'environnement absent ou illisible (%s): %s", path, exc)


_load_env_file(Path(__file__).resolve().parent / ".env")

from ingestion.raw import toRows
from process.extract_transforme import analyze_rows, summarize
from process.geolocation import get_account_status, get_location, is_public_ip, load_cache, save_cache


def _charts(events: list[dict], stats: dict, enriched: dict[str, dict], output: Path) -> None:
    """Crée les quatre visualisations demandées en PNG."""
    output.mkdir(parents=True, exist_ok=True)
    top = stats["top_ips"]
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.barh([ip for ip, _ in top[::-1]], [n for _, n in top[::-1]], color="#3478a8")
    ax.set(title="Top 10 des IP les plus fréquentes", xlabel="Occurrences", ylabel="Adresse IP")
    fig.tight_layout(); fig.savefig(output / "top_ips.png", dpi=150); plt.close(fig)

    fig, ax = plt.subplots(figsize=(7, 5))
    labels, values = ["Réussies", "Échouées", "Autres SSH"], [stats["successful_logins"], stats["failed_logins"], stats["other_ssh_events"]]
    ax.bar(labels, values, color=["#4c9f70", "#d9534f", "#8a8f98"])
    ax.set(title="Résultats des événements SSH", ylabel="Nombre d'événements")
    fig.tight_layout(); fig.savefig(output / "ssh_outcomes.png", dpi=150); plt.close(fig)

    by_time = Counter(e["timestamp"][:13] for e in events if e["timestamp"])
    fig, ax = plt.subplots(figsize=(11, 5))
    ax.plot(list(sorted(by_time)), [by_time[t] for t in sorted(by_time)], marker=".", linewidth=1)
    ax.set(title="Événements dans le temps (agrégation par heure)", xlabel="Date et heure (année supposée)", ylabel="Événements")
    ax.tick_params(axis="x", labelrotation=45)
    if not by_time:
        ax.text(.5, .5, "Aucun timestamp exploitable", ha="center", va="center", transform=ax.transAxes)
    fig.tight_layout(); fig.savefig(output / "events_timeline.png", dpi=150); plt.close(fig)

    countries = Counter(item.get("country") for item in enriched.values() if item.get("country"))
    fig, ax = plt.subplots(figsize=(9, 5))
    if countries:
        most = countries.most_common(15)[::-1]
        ax.barh([name for name, _ in most], [n for _, n in most], color="#8064a2")
        ax.set(xlabel="IP enrichies", ylabel="Pays", title="Répartition géographique (IPinfo)")
    else:
        ax.text(.5, .5, "Aucune donnée géographique (token absent ou API indisponible)", ha="center", va="center", transform=ax.transAxes)
        ax.set_axis_off()
    fig.tight_layout(); fig.savefig(output / "geography.png", dpi=150); plt.close(fig)


def run(input_path: str = "data", output_path: str = "results", year: int | None = None,
        threshold: int = 5, enrich: bool = True) -> dict:
    """Exécute et exporte une analyse complète ; utilisable aussi depuis Python."""
    output = Path(output_path)
    output.mkdir(parents=True, exist_ok=True)
    rows = toRows(input_path)
    # Le dépôt fournit aussi un auth.log à la racine, distinct des archives data/.
    if input_path == "data" and Path("auth.log").is_file():
        rows.extend(toRows("auth.log"))
    events = analyze_rows(rows, year=year)
    stats = summarize(events, suspicious_threshold=threshold)

    cache_path = output / "ipinfo_cache.json"
    cache = load_cache(cache_path)
    public_ips = sorted({ip for event in events for ip in event["ips"] if is_public_ip(ip)})
    enriched: dict[str, dict] = {}
    if enrich:
        token = os.getenv("IPINFO_TOKEN")
        if not token:
            logger.info("IPinfo désactivé: token absent.")
            print("IPinfo désactivé : token absent; l'analyse continue sans géolocalisation.")
        elif public_ips:
            print(f"Enrichissement IPinfo : 0/{len(public_ips)} IP publiques…", end="", flush=True)
            # Petit pool borné : accélère les centaines d'IP sans ouvrir un
            # nombre excessif de connexions vers le service.
            with ThreadPoolExecutor(max_workers=4) as pool:
                futures = {pool.submit(get_location, ip, token, cache): ip for ip in public_ips}
                for completed, future in enumerate(as_completed(futures), start=1):
                    ip = futures[future]
                    try:
                        result = future.result()
                        if result:
                            enriched[ip] = result
                    except Exception as exc:
                        # Un incident d'enrichissement ne doit pas annuler
                        # l'analyse ni la génération des rapports.
                        logger.exception("Enrichissement ignoré pour %s", ip)
                        print(f"\nAvertissement : enrichissement ignoré pour {ip} : {exc}")
                    print(f"\rEnrichissement IPinfo : {completed}/{len(public_ips)} IP publiques", end="", flush=True)
            print()
        if os.getenv("IPINFO_TOKEN"):
            save_cache(cache_path, cache)
    token = os.getenv("IPINFO_TOKEN")
    if not enrich:
        account_status = {"status": "disabled", "available": False,
                          "message": "Requêtes IPinfo désactivées par --no-enrich."}
    else:
        account_status = get_account_status(token)
    (output / "ipinfo_status.json").write_text(
        json.dumps(account_status, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    stats["enriched_public_ips"] = len(enriched)
    stats["ipinfo_enabled"] = bool(enrich and os.getenv("IPINFO_TOKEN"))
    (output / "summary.json").write_text(json.dumps(stats, indent=2, ensure_ascii=False), encoding="utf-8")
    (output / "events.json").write_text(json.dumps(events, indent=2, ensure_ascii=False), encoding="utf-8")
    (output / "ipinfo.json").write_text(json.dumps(enriched, indent=2, ensure_ascii=False), encoding="utf-8")
    with (output / "events.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(
            stream,
            fieldnames=["timestamp", "category", "outcome", "ips", "user", "invalid_user", "message"],
        )
        writer.writeheader()
        for event in events:
            writer.writerow({**event, "ips": ",".join(event["ips"])})
    _charts(events, stats, enriched, output)
    logger.info(
        "Analyse terminée: %d lignes, %d événements, %d IP uniques.",
        len(rows), stats["total_events"], stats["unique_ips"],
    )
    print(f"Analyse terminée : {len(rows)} lignes, {stats['total_events']} événements, {stats['unique_ips']} IP uniques.")
    print(f"Résultats : {output.resolve()}")
    print("\nStatistiques de consommation du compte IPinfo :")
    if account_status["available"]:
        print(f"  Requêtes aujourd'hui : {account_status['requests_used_today']}")
        print(f"  Requêtes ce mois : {account_status['requests_used_month']}")
        print(f"  Limite mensuelle : {account_status['monthly_limit']}")
        print(f"  Requêtes restantes : {account_status['requests_remaining']}")
    else:
        print(f"  Indisponibles ({account_status['status']}) : {account_status['message']}")
    print("  Détail écrit dans ipinfo_status.json (statistiques du compte, distinctes des IP enrichies).")
    if not stats["ipinfo_enabled"]:
        print("IPinfo désactivé : définissez IPINFO_TOKEN dans .env pour enrichir les IP publiques.")
    return stats


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyse des logs SSH et export des statistiques.")
    parser.add_argument("input", nargs="?", default="data", help="Fichier ou dossier de logs (défaut : data)")
    parser.add_argument("--output", default="results", help="Dossier de sortie (défaut : results)")
    parser.add_argument("--year", type=int, help="Année des logs syslog sans année (défaut : année actuelle)")
    parser.add_argument("--threshold", type=int, default=5, help="Seuil d'échecs SSH pour signaler une IP suspecte")
    parser.add_argument("--no-enrich", action="store_true", help="Désactive les appels IPinfo")
    args = parser.parse_args()
    try:
        run(args.input, args.output, args.year, args.threshold, not args.no_enrich)
    except (FileNotFoundError, NotADirectoryError, PermissionError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
