"""Tableau de bord Streamlit alimenté par SQLite."""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
import sys

import pandas as pd
import streamlit as st

# `streamlit run` place parfois seulement `serving/` sur sys.path. Ajouter la
# racine calculée depuis ce fichier rend les packages du dépôt importables,
# quel que soit le répertoire courant de lancement.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
project_root = str(PROJECT_ROOT)
if project_root in sys.path:
    sys.path.remove(project_root)
sys.path.insert(0, project_root)

from storage import get_database
from logging_config import get_logger

logger = get_logger("app")

st.set_page_config(page_title="Log Analyzer | Security Console", page_icon="◈", layout="wide")
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Manrope:wght@400;500;600;700;800&display=swap');
html, body, [class*="css"] { font-family: 'Manrope', sans-serif; }
.stApp { background: radial-gradient(ellipse at 72% -10%, #102a35 0, #0b1118 42%, #080d13 100%); color:#e6edf3; }
[data-testid="stSidebar"] { background:#0c141c; border-right:1px solid #1b2b35; }
.hero { padding: 1.5rem 0 1rem; border-bottom:1px solid #1d3039; margin-bottom:1.5rem; }
.eyebrow { color:#47d7b0; letter-spacing:.16em; font:500 .72rem 'DM Mono',monospace; text-transform:uppercase; }
.hero h1 { font-size:2rem; margin:.35rem 0; color:#f0f6fc; }
.hero p { color:#8da0ad; margin:0; }
.metric { background:linear-gradient(145deg,#111f28,#0d171f); border:1px solid #203540; border-radius:14px; padding:1.1rem 1.2rem; min-height:112px; }
.metric-label { color:#8ca1ad; font-size:.78rem; letter-spacing:.04em; }
.metric-value { color:#f0f6fc; font-size:1.85rem; font-weight:800; margin-top:.25rem; }
.metric-hint { color:#45d6ad; font: .72rem 'DM Mono',monospace; margin-top:.2rem; }
div[data-testid="stDataFrame"] { border:1px solid #203540; border-radius:10px; overflow:hidden; }
section[data-testid="stVerticalBlock"] div[data-testid="stMarkdownContainer"] h2 { padding-top:.6rem; }
</style>
""", unsafe_allow_html=True)


try:
    db = get_database()
    db.connect()
    runs = db.list_runs()
except Exception:
    logger.exception("Impossible de charger les analyses depuis la base")
    st.error("Connexion à SQLite impossible. Vérifiez les permissions du dossier storage/.")
    st.stop()


def database_call(operation, *args, **kwargs):
    """Affiche une erreur exploitable et trace l'exception sans arrêter le serveur."""
    try:
        return operation(*args, **kwargs)
    except Exception:
        logger.exception("Échec d'une lecture du dashboard: %s", operation.__name__)
        st.error("Lecture des données impossible. Consultez logs/app.log.")
        st.stop()
st.sidebar.markdown("### ◈ LOG ANALYZER")
st.sidebar.caption("SECURITY OPERATIONS CONSOLE")
page = st.sidebar.radio("Navigation", ["Dashboard", "Événements", "Analyse IP", "Rapports"])
if runs:
    labels = {f"#{r['id']} · {r['created_at'][:19]} · {r['source']}": r for r in runs}
    selected_label = st.sidebar.selectbox("Analyse", list(labels))
    run = labels[selected_label]
    try:
        summary = json.loads(run["summary_json"])
    except (TypeError, json.JSONDecodeError):
        logger.exception("Résumé illisible pour une analyse")
        summary = {}
        st.warning("Le résumé enregistré est illisible; les événements restent consultables.")
    origin = "SQLite"
else:
    run = None
    summary = {}
    origin = "Aucune analyse enregistrée dans SQLite"

st.markdown(f'<div class="hero"><div class="eyebrow">● SYSTEM ONLINE &nbsp; / &nbsp; {origin}</div><h1>Security Overview</h1><p>Surveillance et analyse des événements d’authentification Linux</p></div>', unsafe_allow_html=True)
if run is None:
    st.info("La base SQLite ne contient aucune analyse. Lancez `uv run python main.py`, puis rechargez la page.")
    st.stop()

if page == "Dashboard":
    run_id = run["id"]
    timeline = database_call(db.get_timeline, run_id)
    outcomes = database_call(db.get_outcome_counts, run_id)
    top_ips = database_call(db.get_top_ips, run_id)
    recent, _ = database_call(db.query_events, run_id, limit=10)
    failed_by_country = database_call(db.get_failed_attempts_by_country, run_id)
    successful_by_user = database_call(db.get_successful_logins_by_user, run_id)
    invalid_attempts, invalid_total = database_call(db.get_invalid_user_attempts, run_id)
    with st.container(horizontal=True):
        st.metric("Logs analysés", f"{run['rows_analyzed']:,}", help="Lignes source de cette analyse", border=True)
        st.metric("IP suspectes", f"{len(summary.get('suspicious_ips', [])):,}", help="IP au-dessus du seuil configuré", border=True)
        st.metric("IP uniques", f"{summary.get('unique_ips', 0):,}", help="Adresses observées", border=True)
        st.metric("Échecs SSH", f"{summary.get('failed_logins', 0):,}", help="Tentatives SSH refusées", border=True)
        st.metric("Utilisateurs invalides", f"{invalid_total:,}", help="Échecs visant un utilisateur inconnu", border=True)
    left, right = st.columns([1.35, 1])
    with left:
        st.subheader("Activité dans le temps")
        st.line_chart(pd.DataFrame({"Événements": timeline}).sort_index(), height=300, color="#47d7b0")
    with right:
        st.subheader("Résultats SSH")
        st.bar_chart(pd.DataFrame.from_dict(outcomes, orient="index", columns=["Événements"]), height=300, color="#43c9aa")
    st.subheader("Sources les plus actives")
    st.bar_chart(pd.DataFrame(top_ips, columns=["IP", "Occurrences"]).set_index("IP"), height=260, color="#48b9d0")
    st.subheader("Événements récents")
    st.dataframe(pd.DataFrame(recent), width="stretch", hide_index=True,
                 alt="Événements récents de l’analyse sélectionnée")

    st.subheader("Sécurité des authentifications")
    country_col, user_col = st.columns(2)
    with country_col:
        st.markdown("**Tentatives SSH échouées par pays**")
        if failed_by_country:
            country_frame = pd.DataFrame(
                [{"Pays": country, "Tentatives échouées": count}
                 for country, count in failed_by_country.items()]
            )
            st.bar_chart(country_frame, x="Pays", y="Tentatives échouées",
                         alt="Tentatives SSH échouées par pays, Unknown regroupe les pays absents")
            st.caption("Les libellés utilisent les codes pays fournis par IPinfo.")
        else:
            st.info("Aucune tentative SSH échouée dans cette analyse.")
    with user_col:
        st.markdown("**Connexions SSH réussies par utilisateur**")
        if successful_by_user:
            st.dataframe(pd.DataFrame(successful_by_user), hide_index=True,
                         alt="Nombre de connexions SSH réussies par utilisateur")
        else:
            st.info("Aucune connexion SSH réussie dans cette analyse.")
    st.markdown("**Échecs avec utilisateur invalide**")
    if invalid_attempts:
        st.dataframe(pd.DataFrame(invalid_attempts), hide_index=True,
                     alt="Horodatage, utilisateur tenté, adresse IP et pays des échecs avec utilisateur invalide")
        if invalid_total > len(invalid_attempts):
            st.caption(f"{len(invalid_attempts):,} détails affichés sur {invalid_total:,} tentatives.")
    else:
        st.info("Aucun échec avec utilisateur invalide enregistré dans cette analyse.")

elif page == "Événements":
    st.subheader("Journal des événements")
    c1, c2, c3 = st.columns([2, 1, 1])
    search = c1.text_input("Recherche", placeholder="IP, utilisateur ou message")
    category = c2.selectbox("Catégorie", ["Toutes", "ssh", "other"])
    outcome = c3.selectbox("Résultat", ["Tous", "success", "failure", "other"])
    page_size = st.selectbox("Lignes par page", [100, 500, 1000, 5000], index=1)
    page_number = st.number_input("Page", min_value=1, value=1, step=1)
    shown, total = database_call(
        db.query_events, run["id"], search,
        "" if category == "Toutes" else category,
        "" if outcome == "Tous" else outcome,
        limit=page_size, offset=(page_number - 1) * page_size,
    )
    frame = pd.DataFrame(shown)
    st.caption(f"Page {page_number} · {len(shown):,} affiché(s) sur {total:,} événement(s) correspondant(s)")
    st.dataframe(frame, width="stretch", hide_index=True, height=520)
    st.download_button("↓ Exporter CSV", frame.to_csv(index=False).encode("utf-8-sig"), "events.csv", "text/csv")
    st.download_button("↓ Exporter JSON", json.dumps(shown, ensure_ascii=False, indent=2).encode("utf-8"), "events.json", "application/json")

elif page == "Analyse IP":
    st.subheader("Renseignement IP et géolocalisation")
    suspects = {x["ip"]: x["failed_attempts"] for x in summary.get("suspicious_ips", [])}
    ip_table = []
    for item in database_call(db.get_ip_stats, run["id"]):
        ip, geo = item["ip"], item["enrichment"]
        ip_table.append({"Adresse IP": ip, "Événements": item["occurrences"], "Échecs": item["failures"], "Suspecte": ip in suspects,
                         "Pays": geo.get("country", "—"), "Ville": geo.get("city", "—"), "Région": geo.get("region", "—"), "Organisation": geo.get("org", "—")})
    frame = pd.DataFrame(ip_table)
    if not frame.empty:
        st.dataframe(frame, width="stretch", hide_index=True)
        countries = Counter(row["Pays"] for row in ip_table if row["Pays"] != "—")
        if countries:
            st.subheader("Répartition géographique")
            st.bar_chart(pd.DataFrame.from_dict(countries, orient="index", columns=["IP"]), color="#a88bff")
    else:
        st.info("Aucune adresse IP détectée dans les événements.")

else:
    st.subheader("Rapports et exports")
    st.json(summary)
    c1, c2 = st.columns(2)
    export_rows, export_total = database_call(db.query_events, run["id"], limit=1_000_000)
    export_events = [{k: v for k, v in row.items() if k != "run_id"} for row in export_rows]
    c1.download_button("Exporter les événements JSON", json.dumps(export_events, ensure_ascii=False, indent=2).encode(), "events.json", "application/json")
    c2.download_button("Exporter les événements CSV", pd.DataFrame(export_events).to_csv(index=False).encode("utf-8-sig"), "events.csv", "text/csv")
    st.caption(f"{export_total:,} événements présents dans cette analyse SQLite.")
