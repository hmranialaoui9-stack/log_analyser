"""Enrichissement IPinfo avec filtrage des IP non publiques et cache disque."""
from __future__ import annotations

import ipaddress
import json
import os
import time
from pathlib import Path
from typing import Any

import requests


def is_public_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def get_location(ip: str, token: str | None = None, cache: dict[str, Any] | None = None,
                 timeout: float = 8.0) -> dict[str, Any] | None:
    """Retourne les données IPinfo, en mémoire d'abord, puis via l'API.

    Les IP privées, réservées ou invalides sont exclues. L'absence de token
    désactive proprement les requêtes réseau.
    """
    try:
        normalized = str(ipaddress.ip_address(ip))
    except ValueError:
        return None
    if not is_public_ip(normalized):
        return None
    if cache is not None and normalized in cache:
        return cache[normalized]
    api_token = token if token is not None else os.getenv("IPINFO_TOKEN")
    if not api_token:
        return None
    # Un 429 est généralement temporaire. On honore Retry-After lorsqu'il est
    # exploitable, avec une attente bornée pour ne jamais bloquer indéfiniment.
    for attempt in range(3):
        try:
            response = requests.get(
                f"https://ipinfo.io/{normalized}/json",
                params={"token": api_token}, timeout=timeout,
            )
            if response.status_code == 429:
                if attempt == 2:
                    print(f"Avertissement : limite IPinfo atteinte pour {normalized}; IP ignorée.")
                    break
                try:
                    delay = min(5.0, max(0.0, float(response.headers.get("Retry-After", 2 ** attempt))))
                except (TypeError, ValueError):
                    delay = float(2 ** attempt)
                time.sleep(delay)
                continue
            response.raise_for_status()
            result = response.json()
            if not isinstance(result, dict) or result.get("error"):
                print(f"Avertissement : réponse IPinfo invalide pour {normalized}; IP ignorée.")
                break
            result.pop("readme", None)
            if cache is not None:
                cache[normalized] = result
            return result
        except (requests.RequestException, ValueError) as exc:
            print(f"Avertissement : IPinfo indisponible pour {normalized} : {exc}")
            break
    return None


def get_account_status(token: str | None = None, timeout: float = 8.0) -> dict[str, Any]:
    """Récupère les compteurs du compte via l'endpoint officiel /me.

    Les compteurs de compte sont distincts des réponses de géolocalisation
    individuelles. Les erreurs sont rendues sous forme de statut exploitable,
    sans propager d'exception au pipeline d'analyse.
    """
    api_token = token if token is not None else os.getenv("IPINFO_TOKEN")
    if not api_token:
        return {"status": "token_missing", "available": False,
                "message": "IPINFO_TOKEN absent; statistiques de compte indisponibles."}
    try:
        response = requests.get(
            "https://ipinfo.io/me", params={"token": api_token}, timeout=timeout,
        )
        if response.status_code == 429:
            return {"status": "rate_limited", "available": False,
                    "message": "IPinfo a limité la requête de statut (HTTP 429)."}
        if response.status_code in (401, 403):
            return {"status": "invalid_token", "available": False,
                    "message": f"Token IPinfo refusé (HTTP {response.status_code})."}
        response.raise_for_status()
        payload = response.json()
        if isinstance(payload, dict) and payload.get("error"):
            return {"status": "invalid_token", "available": False,
                    "message": "IPinfo a refusé le token ou la requête de statut."}
        requests_info = payload.get("requests") if isinstance(payload, dict) else None
        fields = {"requests_used_today": "day", "requests_used_month": "month",
                  "monthly_limit": "limit", "requests_remaining": "remaining"}
        if not isinstance(requests_info, dict):
            raise ValueError("champ 'requests' manquant dans la réponse IPinfo")
        values: dict[str, int] = {}
        for output_key, api_key in fields.items():
            value = requests_info.get(api_key)
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"champ '{api_key}' invalide dans la réponse IPinfo")
            values[output_key] = value
        return {"status": "ok", "available": True, **values}
    except requests.Timeout:
        return {"status": "timeout", "available": False,
                "message": f"Délai dépassé après {timeout:g} secondes."}
    except requests.HTTPError as exc:
        code = exc.response.status_code if exc.response is not None else "inconnu"
        return {"status": "http_error", "available": False,
                "message": f"Erreur HTTP IPinfo (HTTP {code})."}
    except ValueError as exc:
        return {"status": "invalid_response", "available": False,
                "message": f"Réponse de statut IPinfo invalide : {exc}"}
    except requests.RequestException as exc:
        return {"status": "network_error", "available": False,
                "message": f"Erreur de communication avec IPinfo : {exc}"}


def load_cache(path: str | Path) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def save_cache(path: str | Path, cache: dict[str, Any]) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(cache, indent=2, ensure_ascii=False), encoding="utf-8")


if __name__ == "__main__":
    print("IP publique :", is_public_ip("8.8.8.8"))
