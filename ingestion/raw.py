"""Lecture des fichiers de logs texte et gzip."""
from __future__ import annotations

import gzip
import tarfile
from pathlib import Path

from logging_config import get_logger

logger = get_logger("raw")


def toRows(path: str | Path) -> list[str]:
    """Retourne toutes les lignes d'un fichier ou de tous les fichiers d'un dossier.

    Les fichiers gzip sont reconnus par leur extension ou leur signature, ce qui
    permet aussi de lire un auth.log compressé dont le nom n'a pas d'extension.
    Les fichiers invalides sont ignorés sans interrompre l'analyse.
    """
    source = Path(path)
    if not source.exists():
        raise FileNotFoundError(f"Chemin introuvable : {source}")
    files = sorted(p for p in source.iterdir() if p.is_file()) if source.is_dir() else [source]
    rows: list[str] = []
    for file_path in files:
        try:
            if tarfile.is_tarfile(file_path):
                with tarfile.open(file_path, "r:*") as archive:
                    for member in archive.getmembers():
                        if not member.isfile():
                            continue
                        stream = archive.extractfile(member)
                        if stream is not None:
                            with stream:
                                rows.extend(stream.read().decode("utf-8", errors="replace").splitlines(keepends=True))
                continue
            with file_path.open("rb") as probe:
                compressed = file_path.suffix == ".gz" or probe.read(2) == b"\x1f\x8b"
            opener = gzip.open if compressed else open
            with opener(file_path, "rt", encoding="utf-8", errors="replace") as stream:
                rows.extend(stream)
        except (OSError, EOFError, gzip.BadGzipFile) as exc:
            logger.warning("Fichier ignoré (%s): %s", file_path, exc)
    return rows


if __name__ == "__main__":
    print("Lignes lues :", len(toRows("./data")))
