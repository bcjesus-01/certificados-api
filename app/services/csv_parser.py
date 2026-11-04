"""Parser de CSV de participantes, 100% em memória (``bytes`` -> ``StringIO`` -> ``DictReader``).

Aceita UTF-8 (com ou sem BOM) e, como alternativa, Windows-1252 (padrão do Excel no Brasil);
detecta o delimitador (``,`` ``;`` ou tab). Cabeçalhos são normalizados (sem acento, minúsculos)
e aliases comuns em português são reconhecidos. Colunas desconhecidas viram ``extra_metadata``.
"""

from __future__ import annotations

import csv
import io
import re
import unicodedata
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from app.schemas.issuance import ParticipantInput

_REQUIRED_COLUMN = "recipient_name"
_KNOWN_COLUMNS = frozenset({"recipient_name", "recipient_doc", "role"})
_ALIASES: dict[str, str] = {
    "nome": "recipient_name",
    "nome_completo": "recipient_name",
    "participante": "recipient_name",
    "name": "recipient_name",
    "cpf": "recipient_doc",
    "documento": "recipient_doc",
    "doc": "recipient_doc",
    "matricula": "recipient_doc",
    "papel": "role",
    "funcao": "role",
    "categoria": "role",
}
_DOC_PREFIX: dict[str, str] = {"matricula": "Mat. "}
_DELIMITERS = (",", ";", "\t")
_MAX_ERRORS = 50
_MAX_EXTRA_VALUE_CHARS = 500
_NON_ALNUM_RE = re.compile(r"[^a-z0-9]+")


class CsvFormatError(Exception):
    """CSV inválido (estrutura, colunas ou linhas). ``errors`` não ecoa valores pessoais."""

    def __init__(self, message: str, errors: list[dict[str, str]] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.errors = errors or []


@dataclass(frozen=True, slots=True)
class ParsedCsv:
    participants: list[ParticipantInput]
    locations: list[str]
    delimiter: str
    encoding: str


def _normalize_header(header: str) -> str:
    folded = unicodedata.normalize("NFKD", header.strip().casefold())
    ascii_only = "".join(char for char in folded if not unicodedata.combining(char))
    return _NON_ALNUM_RE.sub("_", ascii_only).strip("_")


def _decode(raw: bytes) -> tuple[str, str]:
    try:
        return raw.decode("utf-8-sig"), "utf-8"
    except UnicodeDecodeError:
        pass
    try:
        return raw.decode("cp1252"), "cp1252"
    except UnicodeDecodeError:
        raise CsvFormatError("Codificação não reconhecida: salve o CSV como UTF-8") from None


def _detect_delimiter(text: str) -> str:
    first_line = next((line for line in text.splitlines() if line.strip()), "")
    counts = {delimiter: first_line.count(delimiter) for delimiter in _DELIMITERS}
    best = max(_DELIMITERS, key=lambda delimiter: counts[delimiter])
    return best if counts[best] > 0 else ","


def parse_participants_csv(raw: bytes, *, max_rows: int) -> ParsedCsv:
    """Converte o conteúdo do CSV em participantes validados (estritamente: qualquer erro rejeita)."""
    if not raw.strip():
        raise CsvFormatError("O arquivo CSV está vazio")
    if b"\x00" in raw:
        raise CsvFormatError("O arquivo não parece ser um CSV de texto")

    text, encoding = _decode(raw)
    delimiter = _detect_delimiter(text)
    reader = csv.DictReader(io.StringIO(text, newline=""), delimiter=delimiter, strict=True)

    try:
        original_headers = list(reader.fieldnames or [])
    except csv.Error:
        raise CsvFormatError("Não foi possível ler o cabeçalho do CSV") from None
    if not original_headers:
        raise CsvFormatError("O CSV não possui cabeçalho")

    names: list[str] = []
    doc_prefix = ""
    for position, header in enumerate(original_headers):
        normalized = _normalize_header(header)
        if not normalized:
            names.append(f"_unnamed_{position}")  # coluna sem nome (ex.: delimitador sobrando)
            continue
        target = _ALIASES.get(normalized, normalized)
        if target == "recipient_doc" and normalized in _DOC_PREFIX:
            doc_prefix = _DOC_PREFIX[normalized]
        names.append(target)

    duplicated = sorted({name for name in names if names.count(name) > 1})
    if duplicated:
        raise CsvFormatError(f"Colunas duplicadas no cabeçalho: {', '.join(duplicated)}")
    if _REQUIRED_COLUMN not in names:
        found = ", ".join(name for name in names if not name.startswith("_unnamed_")) or "nenhuma"
        raise CsvFormatError(
            "Coluna obrigatória ausente: 'recipient_name' (aliases aceitos: nome, nome_completo, "
            f"participante). Colunas encontradas: {found}"
        )
    reader.fieldnames = names

    participants: list[ParticipantInput] = []
    locations: list[str] = []
    errors: list[dict[str, str]] = []
    try:
        for row in reader:
            line = reader.line_num
            values = {key: value for key, value in row.items() if key is not None}
            if all(not (value or "").strip() for value in values.values()) and None not in row:
                continue
            if len(participants) + len(errors) >= max_rows:
                raise CsvFormatError(f"O CSV excede o limite de {max_rows} participantes")
            location = f"linha {line}"
            if None in row:
                errors.append({"location": location, "field": "-", "message": "linha com mais colunas que o cabeçalho"})
                continue

            doc = (values.get("recipient_doc") or "").strip()
            extra: dict[str, Any] = {
                key: value.strip()[:_MAX_EXTRA_VALUE_CHARS]
                for key, value in values.items()
                if key not in _KNOWN_COLUMNS and not key.startswith("_unnamed_")
                and value and value.strip()
            }
            try:
                participants.append(
                    ParticipantInput(
                        recipient_name=(values.get("recipient_name") or "").strip(),
                        recipient_doc=f"{doc_prefix}{doc}" if doc else None,
                        role=(values.get("role") or "").strip() or None,
                        extra_metadata=extra,
                    )
                )
                locations.append(location)
            except ValidationError as exc:
                for error in exc.errors(include_url=False, include_context=False, include_input=False):
                    errors.append(
                        {"location": location, "field": ".".join(str(p) for p in error["loc"]), "message": error["msg"]}
                    )
            if len(errors) >= _MAX_ERRORS:
                break
    except csv.Error as exc:
        raise CsvFormatError(f"CSV malformado na linha {reader.line_num}: {exc}") from None

    if errors:
        raise CsvFormatError("Há linhas inválidas no CSV", errors[:_MAX_ERRORS])
    if not participants:
        raise CsvFormatError("O CSV não contém participantes")
    return ParsedCsv(participants=participants, locations=locations, delimiter=delimiter, encoding=encoding)
