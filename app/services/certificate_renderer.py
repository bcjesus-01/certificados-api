"""Motor de renderização do certificado (ReportLab, A4 paisagem) 100% em RAM.

Segurança: todo texto vindo do usuário é normalizado para a codificação WinAnsi
(acentos do português preservados) e escapado antes de entrar em ``Paragraph``,
o que impede injeção de marcação do ReportLab (ex.: ``<img src="file:///...">``).
"""

from __future__ import annotations

import asyncio
import io
import logging
import re
import unicodedata
from dataclasses import dataclass
from typing import TYPE_CHECKING
from uuid import uuid4
from xml.sax.saxutils import escape

from reportlab.lib.colors import Color, HexColor
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.utils import ImageReader
from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import Paragraph

from app.schemas.certificate import CertificateRenderData
from app.services.qr import build_validation_url, generate_qr_png

if TYPE_CHECKING:
    from app.core.config import Settings

logger = logging.getLogger(__name__)

PAGE_WIDTH, PAGE_HEIGHT = landscape(A4)

_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_FONT = "Helvetica"
_FONT_BOLD = "Helvetica-Bold"
_MONO = "Courier"
_MONO_BOLD = "Courier-Bold"


class RenderError(Exception):
    """Falha ao renderizar o certificado."""


@dataclass(frozen=True, slots=True)
class CertificateBranding:
    """Identidade institucional do cabeçalho (ajuste conforme a instituição)."""

    institution_name: str = "Centro Acadêmico de Ciência da Computação (CACIC)"
    institution_subtitle: str = "Universidade Estadual de Santa Cruz — UESC"
    primary_color: str = "#1F3A5F"
    accent_color: str = "#B08D2E"


_TRANSLITERATION = str.maketrans(
    {"Ł": "L", "ł": "l", "Đ": "D", "đ": "d", "Ħ": "H", "ħ": "h", "ı": "i"}
)


def _pdf_safe(text: str) -> str:
    """Normaliza para WinAnsi (cp1252): mantém acentos, degrada o que a fonte não tem."""
    text = _CONTROL_RE.sub("", unicodedata.normalize("NFC", text).translate(_TRANSLITERATION))
    text = " ".join(text.split())
    result: list[str] = []
    for char in text:
        try:
            char.encode("cp1252")
            result.append(char)
        except UnicodeEncodeError:
            folded = unicodedata.normalize("NFKD", char).encode("ascii", "ignore").decode("ascii")
            if folded:
                result.append(folded)
            elif unicodedata.category(char) not in ("Cf", "Mn", "Me"):
                result.append("?")
    return "".join(result)


def _markup(text: str) -> str:
    return escape(_pdf_safe(text))


def _style(
    name: str,
    font: str,
    size: float,
    color: Color,
    *,
    align: int = TA_CENTER,
    leading_factor: float = 1.3,
    word_wrap: str | None = None,
) -> ParagraphStyle:
    return ParagraphStyle(
        name=name,
        fontName=font,
        fontSize=size,
        leading=size * leading_factor,
        textColor=color,
        alignment=align,
        wordWrap=word_wrap,
    )


def _fit_paragraph(
    markup: str,
    *,
    name: str,
    font: str,
    color: Color,
    width: float,
    max_height: float,
    start_size: float,
    min_size: float,
    align: int = TA_CENTER,
    leading_factor: float = 1.3,
    word_wrap: str | None = None,
) -> tuple[Paragraph, float]:
    """Reduz a fonte até o texto (com quebra de linha) caber em ``max_height``."""
    size = start_size
    while True:
        paragraph = Paragraph(
            markup,
            _style(name, font, size, color, align=align, leading_factor=leading_factor, word_wrap=word_wrap),
        )
        _, height = paragraph.wrap(width, 10_000)
        if height <= max_height:
            return paragraph, height
        if size - 0.5 < min_size:
            raise RenderError(f"Texto longo demais para o campo '{name}'")
        size -= 0.5


class CertificateRenderer:
    """Desenha o certificado em A4 paisagem e devolve um ``BytesIO`` rebobinado."""

    # Geometria (pontos). Rodapé: caixa de autenticidade; corpo: entre título e rodapé.
    _FOOTER_X = 44.0
    _FOOTER_Y = 40.0
    _FOOTER_H = 108.0
    _QR_SIZE = 92.0
    _BODY_SIDE_MARGIN = 80.0

    def __init__(
        self,
        validation_base_url: str,
        branding: CertificateBranding | None = None,
        *,
        compress: bool = True,
    ) -> None:
        build_validation_url(validation_base_url, uuid4())  # falha rápida se a base for inválida
        self._base_url = validation_base_url
        self._branding = branding or CertificateBranding()
        self._compress = compress
        self._primary = HexColor(self._branding.primary_color)
        self._accent = HexColor(self._branding.accent_color)
        self._ink = HexColor("#2B2B2B")
        self._muted = HexColor("#5A6270")

    @classmethod
    def from_settings(
        cls, settings: "Settings | None" = None, branding: CertificateBranding | None = None
    ) -> "CertificateRenderer":
        from app.core.config import get_settings

        resolved = settings or get_settings()
        return cls(resolved.public_validation_base_url, branding)

    # ------------------------------------------------------------------
    # API pública
    # ------------------------------------------------------------------
    def verification_url(self, data: CertificateRenderData) -> str:
        return build_validation_url(self._base_url, data.cert_uuid)

    def render(self, data: CertificateRenderData) -> io.BytesIO:
        """Renderiza o PDF (1 página) em memória, com o cursor em 0."""
        url = self.verification_url(data)
        qr_png = generate_qr_png(url)
        buffer = io.BytesIO()
        try:
            self._draw(buffer, data, url, qr_png)
        except RenderError:
            raise
        except Exception as exc:  # noqa: BLE001 - encapsula erros internos do ReportLab
            logger.error("Falha ao renderizar certificado: %s", type(exc).__name__)
            raise RenderError("Falha ao renderizar o certificado") from exc
        buffer.seek(0)
        return buffer

    async def render_async(self, data: CertificateRenderData) -> io.BytesIO:
        """Versão assíncrona: executa o desenho (CPU) em uma thread."""
        return await asyncio.to_thread(self.render, data)

    # ------------------------------------------------------------------
    # Desenho
    # ------------------------------------------------------------------
    def _draw(
        self,
        buffer: io.BytesIO,
        data: CertificateRenderData,
        url: str,
        qr_png: io.BytesIO,
    ) -> None:
        canvas = Canvas(
            buffer,
            pagesize=landscape(A4),
            pageCompression=1 if self._compress else 0,
        )
        canvas.setTitle(f"Certificado - {_pdf_safe(data.recipient_name)}")
        canvas.setAuthor(_pdf_safe(self._branding.institution_name))
        canvas.setSubject(_pdf_safe(data.event_name)[:200])
        canvas.setCreator("certificados-api")
        canvas.setKeywords(f"certificado, {data.cert_uuid}")

        self._draw_frame(canvas)
        self._draw_header(canvas)
        self._draw_title(canvas)
        self._draw_body(canvas, data)
        self._draw_footer(canvas, data, url, qr_png)

        canvas.showPage()
        canvas.save()

    def _draw_frame(self, canvas: Canvas) -> None:
        canvas.setStrokeColor(self._primary)
        canvas.setLineWidth(3)
        canvas.rect(18, 18, PAGE_WIDTH - 36, PAGE_HEIGHT - 36, stroke=1, fill=0)
        canvas.setStrokeColor(self._accent)
        canvas.setLineWidth(0.8)
        canvas.rect(26, 26, PAGE_WIDTH - 52, PAGE_HEIGHT - 52, stroke=1, fill=0)
        canvas.setFillColor(self._accent)
        for x, y in (
            (26, 26), (PAGE_WIDTH - 26, 26), (26, PAGE_HEIGHT - 26), (PAGE_WIDTH - 26, PAGE_HEIGHT - 26)
        ):
            canvas.rect(x - 5, y - 5, 10, 10, stroke=0, fill=1)

    @staticmethod
    def _spaced_width(text: str, font: str, size: float, char_space: float) -> float:
        return stringWidth(text, font, size) + char_space * max(len(text) - 1, 0)

    def _draw_centered_spaced(
        self,
        canvas: Canvas,
        text: str,
        y: float,
        font: str,
        size: float,
        char_space: float,
        color: Color,
        max_width: float,
    ) -> None:
        text = _pdf_safe(text)
        while size > 7 and self._spaced_width(text, font, size, char_space) > max_width:
            size -= 0.5
        width = self._spaced_width(text, font, size, char_space)
        # O espaçamento entre caracteres (Tc) faz parte do estado gráfico e persistiria
        # nos textos seguintes: isolamos em save/restore e zeramos ao final.
        canvas.saveState()
        text_object = canvas.beginText((PAGE_WIDTH - width) / 2, y)
        text_object.setFont(font, size)
        text_object.setFillColor(color)
        text_object.setCharSpace(char_space)
        text_object.textOut(text)
        text_object.setCharSpace(0)
        canvas.drawText(text_object)
        canvas.restoreState()

    def _draw_header(self, canvas: Canvas) -> None:
        max_width = PAGE_WIDTH - 2 * self._BODY_SIDE_MARGIN
        self._draw_centered_spaced(
            canvas, self._branding.institution_name.upper(), PAGE_HEIGHT - 60,
            _FONT_BOLD, 14, 1.2, self._primary, max_width,
        )
        self._draw_centered_spaced(
            canvas, self._branding.institution_subtitle, PAGE_HEIGHT - 76,
            _FONT, 10, 0.4, self._muted, max_width,
        )

    def _draw_title(self, canvas: Canvas) -> None:
        self._draw_centered_spaced(
            canvas, "CERTIFICADO", PAGE_HEIGHT - 130, _FONT_BOLD, 44, 10, self._primary,
            PAGE_WIDTH - 2 * self._BODY_SIDE_MARGIN,
        )
        y = PAGE_HEIGHT - 150
        center = PAGE_WIDTH / 2
        canvas.setStrokeColor(self._accent)
        canvas.setLineWidth(1.2)
        canvas.line(center - 110, y, center - 12, y)
        canvas.line(center + 12, y, center + 110, y)
        canvas.setFillColor(self._accent)
        canvas.rect(center - 4, y - 4, 8, 8, stroke=0, fill=1)

    def _draw_body(self, canvas: Canvas, data: CertificateRenderData) -> None:
        width = PAGE_WIDTH - 2 * self._BODY_SIDE_MARGIN
        left = self._BODY_SIDE_MARGIN
        top = PAGE_HEIGHT - 170
        bottom = self._FOOTER_Y + self._FOOTER_H + 16
        available = top - bottom

        blocks: list[tuple[Paragraph, float, float]] = []  # (parágrafo, altura, espaço depois)

        intro, intro_h = _fit_paragraph(
            "Certificamos que", name="intro", font=_FONT, color=self._ink,
            width=width, max_height=24, start_size=14, min_size=14,
        )
        blocks.append((intro, intro_h, 4))

        name, name_h = _fit_paragraph(
            _markup(data.recipient_name), name="recipient", font=_FONT_BOLD, color=self._primary,
            width=width, max_height=76, start_size=34, min_size=11, leading_factor=1.2,
        )
        blocks.append((name, name_h, 2))

        if data.recipient_doc:
            doc, doc_h = _fit_paragraph(
                f"Documento: {_markup(data.recipient_doc)}", name="doc", font=_FONT, color=self._muted,
                width=width, max_height=18, start_size=11, min_size=8,
            )
            blocks.append((doc, doc_h, 12))
        else:
            blocks[-1] = (name, name_h, 12)

        body_markup = (
            f"participou, na condição de <b>{_markup(data.role)}</b>, "
            f"do evento <b>{_markup(data.event_name)}</b>, "
            f"realizado em <b>{_markup(data.event_date)}</b>, "
            f"com carga horária total de <b>{_markup(data.workload_label)}</b>."
        )
        body, body_h = _fit_paragraph(
            body_markup, name="body", font=_FONT, color=self._ink,
            width=width, max_height=112, start_size=16, min_size=10, leading_factor=1.45,
        )
        blocks.append((body, body_h, 0))

        total = sum(height + gap for _, height, gap in blocks)
        if total > available:
            raise RenderError("O conteúdo não cabe na área do corpo do certificado")

        y = top - (available - total) / 2
        for paragraph, height, gap in blocks:
            y -= height
            paragraph.wrapOn(canvas, width, height)
            paragraph.drawOn(canvas, left, y)
            y -= gap

    def _draw_footer(
        self,
        canvas: Canvas,
        data: CertificateRenderData,
        url: str,
        qr_png: io.BytesIO,
    ) -> None:
        x0, y0, height = self._FOOTER_X, self._FOOTER_Y, self._FOOTER_H
        box_width = PAGE_WIDTH - 2 * x0
        canvas.setFillColor(HexColor("#F4F6F9"))
        canvas.setStrokeColor(HexColor("#C9D1DC"))
        canvas.setLineWidth(0.8)
        canvas.roundRect(x0, y0, box_width, height, 4, stroke=1, fill=1)

        qr_x, qr_y = x0 + 10, y0 + (height - self._QR_SIZE) / 2
        qr_png.seek(0)
        canvas.drawImage(
            ImageReader(qr_png), qr_x, qr_y, width=self._QR_SIZE, height=self._QR_SIZE,
            preserveAspectRatio=True,
        )

        text_x = qr_x + self._QR_SIZE + 14
        text_w = x0 + box_width - 10 - text_x
        gap = 3.0
        stack_top = y0 + height - 8
        available = height - 16

        heading, heading_h = _fit_paragraph(
            "AUTENTICIDADE E VERIFICAÇÃO", name="f-head", font=_FONT_BOLD, color=self._primary,
            width=text_w, max_height=14, start_size=9, min_size=9, align=TA_LEFT,
        )
        code, code_h = _fit_paragraph(
            f'Código de verificação (UUID v4): <font name="{_MONO_BOLD}">{data.cert_uuid}</font>',
            name="f-code", font=_FONT, color=self._ink, width=text_w, max_height=18,
            start_size=9, min_size=7, align=TA_LEFT,
        )
        link, link_h = _fit_paragraph(
            f'Consulta pública: <font name="{_MONO}">{escape(url)}</font>',
            name="f-url", font=_FONT, color=self._ink, width=text_w, max_height=26,
            start_size=9, min_size=6.5, align=TA_LEFT, word_wrap="CJK",
        )
        note_text = (
            "Documento assinado digitalmente no padrão PAdES. A autenticidade e a integridade "
            "binária deste arquivo podem ser verificadas no portal público, informando o código "
            "acima, lendo o QR Code ou enviando este PDF para conferência. "
            f"Emitido em {data.issued_at_label}."
        )
        note_max = available - (heading_h + code_h + link_h) - 3 * gap
        if note_max < 14:
            raise RenderError("Rodapé de autenticidade sem espaço para a nota técnica")
        note, note_h = _fit_paragraph(
            escape(_pdf_safe(note_text)), name="f-note", font=_FONT, color=self._muted,
            width=text_w, max_height=note_max, start_size=7.5, min_size=6, align=TA_LEFT,
            leading_factor=1.25,
        )

        y = stack_top
        for paragraph, paragraph_h in (
            (heading, heading_h), (code, code_h), (link, link_h), (note, note_h)
        ):
            y -= paragraph_h
            paragraph.wrapOn(canvas, text_w, paragraph_h)
            paragraph.drawOn(canvas, text_x, y)
            y -= gap
