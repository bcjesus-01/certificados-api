# syntax=docker/dockerfile:1.7
# =============================================================================
# certificados-api: imagem de produção (Cloud Run / Render / Railway)
#   docker build -t certificados-api .
#   docker run --rm --read-only --tmpfs /tmp -p 8080:8080 --env-file .env \
#       -e APP_ENV=development certificados-api
# O pipeline inteiro usa io.BytesIO: a imagem roda com o sistema de arquivos SOMENTE LEITURA.
# =============================================================================
ARG PYTHON_VERSION=3.11

# -----------------------------------------------------------------------------
# Estágio 1: builder. Instala as dependências num virtualenv isolado.
# Todas as dependências têm wheels binárias (asyncpg, cryptography, pillow...), então
# não há compilador na imagem final nem neste estágio.
# -----------------------------------------------------------------------------
FROM python:${PYTHON_VERSION}-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_PREFER_BINARY=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"

WORKDIR /build
COPY requirements.txt .
RUN pip install --upgrade pip \
 && pip install -r requirements.txt

# -----------------------------------------------------------------------------
# Estágio 2: runtime enxuto, usuário não-root, sem ferramentas de build.
# -----------------------------------------------------------------------------
FROM python:${PYTHON_VERSION}-slim AS runtime

LABEL org.opencontainers.image.title="certificados-api" \
      org.opencontainers.image.description="Emissão em lote, assinatura PAdES e validação pública de certificados (stateless, zero-disk)" \
      org.opencontainers.image.licenses="NOASSERTION"

# PORT: Cloud Run injeta a porta; 8080 é o padrão da plataforma.
# FORWARDED_ALLOW_IPS=*: atrás do balanceador do Cloud Run/Render o IP real do cliente vem em
#   X-Forwarded-For; sem isso todo hash de IP da auditoria seria o do proxy. Se expuser a porta
#   diretamente (sem proxy), defina FORWARDED_ALLOW_IPS=127.0.0.1.
# APP_ENV=production: falha fechada (exige ISSUANCE_API_KEY, CORS https e DB_SSL seguro).
#   Para rodar localmente em contêiner use -e APP_ENV=development.
ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    PORT=8080 \
    FORWARDED_ALLOW_IPS="*" \
    APP_ENV=production

# Usuário sem privilégios, sem home e sem shell de login.
RUN groupadd --system --gid 10001 appuser \
 && useradd --system --uid 10001 --gid appuser --no-create-home \
            --home-dir /nonexistent --shell /usr/sbin/nologin appuser

COPY --from=builder /opt/venv /opt/venv

WORKDIR /srv
# Código pertence ao root e é somente leitura para o appuser (imagem imutável).
COPY --chown=root:root app ./app
COPY --chown=root:root docker/healthcheck.py ./healthcheck.py

USER appuser
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["python", "/srv/healthcheck.py"]

# "sh -c exec" expande $PORT e mantém o uvicorn como PID 1 (recebe o SIGTERM do orquestrador).
# Um único worker: o escalonamento é horizontal (instâncias), e cada instância mantém seu pool.
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8080} --proxy-headers --no-server-header --timeout-graceful-shutdown 20"]
