# A Python base image with an application pip-installed into a venv: the official image's own
# /usr/local installation plus /app/.venv. --no-deps: the lock was compiled on macOS, where
# sqlalchemy needs no greenlet, and installs exactly what it pins.
FROM python:3.11-slim-bookworm
COPY requirements/02-flask/requirements.txt /app/requirements.txt
RUN python -m venv /app/.venv \
    && /app/.venv/bin/pip install --no-cache-dir --no-deps --require-hashes -r /app/requirements.txt
