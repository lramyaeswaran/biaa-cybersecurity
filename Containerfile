# Multi-stage: the Trivy binary is 161MB, so it is copied from the official image
# rather than downloaded into our layer. Nothing else needs a build stage.
FROM aquasec/trivy:0.72.0 AS trivy

FROM python:3.13-slim

WORKDIR /app

COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Run as non-root. This app tells people to drop privileges; it should not need them.
RUN useradd --create-home --uid 10001 sentinel && chown -R sentinel:sentinel /app
USER sentinel

EXPOSE 8000

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
