# Imagen para Google Cloud Run
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 ENTORNO=produccion MODO_LOCAL=0
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD exec gunicorn --bind :${PORT:-8080} --workers 2 --threads 4 --timeout 60 app:app
