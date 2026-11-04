FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src/ src/
RUN useradd -u 1001 -m app && mkdir -p /app/output && chown -R 1001:0 /app && chmod -R g=u /app
USER 1001
ENV OUTPUT_DIR=/app/output PYTHONUNBUFFERED=1
ENTRYPOINT ["python", "src/main.py"]
