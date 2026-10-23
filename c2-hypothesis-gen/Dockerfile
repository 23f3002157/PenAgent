FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY hgs/ ./hgs/

EXPOSE 9002

ENV PYTHONUNBUFFERED=1
ENV HGS_HOST=0.0.0.0
ENV HGS_PORT=9002

CMD ["uvicorn", "hgs.main:app", "--host", "0.0.0.0", "--port", "9002"]
