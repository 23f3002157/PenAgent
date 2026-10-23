FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy SIS application code
COPY sis/ ./sis/

EXPOSE 9001

ENV PYTHONUNBUFFERED=1
ENV SIS_HOST=0.0.0.0
ENV SIS_PORT=9001

CMD ["uvicorn", "sis.main:app", "--host", "0.0.0.0", "--port", "9001"]
