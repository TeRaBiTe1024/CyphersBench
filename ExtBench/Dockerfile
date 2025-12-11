FROM python:3.11-slim

# Instala OpenSSL e limpa cache para manter a imagem pequena
RUN apt-get update && \
    apt-get install -y openssl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copia o script novo
COPY extbench.py .

# Cria pasta de saída
RUN mkdir /data

CMD ["python", "extbench.py"]