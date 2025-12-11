# Usamos Python Slim base (Debian-based) para ter facilidade com apt-get
FROM python:3.11-slim

# Instalar OpenSSL
RUN apt-get update && \
    apt-get install -y openssl && \
    rm -rf /var/lib/apt/lists/*

# Definir diretório de trabalho
WORKDIR /app

# Copiar o script para dentro do container
COPY benchmark.py .

# Criar diretório para volume de dados
RUN mkdir /data

# Comando padrão
CMD ["python", "benchmark.py"]