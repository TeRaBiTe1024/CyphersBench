import subprocess
import re
import sys
import statistics
import time

OUTPUT_FILE = "/data/resultado_detalhado.txt"
NUM_EXECUCOES = 10
# Tempo de execução por teste em segundos (reduzido para 1s para o teste total não demorar horas)
# O OpenSSL padrão usa 3s. Com 10 execuções, 1s é suficiente para estabilidade.
TIME_PER_RUN = "1" 

def run_openssl_symmetric(algo_cmd):
    """Executa e extrai o throughput para bloco de 8kb (8192 bytes)."""
    # Adiciona flag -seconds para controlar duração
    cmd = f"{algo_cmd} -seconds {TIME_PER_RUN}"
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).decode('utf-8')
        lines = out.splitlines()
        # Procura a linha que contem os resultados (geralmente termina com k)
        for line in lines:
            # Padrão de saída do openssl speed -evp:
            # type             16 bytes     64 bytes    256 bytes   1024 bytes   8192 bytes  16384 bytes
            # aes-256-gcm      123.4k       456.7k ...
            if "k" in line and ("8192" in line or "16384" in line):
                continue # Cabeçalho
            
            # Tenta encontrar a linha com números
            parts = line.split()
            if len(parts) > 5 and parts[-1].endswith('k'):
                # Pega a última coluna (throughput maximo)
                val_str = parts[-1].replace('k', '')
                return float(val_str) / 1000.0 # Converte para MB/s
    except Exception as e:
        return 0.0
    return 0.0

def run_openssl_asymmetric(algo_cmd, is_ecdsa=False):
    """Executa e extrai sign/s e verify/s."""
    cmd = f"{algo_cmd} -seconds {TIME_PER_RUN}"
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).decode('utf-8')
        lines = out.splitlines()
        sign, verify = 0.0, 0.0
        
        for line in lines:
            parts = line.split()
            if not parts: continue
            
            # Padrão RSA/DSA: ... 4096 bits 0.002s ... 500.0 10000.0
            # Os dois ultimos numeros costumam ser sign/s e verify/s
            if "sign/s" in line: continue
            
            try:
                # Tentativa genérica de pegar as duas ultimas colunas numéricas
                v = float(parts[-1])
                s = float(parts[-2])
                # Validação simples para evitar pegar linhas erradas
                if v > 0 and s > 0:
                    sign, verify = s, v
            except:
                pass
        return sign, verify
    except:
        return 0.0, 0.0

def print_header(f, title):
    f.write("\n" + "="*80 + "\n")
    f.write(f" {title}\n")
    f.write("="*80 + "\n")

def main():
    data_store = {} # Armazena todos os resultados brutos
    
    print(f"--- Iniciando Benchmark Profundo ({NUM_EXECUCOES} execuções/algo) ---")

    # ---------------------------------------------------------
    # 1. DEFINIÇÃO DOS ALGORITMOS
    # ---------------------------------------------------------
    sym_tests = [
        ("AES-128-GCM", "openssl speed -evp aes-128-gcm"),
        ("AES-256-GCM", "openssl speed -evp aes-256-gcm"),
        ("AES-256-CBC", "openssl speed -evp aes-256-cbc"),
        ("ChaCha20-Poly1305", "openssl speed -evp chacha20-poly1305"),
        ("Camellia-256-CBC", "openssl speed -evp camellia-256-cbc"),
        ("ARIA-256-CBC", "openssl speed -evp aria-256-cbc"),
        ("SHA3-512 (Hash)", "openssl speed -evp sha3-512")
    ]

    asym_tests = [
        ("RSA 4096", "openssl speed rsa4096"),
        ("RSA 7680", "openssl speed rsa -rsa_keylen 7680"), # Pode ser lento
        ("ECDSA P-256 (secp256r1)", "openssl speed ecdsa -curve secp256r1"),
        ("ECDSA P-521 (secp521r1)", "openssl speed ecdsa -curve secp521r1"),
        ("ECDSA secp256k1 (Bitcoin)", "openssl speed ecdsa -curve secp256k1"),
        ("Ed25519 (Moderno)", "openssl speed ed25519")
    ]

    # ---------------------------------------------------------
    # 2. EXECUÇÃO
    # ---------------------------------------------------------
    
    # --- Simétricos ---
    for name, cmd in sym_tests:
        print(f"Benchmarking Simétrico: {name} ...", end="", flush=True)
        results = []
        for _ in range(NUM_EXECUCOES):
            val = run_openssl_symmetric(cmd)
            results.append(val)
            print(".", end="", flush=True)
        print(" OK")
        data_store[name] = {"type": "sym", "raw": results}

    # --- Assimétricos ---
    for name, cmd in asym_tests:
        print(f"Benchmarking Assimétrico: {name} ...", end="", flush=True)
        signs = []
        verifies = []
        for _ in range(NUM_EXECUCOES):
            s, v = run_openssl_asymmetric(cmd)
            signs.append(s)
            verifies.append(v)
            print(".", end="", flush=True)
        print(" OK")
        data_store[name] = {"type": "asym", "sign": signs, "verify": verifies}

    # ---------------------------------------------------------
    # 3. GERAÇÃO DO RELATÓRIO
    # ---------------------------------------------------------
    with open(OUTPUT_FILE, "w") as f:
        f.write(f"RELATÓRIO DE PERFORMANCE CRIPTOGRÁFICA\n")
        f.write(f"Execuções por algoritmo: {NUM_EXECUCOES}\n")
        f.write(f"Data: {time.ctime()}\n")

        # TABELA 1: SIMÉTRICOS
        print_header(f, "TABELA DETALHADA: CRIPTOGRAFIA SIMÉTRICA (Throughput MB/s)")
        header = f"{'Algoritmo':<25} | {'Média':<10} | {'Mín':<10} | {'Máx':<10} | {'DesvPad':<10}"
        f.write(header + "\n")
        f.write("-" * len(header) + "\n")
        
        for name, cmd in sym_tests:
            raw = data_store[name]['raw']
            # Filtra zeros se houver erro
            raw = [x for x in raw if x > 0]
            if not raw:
                f.write(f"{name:<25} | FALHA NA EXECUÇÃO\n")
                continue
                
            mean = statistics.mean(raw)
            stdev = statistics.stdev(raw) if len(raw) > 1 else 0
            f.write(f"{name:<25} | {mean:<10.2f} | {min(raw):<10.2f} | {max(raw):<10.2f} | {stdev:<10.2f}\n")

        # TABELA 2: ASSIMÉTRICOS
        print_header(f, "TABELA DETALHADA: CRIPTOGRAFIA ASSIMÉTRICA (Ops/sec)")
        header = f"{'Algoritmo':<25} | {'Op':<8} | {'Média':<10} | {'Mín':<10} | {'Máx':<10} | {'DesvPad':<10}"
        f.write(header + "\n")
        f.write("-" * len(header) + "\n")

        for name, cmd in asym_tests:
            for op_type in ['sign', 'verify']:
                raw = data_store[name][op_type]
                raw = [x for x in raw if x > 0]
                if not raw:
                    f.write(f"{name:<25} | {op_type:<8} | FALHA\n")
                    continue
                
                mean = statistics.mean(raw)
                stdev = statistics.stdev(raw) if len(raw) > 1 else 0
                
                algo_display = name if op_type == 'sign' else ""
                f.write(f"{algo_display:<25} | {op_type:<8} | {mean:<10.1f} | {min(raw):<10.1f} | {max(raw):<10.1f} | {stdev:<10.1f}\n")
            f.write("-" * 80 + "\n")

        # DUMP RAW DATA
        print_header(f, "RAW DATA DUMP (DADOS BRUTOS DAS 10 EXECUÇÕES)")
        f.write("Este bloco contém os valores exatos coletados em cada rodada para auditoria.\n\n")
        
        for name in data_store:
            data = data_store[name]
            f.write(f"[{name}]\n")
            if data['type'] == 'sym':
                f.write(f"  MB/s: {data['raw']}\n")
            else:
                f.write(f"  Sign/s:   {data['sign']}\n")
                f.write(f"  Verify/s: {data['verify']}\n")
            f.write("\n")

    print(f"\nConcluído! Relatório salvo em: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()