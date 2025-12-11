import subprocess
import re
import sys

OUTPUT_FILE = "/data/resultado_benchmark.txt"

def run_command(cmd):
    """Roda um comando shell e retorna a saída decodificada."""
    try:
        result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        return result.decode('utf-8')
    except subprocess.CalledProcessError as e:
        return e.output.decode('utf-8')

def parse_symmetric(output, algo_name):
    """Extrai a velocidade em MB/s para blocos grandes (8192 bytes ou 16k)."""
    # OpenSSL speed output format varies, but usually ends with tabular data.
    # We look for the line starting with the algo name or specific marker
    lines = output.splitlines()
    # Pega a última linha que geralmente contém os dados resumidos com 'k'
    for line in lines:
        if "k" in line and ("1024" in line or "8192" in line):
             # Vamos pegar a última coluna (bloco maior = throughput máximo)
             parts = line.split()
             # O throughput geralmente é o último valor
             speed_str = parts[-1].replace('k', '')
             try:
                 speed_mb = float(speed_str) / 1000  # Converter k/s para MB/s (aprox)
                 return f"{speed_mb:.2f} MB/s"
             except:
                 continue
    return "Erro no Parse"

def parse_asymmetric(output):
    """Extrai assinaturas e verificações por segundo."""
    lines = output.splitlines()
    sign_s = "N/A"
    verify_s = "N/A"
    
    for line in lines:
        # Formato típico: "rsa 4096 bits 0.003s ...  120.5  3500.2" (os ultimos são ops/sec)
        # Ou formato tabulado do OpenSSL 3.x
        if "sign/s" in line and "verify/s" in line:
            continue # Skip header
        
        parts = line.split()
        if len(parts) > 1:
            # Assumindo que os dois ultimos numeros sao sign/s e verify/s
            try:
                verify_s = float(parts[-1])
                sign_s = float(parts[-2])
                return f"{sign_s:.1f}", f"{verify_s:.1f}"
            except:
                continue
    return sign_s, verify_s

def main():
    results = []
    
    print("--- Iniciando Benchmark OpenSSL (Docker) ---")
    
    # 1. SIMÉTRICOS (Focando em Throughput com aceleração de hardware -evp)
    # Testando AES-256 CBC e GCM (Modo moderno) e ChaCha20
    sym_algos = [
        ("AES-256-CBC", "openssl speed -evp aes-256-cbc"),
        ("AES-256-GCM", "openssl speed -evp aes-256-gcm"),
        ("ChaCha20-Poly1305", "openssl speed -evp chacha20-poly1305"),
        ("SHA-512 (Hash)", "openssl speed -evp sha512") # Útil para referência
    ]

    results.append("===================================================================")
    results.append(" BENCHMARK SIMÉTRICO (Throughput em Blocos Grandes)")
    results.append("===================================================================")
    results.append(f"{'Algoritmo':<25} | {'Velocidade Estimada'}")
    results.append("-" * 50)

    for name, cmd in sym_algos:
        print(f"Executando {name}...")
        out = run_command(cmd)
        speed = parse_symmetric(out, name.lower())
        results.append(f"{name:<25} | {speed}")
    
    results.append("\n")

    # 2. ASSIMÉTRICOS (Focando em Ops/sec)
    # RSA Gigante (4096 e 7680) e Curvas Elípticas Fortes (P-521)
    results.append("===================================================================")
    results.append(" BENCHMARK ASSIMÉTRICO (Operações por Segundo)")
    results.append("===================================================================")
    results.append(f"{'Algoritmo / Tamanho':<25} | {'Sign/s':<10} | {'Verify/s':<10}")
    results.append("-" * 55)

    # RSA
    rsa_sizes = [4096, 7680] # 7680 bits é massivo (segurança equivalente a AES-192)
    for size in rsa_sizes:
        name = f"RSA {size} bits"
        print(f"Executando {name}...")
        # OpenSSL speed rsa suporta argumentos customizados
        cmd = f"openssl speed rsa{size}" 
        # Nota: Se o openssl da distro não tiver o alias rsa7680, ele pode falhar ou rodar padrão.
        # Ajuste para comando genérico se falhar, mas rsa4096 é padrão.
        if size > 4096:
             # Fallback para comando genérico de teste se necessário, 
             # mas o 'speed' padrão foca em potencias de 2. Vamos tentar o padrão.
             cmd = f"openssl speed rsa -rsa_keylen {size}" 
        
        out = run_command(cmd)
        sign, verify = parse_asymmetric(out)
        results.append(f"{name:<25} | {sign:<10} | {verify:<10}")

    # ECC
    curves = ["secp384r1", "secp521r1"] # 521 é uma das curvas mais fortes padrão NIST
    for curve in curves:
        name = f"ECDSA {curve}"
        print(f"Executando {name}...")
        cmd = f"openssl speed ecdsa -curve {curve}"
        out = run_command(cmd)
        sign, verify = parse_asymmetric(out)
        results.append(f"{name:<25} | {sign:<10} | {verify:<10}")

    # Salvar em arquivo
    with open(OUTPUT_FILE, "w") as f:
        f.write("\n".join(results))
    
    print(f"\nSucesso! Resultados salvos em {OUTPUT_FILE}")
    print("\n".join(results))

if __name__ == "__main__":
    main(