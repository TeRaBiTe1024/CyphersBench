#!/usr/bin/python3

from mininet.net import Mininet
from mininet.node import Controller, OVSKernelSwitch, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
from mininet.topo import Topo
import time
import os

# ==========================================
# 1. SCRIPTS QUE RODARÃO DENTRO DOS HOSTS
# ==========================================

# Script do ENCRIPTADOR (Fica a 40km de distância - H1)
sender_script = """
import socket
import time
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

HOST = '0.0.0.0'
PORT = 5000
PAYLOAD_SIZE = 10 * 1024 * 1024  # 10 MB de dados

def get_cipher(name, key, iv):
    if name == 'AES-256-GCM':
        return Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).encryptor()
    elif name == 'ChaCha20':
        return Cipher(algorithms.ChaCha20(key, iv), mode=None, backend=default_backend()).encryptor()

def run_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(1)
    print(f"[Sender] Aguardando conexao em {PORT}...")
    
    conn, addr = s.accept()
    print(f"[Sender] Conectado por {addr}")

    # Dados fake
    data = os.urandom(PAYLOAD_SIZE)
    key = os.urandom(32)
    iv = os.urandom(12) if 'GCM' in 'AES-256-GCM' else os.urandom(16)

    # Protocolo simples: Envia o Nome do Algo -> Espera ACK -> Envia Dados Cifrados
    algos = ['AES-256-GCM', 'ChaCha20']
    
    for algo in algos:
        print(f"[Sender] Preparando {algo}...")
        encryptor = get_cipher(algo, key, iv)
        
        # Criptografa
        start_enc = time.time()
        if algo == 'AES-256-GCM':
            ciphertext = encryptor.update(data) + encryptor.finalize() + encryptor.tag
        else:
            ciphertext = encryptor.update(data)
        enc_time = time.time() - start_enc
        
        # 1. Avisa qual algoritmo é
        conn.sendall(algo.encode().ljust(32))
        
        # 2. Envia IV e KEY (Simulando que a chave vai por outro canal, 
        # mas aqui mandamos pelo socket para simplificar o lab, o delay de API é simulado no cliente)
        conn.sendall(iv)
        conn.sendall(key)
        
        # 3. Envia tamanho
        conn.sendall(str(len(ciphertext)).encode().ljust(16))
        
        # 4. Envia payload cifrado (Streaming)
        print(f"[Sender] Enviando {len(ciphertext)/1024/1024:.2f} MB via rede...")
        conn.sendall(ciphertext)
        
        # Espera confirmação do cliente para o próximo
        conn.recv(1024) 
        time.sleep(1)

    conn.close()
    s.close()

if __name__ == '__main__':
    run_server()
"""

# Script do DECRIPTADOR (Nó Local - H2)
receiver_script = """
import socket
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

SERVER_IP = '10.0.0.1'
PORT = 5000
API_LATENCY_MS = 15  # Simulação: Tempo para autenticar e baixar a chave do KMS Local

def simulate_local_api_call():
    # Simula o request HTTP para um servidor na mesma rack (localhost ou LAN próxima)
    # Inclui handshake TCP, processamento da API e retorno JSON
    time.sleep(API_LATENCY_MS / 1000.0)

def get_decryptor(name, key, iv, tag=None):
    if name == 'AES-256-GCM':
        return Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
    elif name == 'ChaCha20':
        return Cipher(algorithms.ChaCha20(key, iv), mode=None, backend=default_backend()).decryptor()

def run_client():
    print(f"[Receiver] Tentando conectar ao Sender a 40km ({SERVER_IP})...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    while True:
        try:
            s.connect((SERVER_IP, PORT))
            break
        except:
            time.sleep(1)
    
    # Rodar para os 2 algoritmos
    for _ in range(2):
        # 1. Recebe metadados
        algo_name = s.recv(32).decode().strip()
        print(f"\\n--- Testando: {algo_name} ---")
        
        # Recebe IV e Key (Na vida real, a Key viria da API)
        # O tamanho do IV varia: GCM=12, ChaCha=16. Vamos assumir leitura segura
        if 'GCM' in algo_name:
            iv = s.recv(12)
            key = s.recv(32)
        else:
            iv = s.recv(16)
            key = s.recv(32)
            
        msg_len = int(s.recv(16).decode().strip())
        
        # === PONTO CRÍTICO: SIMULAÇÃO DA API DE CHAVES ===
        print(f"[Receiver] Solicitando chave ao KMS Local (API)...")
        api_start = time.time()
        simulate_local_api_call()
        api_time = time.time() - api_start
        print(f"[Receiver] Chave recebida em {api_time*1000:.2f}ms")
        
        # 2. Baixa o conteúdo cifrado (Latência de Rede impacta aqui)
        received_data = b""
        net_start = time.time()
        while len(received_data) < msg_len:
            packet = s.recv(4096)
            if not packet: break
            received_data += packet
        net_time = time.time() - net_start
        print(f"[Receiver] Download (40km) concluído em {net_time:.4f}s")

        # 3. Decripta (Performance da CPU impacta aqui)
        dec_start = time.time()
        if 'GCM' in algo_name:
            tag = received_data[-16:]
            ciphertext = received_data[:-16]
            decryptor = get_decryptor(algo_name, key, iv, tag)
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        else:
            decryptor = get_decryptor(algo_name, key, iv)
            plaintext = decryptor.update(received_data)
            
        dec_time = time.time() - dec_start
        print(f"[Receiver] Decriptação (CPU) concluída em {dec_time:.4f}s")
        
        total_time = api_time + net_time + dec_time
        print(f"[RESULTADO] Tempo Total (API+Rede+Crypto): {total_time:.4f}s")
        
        # ACK para o proximo
        s.sendall(b'OK')

    s.close()

if __name__ == '__main__':
    run_client()
"""

# ==========================================
# 2. DEFINIÇÃO DA TOPOLOGIA (40km, 4 Saltos)
# ==========================================
class MetroNetwork(Topo):
    def build(self):
        # Criação dos Hosts
        sender = self.addHost('h1') # A 40km
        receiver = self.addHost('h2') # Local
        
        # Criação dos Switches (4 saltos)
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')
        
        # Link Setup:
        # Distancia total ~40km.
        # Vamos distribuir o delay entre os links.
        # Delay total propagação ~0.2ms. + Switching.
        # Configuração: 0.5ms por link * 5 links = 2.5ms Latência One-Way
        link_opts = dict(bw=100, delay='0.5ms', loss=0) # 100Mbps Link Fibra Metro

        self.addLink(sender, s1, **link_opts)
        self.addLink(s1, s2, **link_opts)
        self.addLink(s2, s3, **link_opts)
        self.addLink(s3, s4, **link_opts)
        self.addLink(s4, receiver, **link_opts)

# ==========================================
# 3. ORQUESTRAÇÃO
# ==========================================
def run_simulation():
    # Cria os arquivos python temporários
    with open("sender_node.py", "w") as f: f.write(sender_script)
    with open("receiver_node.py", "w") as f: f.write(receiver_script)

    topo = MetroNetwork()
    net = Mininet(topo=topo, link=TCLink, controller=Controller)
    net.start()

    h1 = net.get('h1')
    h2 = net.get('h2')

    info(f"\n*** Configuração da Rede ***\n")
    info(f"Sender (H1) <---> S1 <-> S2 <-> S3 <-> S4 <---> Receiver (H2)\n")
    info(f"Distância simulada: 40km (4 saltos de switches)\n")
    info(f"Largura de banda: 100Mbps\n")
    
    # Teste de conectividade básica
    info(f"\n*** Testando Latência de Rede (Ping) ***\n")
    net.ping([h1, h2])

    info(f"\n*** Iniciando Servidor de Criptografia em H1 ***\n")
    h1.cmd('python3 sender_node.py &')
    time.sleep(2) # Espera servidor subir

    info(f"\n*** Iniciando Cliente (Request API + Decrypt) em H2 ***\n")
    # Captura a saída em tempo real
    result = h2.cmd('python3 receiver_node.py')
    print(result)

    info(f"*** Encerrando ***\n")
    net.stop()
    
    # Limpeza
    os.remove("sender_node.py")
    os.remove("receiver_node.py")

if __name__ == '__main__':
    setLogLevel('info')
    run_simulation()