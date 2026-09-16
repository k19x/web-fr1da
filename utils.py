import subprocess
import shlex
import logging

# Configuração básica de logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


def executar_comando_sync(comando, timeout=30):
    try:
        if isinstance(comando, str):
            comando = shlex.split(comando)
        result = subprocess.run(
            comando,
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
        return result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        logging.error("Erro: Timeout ao executar o comando.")
        return "", "Erro: Timeout ao executar o comando."
    except Exception as e:
        logging.error(f"Erro ao executar o comando: {e}")
        return "", str(e)


def sanitize_input(input_value):
    # Simples verificação para evitar comandos perigosos
    if ";" in input_value or "&" in input_value or "|" in input_value:
        raise ValueError("Entrada inválida detectada.")
    return input_value
