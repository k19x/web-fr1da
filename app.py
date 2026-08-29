from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
import subprocess
import os
import shlex
import threading
from uuid import uuid4

app = Flask(__name__)
socketio = SocketIO(app)
# l\Downloads\projeto-frida-web-v3\projeto-frida-web\static\js
SCRIPT_PATH = os.path.join(os.environ['USERPROFILE'], 'Downloads', 'projeto-frida-web', 'static', 'js')

def executar_comando(comando, sid):
    try:
        process = subprocess.Popen(
            shlex.split(comando), shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        for linha in iter(process.stdout.readline, ''):
            if linha:
                append_log_to_socket(linha.strip(), sid)
        process.stdout.close()
        process.wait()
    except Exception as e:
        append_log_to_socket(f"Erro ao executar o comando: {e}", sid)
    finally:
        if process and process.poll() is None:
            process.terminate()  # Garante que o subprocesso seja encerrado

def append_log_to_socket(log_message, sid):
    try:
        socketio.emit('output', {'data': log_message}, to=sid)
    except Exception as e:
        print(f"Erro ao enviar log via SocketIO: {e}")

def executar_comando_sync(comando):
    try:
        result = subprocess.run(
            shlex.split(comando), shell=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        return result.stdout, result.stderr
    except Exception as e:
        return '', f"Erro: {e}"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/listar_dispositivos', methods=['GET'])
def listar_dispositivos():
    stdout, stderr = executar_comando_sync('adb devices')
    if stderr:
        return jsonify({'error': stderr}), 500
    dispositivos = [line.split()[0] for line in stdout.splitlines()[1:] if line.strip()]
    return jsonify(dispositivos)

@app.route('/listar_pacotes', methods=['POST'])
def listar_pacotes():
    dispositivo = request.json.get('dispositivo')
    if not dispositivo:
        return jsonify({'error': 'Dispositivo não selecionado'}), 400
    comando = f'adb -s {dispositivo} shell pm list packages -3'
    stdout, stderr = executar_comando_sync(comando)
    if stderr:
        return jsonify({'error': stderr}), 500
    pacotes = [line.replace('package:', '') for line in stdout.splitlines()]
    return jsonify(pacotes)

@app.route('/executar_frida', methods=['POST'])
def executar_frida():
    dispositivo = request.json.get('dispositivo')
    pacote = request.json.get('pacote')
    scripts = request.json.get('scripts', [])
    sid = request.json.get('sid')

    if not dispositivo or not pacote or not scripts:
        return jsonify({'error': 'Dados insuficientes'}), 400

    comandos_scripts = " ".join([f"-l {os.path.join(SCRIPT_PATH, script)}" for script in scripts])
    comando = f"frida -D {dispositivo} -f {pacote} {comandos_scripts}"
    thread = threading.Thread(target=executar_comando, args=(comando, sid))
    thread.start()
    return jsonify({'message': 'Comando Frida em execução'})

@app.route('/definir_proxy', methods=['POST'])
def definir_proxy():
    dispositivo = request.json.get('dispositivo')
    host = request.json.get('host')
    port = request.json.get('port')
    sid = request.json.get('sid')

    if not dispositivo or not host or not port:
        return jsonify({'error': 'Dados insuficientes'}), 400

    try:
        comandos = [
            f'adb -s {dispositivo} shell "su -c \'settings put global http_proxy {host}:{port}\'"',
            f'adb -s {dispositivo} shell "su -c \'settings put global global_http_proxy_host {host}\'"',
            f'adb -s {dispositivo} shell "su -c \'settings put global global_http_proxy_port {port}\'"',
            f'adb -s {dispositivo} shell "su -c \'settings put global global_http_proxy_exclusion_list ""\'"'
        ]
        
        for comando in comandos:
            stdout, stderr = executar_comando_sync(comando)
            if stderr:
                socketio.emit('output', {'data': stderr}, to=sid)
        
        return jsonify({'message': 'Proxy definido com sucesso'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
@app.route('/remover_proxy', methods=['POST'])
def remover_proxy():
    dispositivo = request.json.get('dispositivo')
    sid = request.json.get('sid')

    if not dispositivo:
        return jsonify({'error': 'Dispositivo não selecionado'}), 400

    try:
        # Comandos para remover proxy com aspas corrigidas
        comandos = [
            f'adb -s {dispositivo} shell "su -c \'settings put global http_proxy :0\'"',
            f'adb -s {dispositivo} shell "su -c \'settings put global global_http_proxy_host \\\"\\\"\'"',
            f'adb -s {dispositivo} shell "su -c \'settings put global global_http_proxy_port \\\"\\\"\'"',
            f'adb -s {dispositivo} shell "su -c \'settings put global global_http_proxy_exclusion_list \\\"\\\"\'"'
        ]

        erros = []
        for comando in comandos:
            stdout, stderr = executar_comando_sync(comando)
            if stderr:
                erros.append(stderr)

        if erros:
            return jsonify({'error': 'Erro ao remover proxy', 'details': erros}), 500

        return jsonify({'message': 'Proxy removido com sucesso'})
    except Exception as e:
        return jsonify({'error': f'Erro interno: {str(e)}'}), 500

@app.route('/verificar_proxy', methods=['POST'])
def verificar_proxy():
    dispositivo = request.json.get('dispositivo')
    sid = request.json.get('sid')

    if not dispositivo:
        return jsonify({'error': 'Dispositivo não selecionado'}), 400

    try:
        # Comandos para verificar proxy
        comandos = {
            "http_proxy": f'adb -s {dispositivo} shell "settings get global http_proxy"',
            "global_http_proxy_host": f'adb -s {dispositivo} shell "settings get global global_http_proxy_host"',
            "global_http_proxy_port": f'adb -s {dispositivo} shell "settings get global global_http_proxy_port"',
            "global_http_proxy_exclusion_list": f'adb -s {dispositivo} shell "settings get global global_http_proxy_exclusion_list"'
        }

        resultados = {}
        for chave, comando in comandos.items():
            stdout, stderr = executar_comando_sync(comando)
            if stderr:
                append_log_to_socket(f"Erro ao verificar {chave}: {stderr}", sid)
                resultados[chave] = f"Erro: {stderr}"
            else:
                resultados[chave] = stdout.strip()

        return jsonify(resultados)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/reboot_device', methods=['POST'])
def reboot_device():
    dispositivo = request.json.get('dispositivo')
    if not dispositivo:
        return jsonify({'error': 'Dispositivo não selecionado'}), 400

    try:
        comando = f'adb -s {dispositivo} reboot'
        stdout, stderr = executar_comando_sync(comando)
        if stderr:
            return jsonify({'error': stderr}), 500
        return jsonify({'message': 'Dispositivo reiniciado com sucesso'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
@app.route('/adb_reverse', methods=['POST'])
def adb_reverse():
    dispositivo = request.json.get('dispositivo')
    if not dispositivo:
        return jsonify({'error': 'Dispositivo não selecionado'}), 400

    try:
        comando = f'adb -s {dispositivo} reverse tcp:8080 tcp:8008'
        stdout, stderr = executar_comando_sync(comando)
        if stderr:
            return jsonify({'error': stderr}), 500
        return jsonify({'message': 'Reverso aplicado com sucesso'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
@app.route('/adb_screencap', methods=['POST'])
def adb_screencap():
    dispositivo = request.json.get('dispositivo')
    if not dispositivo:
        return jsonify({'error': 'Dispositivo não selecionado'}), 400

    try:
        comando = f'adb -s {dispositivo} shell screencap -p /sdcard/{uuid4()}.png'
        stdout, stderr = executar_comando_sync(comando)
        if stderr:
            return jsonify({'error': stderr}), 500
        return jsonify({'message': 'Captura realizada com sucesso'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
@app.route('/adb_screenrecord', methods=['POST'])
def adb_screenrecord():
    dispositivo = request.json.get('dispositivo')
    if not dispositivo:
        return jsonify({'error': 'Dispositivo não selecionado'}), 400

    try:
        comando = f'adb -s {dispositivo} shell screenrecord /sdcard/{uuid4()}.mp4'
        stdout, stderr = executar_comando_sync(comando)
        if stderr:
            return jsonify({'error': stderr}), 500
        return jsonify({'message': 'Gravação Iniciada'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/adb_shell_ls', methods=['POST'])
def adb_shell_ls():
    dispositivo = request.json.get('dispositivo')
    if not dispositivo:
        return jsonify({'error': 'Dispositivo não selecionado'}), 400
    comando = f'adb -s {dispositivo} shell su -c ls /sdcard'
    stdout, stderr = executar_comando_sync(comando)
    if stderr:
        return jsonify({'error': stderr}), 500
    files = [line.replace('package:', '') for line in stdout.splitlines()]
    return jsonify(files)

@app.route('/instalar_apk', methods=['POST'])
def instalar_apk():
    dispositivo = request.form.get('dispositivo')
    arquivo = request.files.get('arquivo')

    if not dispositivo or not arquivo:
        return jsonify({'error': 'Dispositivo ou arquivo não fornecido'}), 400

    caminho_arquivo = os.path.join('uploads', arquivo.filename)
    os.makedirs('uploads', exist_ok=True)
    arquivo.save(caminho_arquivo)

    try:
        comando = f'adb -s {dispositivo} install {caminho_arquivo}'
        stdout, stderr = executar_comando_sync(comando)
        if stderr:
            return jsonify({'error': stderr}), 500
        return jsonify({'message': 'APK instalado com sucesso'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        os.remove(caminho_arquivo)

@app.route('/remover_app', methods=['POST'])
def remover_app():
    dispositivo = request.json.get('dispositivo')
    pacote = request.json.get('pacote')

    if not dispositivo or not pacote:
        return jsonify({'error': 'Dispositivo ou pacote não fornecido'}), 400

    try:
        comando = f"adb -s {dispositivo} uninstall {pacote}"
        stdout, stderr = executar_comando_sync(comando)
        if stderr:
            return jsonify({'error': stderr}), 500
        return jsonify({'message': f'App {pacote} removido com sucesso!'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/limpar_pacote', methods=['POST'])
def limpar_pacote():
    dispositivo = request.json.get('dispositivo')
    pacote = request.json.get('pacote')

    if not dispositivo or not pacote:
        return jsonify({'error': 'Dispositivo ou pacote não fornecido'}), 400

    try:
        comando = f"adb -s {dispositivo} shell pm clear {pacote}"
        stdout, stderr = executar_comando_sync(comando)
        if stderr:
            return jsonify({'error': stderr}), 500
        return jsonify({'message': f'Cache do pacote {pacote} limpo com sucesso!'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/execute_script', methods=['POST'])
def execute_script():
    data = request.json
    dispositivo = data.get('dispositivo')
    pacote = data.get('pacote')
    script_content = data.get('script')

    if not dispositivo:
        return jsonify({'error': 'Nenhum dispositivo selecionado'}), 400

    if not pacote:
        return jsonify({'error': 'Nenhum pacote fornecido'}), 400

    if not script_content:
        return jsonify({'error': 'Nenhum script fornecido'}), 400

    try:
        # Salva o script em um arquivo temporário com UTF-8
        script_path = os.path.join(SCRIPT_PATH, f"temp_script_{uuid4()}.js")
        with open(script_path, 'w', encoding='utf-8') as script_file:
            script_file.write(script_content)

        # Executa o script usando Frida
        comando = f"frida -D {dispositivo} -f {pacote} -l {script_path}"
        stdout, stderr = executar_comando_sync(comando)

        # Remove o arquivo temporário
        os.remove(script_path)

        if stderr:
            return jsonify({'error': stderr}), 500

        return jsonify({'message': 'Script executado com sucesso.', 'output': stdout})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    socketio.run(app, host="0.0.0.0", debug=False, use_reloader=False)

def executar_comando_sync(comando):
    try:
        process = subprocess.Popen(shlex.split(comando), shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()
        return stdout, stderr
    except Exception as e:
        return '', str(e)

if __name__ == '__main__':
    socketio.run(app, host="0.0.0.0", debug=False)
