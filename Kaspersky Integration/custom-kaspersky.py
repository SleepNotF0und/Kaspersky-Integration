#!/var/ossec/framework/python/bin/python3
# -*- coding: utf-8 -*-
# --------------------------------------------------------------------------
# Wazuh - Kaspersky OpenTI Integration Script (Log File Output)
# Author: Gemini (Adaptado)
# Last Modified: 2025-10-28
#
# Description:
#   Este script se ejecuta por wazuh-integratord. Recibe una alerta FIM,
#   extrae el hash, consulta la API de Kaspersky OpenTI y,
#   si el hash es malicioso, escribe la información relevante como
#   un objeto JSON en el archivo /var/ossec/logs/external/kaspersky.log.
# --------------------------------------------------------------------------

import sys
import json
import requests
import os
# import socket # Ya no se necesita socket
import logging
import datetime
import traceback # Para loguear errores completos

# Configuración de Logging (para depurar el script en sí)
integrations_log_file = '/var/ossec/logs/integrations.log'
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
                    filename=integrations_log_file,
                    filemode='a')
logger = logging.getLogger('custom-kaspersky-log.py') # Nombre diferente para claridad

# Archivo de log específico para los resultados de Kaspersky
KASPERSKY_OUTPUT_LOG = '/var/ossec/logs/external/kaspersky.log'

# --- Constantes y Configuración ---
REQUEST_TIMEOUT = 15 # Segundos

# --- Funciones ---

def log_kaspersky_event(msg_dict):
    """
    Escribe un diccionario como una línea JSON en el archivo de log especificado.
    """
    try:
        # Asegurarse que el directorio de logs externos existe
        log_dir = os.path.dirname(KASPERSKY_OUTPUT_LOG)
        if not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
            # Intentar ajustar permisos si se crea (puede fallar si no es root)
            try:
                os.chown(log_dir, 998, 996) # UID/GID típicos de wazuh/wazuh, verificar con 'id wazuh'
                os.chmod(log_dir, 0o770)
            except OSError:
                 logger.warning(f"Could not set permissions on created directory {log_dir}. Wazuh might not be able to write logs.")


        json_string = json.dumps(msg_dict)
        with open(KASPERSKY_OUTPUT_LOG, 'a') as f:
            f.write(json_string + '\n')
        logger.info(f"Successfully wrote Kaspersky result to {KASPERSKY_OUTPUT_LOG}")
        return True
    except PermissionError as e:
         logger.error(f"Permission denied writing to {KASPERSKY_OUTPUT_LOG}. Check ownership/permissions. Error: {e}")
         logger.error(traceback.format_exc())
    except Exception as e:
        logger.error(f"Unexpected error writing to {KASPERSKY_OUTPUT_LOG}: {e}")
        logger.error(traceback.format_exc())
    return False

def query_kaspersky_api(api_url, api_key, file_hash):
    """
    Consulta la API de Kaspersky OpenTI para un hash dado.
    Retorna el JSON de la respuesta o None si hay error.
    (Sin cambios respecto a la versión anterior)
    """
    headers = {'x-api-key': api_key}
    params = {'request': file_hash}
    try:
        response = requests.get(api_url, headers=headers, params=params, timeout=REQUEST_TIMEOUT)
        logger.debug(f"Kaspersky API request URL: {response.url}")
        logger.debug(f"Kaspersky API response status code: {response.status_code}")
        response.raise_for_status()
        response_json = response.json()
        logger.debug(f"Kaspersky API response JSON received.")
        return response_json
    except requests.exceptions.Timeout:
        logger.error(f"Kaspersky API request timed out for hash {file_hash}.")
    except requests.exceptions.HTTPError as e:
         logger.error(f"Kaspersky API HTTP Error for hash {file_hash}: {e.response.status_code} - {e.response.text}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Kaspersky API request failed for hash {file_hash}: {e}")
    except json.JSONDecodeError as e:
        logger.error(f"Failed to decode JSON response from Kaspersky API for hash {file_hash}. Response text: {response.text[:500]}...")
    except Exception as e:
        logger.error(f"Unexpected error during Kaspersky API query for hash {file_hash}: {e}")
        logger.error(traceback.format_exc())
    return None

# --- Procesamiento Principal ---

# 1. Validar y obtener argumentos (Usando el chequeo flexible)
if len(sys.argv) < 4:
    logger.error(f"Insufficient number of arguments. Expected at least 4, got {len(sys.argv)}. Args: {sys.argv}")
    sys.exit(1)

alert_file_path = sys.argv[1]
api_key_arg = sys.argv[2]
hook_url = sys.argv[3]
logger.debug(f"Received Alert file: {alert_file_path}, API Key Arg: {api_key_arg}, Hook URL: {hook_url}")

# 2. Extraer la clave API
try:
    api_key_value = api_key_arg.split(':', 1)[1] if ':' in api_key_arg else api_key_arg
    if not api_key_value:
        raise ValueError("API Key value is empty after splitting.")
    logger.debug("API Key extracted successfully.")
except Exception as e:
    logger.error(f"API Key format error or empty key: {e}. Received: {api_key_arg}")
    sys.exit(1)

# 3. Leer y parsear la alerta JSON de Wazuh
try:
    with open(alert_file_path) as f:
        alert_json = json.load(f)
    logger.debug(f"Alert JSON loaded successfully from {alert_file_path}")
# ... (manejo de errores como antes) ...
except Exception as e:
    logger.error(f"Error reading/parsing alert file {alert_file_path}: {e}")
    logger.error(traceback.format_exc())
    sys.exit(1)


# 4. Extraer información relevante de la alerta FIM
# ... (lógica de extracción de hash y file_path como antes) ...
file_hash = None
hash_type = None
syscheck_data = alert_json.get('syscheck')
original_rule_id = alert_json.get('rule', {}).get('id')
original_rule_level = alert_json.get('rule', {}).get('level')
original_rule_description = alert_json.get('rule', {}).get('description')
agent_info = alert_json.get('agent')
location = alert_json.get('location') # location de la alerta original FIM

if syscheck_data:
    file_path = syscheck_data.get('path', 'N/A')
    if syscheck_data.get('sha256_after'):
        file_hash = syscheck_data['sha256_after']
        hash_type = 'sha256'
    elif syscheck_data.get('sha1_after'):
        file_hash = syscheck_data['sha1_after']
        hash_type = 'sha1'
    # ... (resto de la lógica de hash) ...
    elif syscheck_data.get('md5_after'):
         file_hash = syscheck_data['md5_after']
         hash_type = 'md5'
    else:
        logger.warning(f"No hash found in syscheck data for file: {file_path}. Alert: {alert_json}")
        sys.exit(0)
else:
    logger.debug(f"Alert ID {original_rule_id} does not contain 'syscheck' data. Skipping Kaspersky lookup.")
    sys.exit(0)

logger.info(f"Processing FIM event for file: '{file_path}' with {hash_type}: {file_hash}")

# 5. Consultar la API de Kaspersky
response_json = query_kaspersky_api(hook_url, api_key_value, file_hash)

if response_json:
    # 6. Analizar la respuesta y determinar si es malicioso
    zone = response_json.get("Zone")
    file_status = response_json.get("FileGeneralInfo", {}).get("FileStatus")
    detections_info = response_json.get("DetectionsInfo", [])
    is_malicious = zone == "Red" or file_status == "Malware" or len(detections_info) > 0

    if is_malicious:
        logger.warning(f"MALICIOUS hash detected for file '{file_path}' ({hash_type}: {file_hash}). Zone: {zone}, Status: {file_status}")

        # 7. Construir el diccionario/JSON para escribir en el log
        kaspersky_log_entry = {}
        kaspersky_log_entry['integration'] = 'kaspersky_openti'
        kaspersky_log_entry['kaspersky'] = {
            'status': 'malicious',
            'zone': zone if zone else 'N/A',
            'file_status': file_status if file_status else 'N/A',
            'hash': file_hash,
            'hash_type': hash_type,
            'original_filepath': file_path,
            'original_rule': { # Incluir info de la regla FIM original
                'id': original_rule_id,
                'level': original_rule_level,
                'description': original_rule_description
            },
            'detections': [d.get('DetectionName', 'N/A') for d in detections_info[:5]],
            'first_seen': response_json.get("FileGeneralInfo", {}).get("FirstSeen"),
            'last_seen': response_json.get("FileGeneralInfo", {}).get("LastSeen"),
        }
        # Incluir info del agente y location si existen en la alerta original
        if agent_info:
            kaspersky_log_entry['agent'] = agent_info
        if location:
             kaspersky_log_entry['location'] = location # location será 'syscheck'

        # 8. Escribir la entrada en el archivo de log externo
        log_kaspersky_event(kaspersky_log_entry)

    else:
        logger.info(f"Hash {file_hash} for file '{file_path}' is NOT classified as malicious by Kaspersky OpenTI.")
        # Opcional: podrías escribir una entrada 'clean' en el log si quisieras
        # kaspersky_log_entry = {'integration': 'kaspersky_openti', 'kaspersky': {'status': 'clean', ...}}
        # log_kaspersky_event(kaspersky_log_entry)

else:
    logger.error(f"No valid response received from Kaspersky API for hash {file_hash}. Cannot write log entry.")

# 9. Salir exitosamente
logger.debug("Script finished execution.")
sys.exit(0)
