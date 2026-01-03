from flask import Flask, request, jsonify
import requests
import json
from datetime import datetime
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import traceback
import pytz
import math

import base64
import os
from uuid import uuid4

app = Flask(__name__)

# --- Credenciais de Produção ---
ACCOUNT_ID = "RE_simpremium"
SIGN_KEY = "3GIJ0119BNP3G6UN6A5I6BB4PZS2QVWQ"
SECRET_KEY = "UYHUR49SEVWFR6WI"
VECTOR = "OQ75CK0MYKQDKC0O"
API_VERSION = "1.0"
BASE_URL = "http://enterpriseapi.tugegroup.com:8060/api-publicappmodule/"


# --- Funções de Criptografia e Assinatura ---
def aes_encrypt(data_str):
    # ... (código sem alterações) ...
    key = SECRET_KEY.encode('utf-8'); iv = VECTOR.encode('utf-8'); cipher = AES.new(key, AES.MODE_CBC, iv); padded_data = pad(data_str.encode('utf-8'), AES.block_size); encrypted_bytes = cipher.encrypt(padded_data); return ''.join([f"{chr(((b >> 4) & 0xF) + ord('a'))}{chr(((b & 0xF) + ord('a')))}" for b in encrypted_bytes])
def aes_decrypt(encrypted_hex):
    # ... (código sem alterações) ...
    key = SECRET_KEY.encode('utf-8'); iv = VECTOR.encode('utf-8'); encrypted_bytes = bytes([((ord(encrypted_hex[i]) - ord('a')) << 4) + (ord(encrypted_hex[i+1]) - ord('a')) for i in range(0, len(encrypted_hex), 2)]); cipher = AES.new(key, AES.MODE_CBC, iv); decrypted_padded_bytes = cipher.decrypt(encrypted_bytes); unpadded_bytes = unpad(decrypted_padded_bytes, AES.block_size); return unpadded_bytes.decode('utf-8')
def create_signature(service_name, request_time, encrypted_data):
    # ... (código sem alterações) ...
    raw_string = f"{ACCOUNT_ID}{service_name}{request_time}{encrypted_data}{API_VERSION}{SIGN_KEY}"; md5_hash = hashlib.md5(raw_string.encode('utf-8')).hexdigest(); return md5_hash

# --- Rota Completa para Detalhes do ICCID (ATUALIZADA) ---
@app.route('/get_full_iccid_details', methods=['POST'])
def get_full_iccid_details():
    try:
        sao_paulo_tz = pytz.timezone("America/Sao_Paulo")
        query_datetime_sp = datetime.now(sao_paulo_tz).strftime('%Y-%m-%d %H:%M:%S')
        request_body = request.get_json(); iccid = request_body.get("iccid")
        # ... (código de busca de pedidos, igual ao anterior) ...
        service_name_orders = "queryEsimOrderList"; endpoint_orders = "saleOrderApi/queryEsimOrderList"
        data_payload_orders = { "page": 1, "pageSize": 100, "iccid": iccid, "orderStatus": "", "lang": "en" }
        data_str = json.dumps(data_payload_orders); encrypted_data = aes_encrypt(data_str); request_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'); sign = create_signature(service_name_orders, request_time, encrypted_data)
        final_payload = { "accountId": ACCOUNT_ID, "serviceName": service_name_orders, "requestTime": request_time, "data": encrypted_data, "version": API_VERSION, "sign": sign }
        headers = {'Content-Type': 'application/json'}
        response_orders = requests.post(BASE_URL + endpoint_orders, data=json.dumps(final_payload), headers=headers, timeout=20); response_orders.raise_for_status(); response_orders_json = response_orders.json()
        if response_orders_json.get("code") != "0000": return jsonify({"error": "Failed to fetch orders for ICCID", "details": response_orders_json}), 400
        all_orders = json.loads(aes_decrypt(response_orders_json["data"]))
        if not all_orders: return jsonify([]), 200

        profile_info = {}
        first_order_no = all_orders[0].get("orderNo")
        if first_order_no:
            # ... (código de busca de perfil, igual ao anterior) ...
            service_name_profile = "getProfileInfo"; endpoint_profile = "saleSimApi/getProfileInfo"
            data_payload_profile = {"orderNo": first_order_no, "lang": "en"}
            data_str_profile = json.dumps(data_payload_profile); encrypted_data_profile = aes_encrypt(data_str_profile); request_time_profile = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'); sign_profile = create_signature(service_name_profile, request_time_profile, encrypted_data_profile)
            final_payload_profile = { "accountId": ACCOUNT_ID, "serviceName": service_name_profile, "requestTime": request_time_profile, "data": encrypted_data_profile, "version": API_VERSION, "sign": sign_profile }
            response_profile = requests.post(BASE_URL + endpoint_profile, data=json.dumps(final_payload_profile), headers=headers, timeout=20)
            if response_profile.status_code == 200 and response_profile.json().get("code") == "0000": profile_info = json.loads(aes_decrypt(response_profile.json().get("data", "")))

        detailed_results = []
        for order in all_orders:
            # ... (código de combinação de dados, agora com os campos de renovação) ...
            order_status = order.get("orderStatus"); order_no = order.get("orderNo"); start_date_sp, end_date_sp = "", ""
            try:
                utc_tz, date_format = pytz.utc, '%Y-%m-%d %H:%M:%S'
                if order.get("startDate"): start_date_sp = datetime.strptime(order.get("startDate"), date_format).replace(tzinfo=utc_tz).astimezone(sao_paulo_tz).strftime(date_format)
                if order.get("endDate"): end_date_sp = datetime.strptime(order.get("endDate"), date_format).replace(tzinfo=utc_tz).astimezone(sao_paulo_tz).strftime(date_format)
            except (ValueError, TypeError): pass
            usage_data = {}
            if order_status == "INUSE":
                # ... (código de busca de consumo, igual ao anterior) ...
                service_name_flow = "getEsimFlowByParams"; endpoint_flow = "saleSimApi/getEsimFlowByParams"; data_payload_flow = { "iccid": iccid, "orderNo": order_no, "lang": "en" }; data_str_flow = json.dumps(data_payload_flow); encrypted_data_flow = aes_encrypt(data_str_flow); request_time_flow = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'); sign_flow = create_signature(service_name_flow, request_time_flow, encrypted_data_flow); final_payload_flow = { "accountId": ACCOUNT_ID, "serviceName": service_name_flow, "requestTime": request_time_flow, "data": encrypted_data_flow, "version": API_VERSION, "sign": sign_flow }; response_flow = requests.post(BASE_URL + endpoint_flow, data=json.dumps(final_payload_flow), headers=headers, timeout=20)
                if response_flow.status_code == 200 and response_flow.json().get("code") == "0000": usage_data = json.loads(aes_decrypt(response_flow.json()["data"]))
            
            combined_result = {
                "data_consulta_sp": query_datetime_sp, "iccid": iccid, "eid": profile_info.get("eid"), "imsi": profile_info.get("imsi"),
                "profile_status": profile_info.get("state"), "install_device": profile_info.get("installDevice"), "install_time": profile_info.get("installTime"),
                "orderNo": order_no, "productName": order.get("productName"), "orderStatus": order_status,
                "validity_start_date_sp": start_date_sp, "validity_end_date_sp": end_date_sp,
                # ******** NOVOS CAMPOS ADICIONADOS AQUI ********
                "pode_renovar": profile_info.get("renewFlag"),
                "data_limite_renovacao": profile_info.get("renewExpirationTime"),
                # ******** FIM DA ADIÇÃO ********
                "daily_total_mb": usage_data.get("dataTotal", "N/A"), "daily_usage_mb": usage_data.get("qtaconsumption") or usage_data.get("dataUsage") or "N/A",
                "daily_remaining_mb": usage_data.get("dataResidual", "N/A")
            }
            detailed_results.append(combined_result)
        return jsonify(detailed_results), 200
    except Exception as e:
        print("!!!!!!!!!! ERRO DETALHADO EM /get_full_iccid_details !!!!!!!!!!"); traceback.print_exc(); return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=False)


# --- Rota Otimizada para Buscar Todos os Planos ---
@app.route('/get_all_plans', methods=['POST'])
def get_all_esim_plans():
    all_plans = []
    try:
        # Passo 1: Fazer a primeira chamada para descobrir o total
        service_name = "queryEsimProductListByParams"
        endpoint = "productApi/queryEsimProductListByParams"
        
        data_payload = {"page": 1, "pageSize": 100, "lang": "en"}
        data_str = json.dumps(data_payload)
        encrypted_data = aes_encrypt(data_str)
        request_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        sign = create_signature(service_name, request_time, encrypted_data)
        
        final_payload = { "accountId": ACCOUNT_ID, "serviceName": service_name, "requestTime": request_time, "data": encrypted_data, "version": API_VERSION, "sign": sign }
        headers = {'Content-Type': 'application/json'}
        
        response = requests.post(BASE_URL + endpoint, data=json.dumps(final_payload), headers=headers, timeout=30)
        response.raise_for_status()
        response_json = response.json()

        if response_json.get("code") != "0000":
            return jsonify({"error": "Failed on first API call", "details": response_json}), 400

        total_records = response_json.get("total", 0)
        decrypted_data_list = json.loads(aes_decrypt(response_json["data"]))
        
        if total_records == 0:
            return jsonify({"total": 0, "data": []}), 200
        
        all_plans.extend(decrypted_data_list)
        total_pages = math.ceil(total_records / 100)

        # Passo 2: Fazer o loop para as páginas restantes
        for page_num in range(2, total_pages + 1):
            data_payload["page"] = page_num
            data_str = json.dumps(data_payload)
            encrypted_data = aes_encrypt(data_str)
            request_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
            sign = create_signature(service_name, request_time, encrypted_data)
            final_payload = { "accountId": ACCOUNT_ID, "serviceName": service_name, "requestTime": request_time, "data": encrypted_data, "version": API_VERSION, "sign": sign }
            
            response = requests.post(BASE_URL + endpoint, data=json.dumps(final_payload), headers=headers, timeout=30)
            response.raise_for_status()
            response_json = response.json()
            
            if response_json.get("code") == "0000":
                page_data = json.loads(aes_decrypt(response_json["data"]))
                all_plans.extend(page_data)

        return jsonify({"total": total_records, "data": all_plans}), 200

    except Exception as e:
        print("!!!!!!!!!! ERRO DETALHADO EM /get_all_plans !!!!!!!!!!")
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=False)



# --- Rota para Criar Pedidos (ATUALIZADA) ---
@app.route('/create_order', methods=['POST'])
def create_esim_order():
    try:
        request_body = request.get_json()
        if not request_body:
            return jsonify({"error": "Request body is missing or not JSON"}), 400
        
        product_code = request_body.get("productCode")
        notify_url = request_body.get("notifyUrl")
        
        if not product_code or not notify_url:
            return jsonify({"error": "Missing required fields: productCode and notifyUrl"}), 400

        # --- CHAMADA 1: CRIAR O PEDIDO (openCard) ---
        service_name_create = "openCard"
        endpoint_create = "saleOrderApi/openCard"
        data_payload_create = {
            "productCode": product_code, "currency": request_body.get("currency", "USD"),
            "startDate": request_body.get("startDate", ""), "lang": request_body.get("lang", "en"),
            "otaOrderNo": request_body.get("otaOrderNo", ""), "email": request_body.get("email", ""),
            "notifyUrl": notify_url, "iccidAmount": 1, "requestId": request_body.get("requestId", "")
        }
        data_str = json.dumps(data_payload_create)
        encrypted_data = aes_encrypt(data_str)
        request_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        sign = create_signature(service_name_create, request_time, encrypted_data)
        final_payload = { "accountId": ACCOUNT_ID, "serviceName": service_name_create, "requestTime": request_time, "data": encrypted_data, "version": API_VERSION, "sign": sign }
        headers = {'Content-Type': 'application/json'}
        
        response_create = requests.post(BASE_URL + endpoint_create, data=json.dumps(final_payload), headers=headers, timeout=20)
        response_create.raise_for_status()
        response_create_json = response_create.json()

        if response_create_json.get("code") != "0000":
            return jsonify({"error": "Order creation failed", "details": response_create_json}), 400

        order_details = json.loads(aes_decrypt(response_create_json["data"]))
        new_order_no = order_details[0].get("orderNo") # O resultado é uma lista com um item

        # --- CHAMADA 2: BUSCAR AS INFORMAÇÕES DO PERFIL (getProfileInfo) ---
        profile_info = {}
        if new_order_no:
            service_name_profile = "getProfileInfo"
            endpoint_profile = "saleSimApi/getProfileInfo"
            data_payload_profile = {"orderNo": new_order_no, "lang": "en"}
            
            data_str_profile = json.dumps(data_payload_profile)
            encrypted_data_profile = aes_encrypt(data_str_profile)
            request_time_profile = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
            sign_profile = create_signature(service_name_profile, request_time_profile, encrypted_data_profile)
            final_payload_profile = { "accountId": ACCOUNT_ID, "serviceName": service_name_profile, "requestTime": request_time_profile, "data": encrypted_data_profile, "version": API_VERSION, "sign": sign_profile }
            
            response_profile = requests.post(BASE_URL + endpoint_profile, data=json.dumps(final_payload_profile), headers=headers, timeout=20)
            if response_profile.status_code == 200 and response_profile.json().get("code") == "0000":
                profile_info = json.loads(aes_decrypt(response_profile.json().get("data", "")))

        # --- COMBINA OS RESULTADOS ---
        final_result = {
            "orderNo": new_order_no,
            "otaOrderNo": order_details[0].get("otaOrderNo"),
            "pode_renovar": profile_info.get("renewFlag"),
            "data_limite_renovacao": profile_info.get("renewExpirationTime"),
            "eid": profile_info.get("eid"),
            "imsi": profile_info.get("imsi")
        }
        
        return jsonify(final_result), 200

    except Exception as e:
        print("!!!!!!!!!! ERRO DETALHADO EM /create_order !!!!!!!!!!")
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500



# Adicione esta função ao seu app.py do serviço tgt-esim-purchase
# --- NOVA ROTA PARA RENOVAR PEDIDOS ---
@app.route('/renew_order', methods=['POST'])
def renew_esim_order():
    try:
        request_body = request.get_json()
        if not request_body:
            return jsonify({"error": "Request body is missing"}), 400

        iccid = request_body.get("iccid")
        product_code = request_body.get("productCode")
        notify_url = request_body.get("notifyUrl")
        
        if not iccid or not product_code or not notify_url:
            return jsonify({"error": "Missing required fields: iccid, productCode, and notifyUrl"}), 400

        service_name = "renewOrder"
        endpoint = "saleOrderApi/renewOrder"
        
        data_payload = {
            "productCode": product_code,
            "iccid": iccid,
            "currency": request_body.get("currency", "USD"),
            "startDate": request_body.get("startDate", ""),
            "lang": request_body.get("lang", "en"),
            "otaOrderNo": request_body.get("otaOrderNo", ""),
            "email": request_body.get("email", ""),
            "notifyUrl": notify_url,
            "iccidAmount": 1,
            "requestId": request_body.get("requestId", "")
        }

        data_str = json.dumps(data_payload)
        encrypted_data = aes_encrypt(data_str)
        request_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        sign = create_signature(service_name, request_time, encrypted_data)
        
        final_payload = { "accountId": ACCOUNT_ID, "serviceName": service_name, "requestTime": request_time, "data": encrypted_data, "version": API_VERSION, "sign": sign }
        headers = {'Content-Type': 'application/json'}
        
        response = requests.post(BASE_URL + endpoint, data=json.dumps(final_payload), headers=headers, timeout=20)
        response.raise_for_status()
        
        response_json = response.json()

        if response_json.get("code") == "0000":
            decrypted_data = aes_decrypt(response_json["data"])
            return jsonify(json.loads(decrypted_data)), 200
        else:
            return jsonify({"error": response_json}), 400

    except Exception as e:
        print("!!!!!!!!!! ERRO DETALHADO EM /renew_order !!!!!!!!!!")
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500
        




# --- NOVA ROTA PARA DESCRIPTOGRAFAR NOTIFICAÇÕES ---
@app.route('/decrypt_notification', methods=['POST'])
def decrypt_notification():
    try:
        request_body = request.get_json()
        encrypted_data = request_body.get("data")
        if not encrypted_data:
            return jsonify({"error": "Missing 'data' field to decrypt"}), 400
        
        decrypted_data = aes_decrypt(encrypted_data)
        return jsonify(json.loads(decrypted_data)), 200

    except Exception as e:
        return jsonify({"error": "Decryption failed", "details": str(e)}), 500


# ==========================================
# --- INTEGRAÇÃO CMI (CHINA MOBILE) - FINAL ---
# ==========================================

# Adicione estas importações no topo do seu arquivo se ainda não estiverem lá:
# import base64
# import hashlib
# from uuid import uuid4

# --- Configurações de Produção CMI ---

# 1. URL (Sem espaços no final)
CMI_URL = os.environ.get("CMI_URL", "https://globalapi.udbac.com:18084/aep/APP_getSubscriberAllQuota_SBO/v2")

# 2. APP KEY (A causa do erro 1000002)
# Verifique se não há espaço antes do 'o' ou depois do 'w' dentro das aspas
CMI_APP_KEY = os.environ.get("CMI_APP_KEY", "o4rnH6VFc_vzqpDW-C5Xpoi-o8yw")

# 3. APP SECRET (Sua senha do portal)
# Se a senha estiver errada, daria erro 1000001. Como está dando 1000002, o foco é a KEY acima.
# Mas garanta que esta senha é a correta.
CMI_APP_SECRET = os.environ.get("CMI_APP_SECRET", "Peter@2023")

# Chaves FIXAS para Criptografia do Corpo (AES-128-CBC)
CMI_AES_KEY = b'u1d0b9a2c37U8d46'
CMI_AES_IV = b'1016449182184177'

# --- Funções Auxiliares CMI ---

def cmi_get_wsse_header():
    """
    Gera o cabeçalho X-WSSE seguindo a lógica Java fornecida pela CMI:
    Passo 1: passwordStr = nonce + created + appSecret
    Passo 2: hash = SHA256(passwordStr)
    Passo 3: PasswordDigest = Base64(hash)
    """
    # 1. Nonce: String aleatória (usando UUID hex para garantir unicidade e sem caracteres especiais)
    nonce = uuid4().hex 
    
    # 2. Created: Timestamp UTC no formato ISO 8601
    created = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    
    # 3. Concatenação (Java: passwordStr = nonce + created + appSecret)
    # Importante: A ordem é estrita e sem separadores
    raw_string = nonce + created + CMI_APP_SECRET
    
    # 4. Hashing (Java: digest.digest(passwordStr.getBytes()))
    # Usa SHA-256 e garante UTF-8
    sha256_bytes = hashlib.sha256(raw_string.encode('utf-8')).digest()
    
    # 5. Encoding (Java: Base64.encodeBase64String(hash))
    password_digest = base64.b64encode(sha256_bytes).decode('utf-8')

    return {
        'Authorization': 'WSSE realm="SDP", profile="UsernameToken", type="Appkey"',
        'X-WSSE': f'UsernameToken Username="{CMI_APP_KEY}", PasswordDigest="{password_digest}", Nonce="{nonce}", Created="{created}"'
    }

def cmi_encrypt_body(payload_dict):
    """
    Criptografa o payload JSON usando AES-128-CBC.
    Retorna uma string Base64.
    """
    try:
        # O payload deve ser uma string JSON
        json_str = json.dumps(payload_dict)
        
        # Configura a cifra AES
        cipher = AES.new(CMI_AES_KEY, AES.MODE_CBC, CMI_AES_IV)
        
        # Faz o Padding (preenchimento) para múltiplo de 16 bytes
        padded_data = pad(json_str.encode('utf-8'), AES.block_size)
        
        # Criptografa
        encrypted_bytes = cipher.encrypt(padded_data)
        
        # Retorna como Base64
        return base64.b64encode(encrypted_bytes).decode('utf-8')
    except Exception as e:
        print(f"Erro na criptografia CMI: {str(e)}")
        raise

def cmi_decrypt_response(encrypted_base64_str):
    """
    Descriptografa a resposta da CMI (Base64 -> AES -> JSON).
    """
    try:
        if not encrypted_base64_str:
            return {}
            
        # Decodifica Base64
        encrypted_bytes = base64.b64decode(encrypted_base64_str)
        
        # Configura a cifra para descriptografar
        cipher = AES.new(CMI_AES_KEY, AES.MODE_CBC, CMI_AES_IV)
        
        # Descriptografa e remove o Padding
        decrypted_padded = cipher.decrypt(encrypted_bytes)
        decrypted_data = unpad(decrypted_padded, AES.block_size)
        
        # Converte bytes de volta para JSON
        return json.loads(decrypted_data.decode('utf-8'))
    except Exception as e:
        # Se falhar (ex: resposta não cifrada de erro), retorna o original para debug
        return {"raw_response": str(encrypted_base64_str), "decrypt_error": str(e)}

# --- Rota Principal para o Make.com (Versão Ultra-Segura) ---
@app.route('/cmi_check_usage', methods=['POST'])
def cmi_check_usage():
    try:
        # 1. Validação de Entrada
        request_body = request.get_json() or {}
        iccid = request_body.get("iccid")
        
        if not iccid:
            return jsonify({"error": "ICCID é obrigatório"}), 400

        # 2. Criptografia (Tratada para evitar 500)
        try:
            raw_payload = { "iccid": iccid, "uuid": str(uuid4()) }
            encrypted_body = cmi_encrypt_body(raw_payload)
        except Exception as e:
            return jsonify({"error": "Falha interna na criptografia AES", "details": str(e)}), 500

        # 3. Preparar Headers
        try:
            headers = cmi_get_wsse_header()
            headers['Content-Type'] = 'application/json'
            headers['Accept'] = 'application/json'
        except Exception as e:
            return jsonify({"error": "Falha ao gerar header WSSE", "details": str(e)}), 500

        # 4. Envio para CMI (Tratando erro de Conexão)
        print(f"Enviando requisicao para: {CMI_URL}")
        try:
            # Timeout reduzido para 25s para não estourar o limite do Render/Make
            response = requests.post(CMI_URL, data=encrypted_body, headers=headers, timeout=25)
        except requests.exceptions.Timeout:
            return jsonify({"error": "Timeout: A CMI demorou muito para responder", "url": CMI_URL}), 504
        except requests.exceptions.ConnectionError:
            return jsonify({"error": "Erro de Conexão: Não foi possível conectar ao servidor da CMI", "url": CMI_URL}), 502
        except Exception as e:
            return jsonify({"error": "Erro desconhecido na requisição HTTP", "details": str(e)}), 500

        # 5. Tratamento da Resposta
        
        # Cenário A: CMI retornou erro de negócio (JSON legível, ex: 1000002)
        try:
            resp_json = response.json()
            # Se for um JSON válido e tiver 'code', retornamos como erro 400 (Bad Request)
            # para o Make entender que foi recusado, mas não é falha do servidor.
            if isinstance(resp_json, dict) and "code" in resp_json:
                return jsonify(resp_json), 400
        except ValueError:
            # Se não for JSON, pode ser a string criptografada de sucesso. Continuamos.
            pass

        # Cenário B: Tentativa de Descriptografar Sucesso
        try:
            result = cmi_decrypt_response(response.text)
            return jsonify(result), 200
        except Exception as e:
            # Se chegou aqui, a CMI respondeu algo que não é JSON erro nem criptografia válida
            # Pode ser uma página HTML de erro (Proxy Error, 404, etc)
            return jsonify({
                "error": "Falha ao ler resposta da CMI", 
                "http_status": response.status_code,
                "raw_preview": response.text[:200], # Mostra o começo da resposta para debug
                "decrypt_error": str(e)
            }), 502

    except Exception as e:
        # Última linha de defesa
        traceback.print_exc()
        return jsonify({"critical_error": "O script Python falhou", "details": str(e)}), 500

    except Exception as e:
        # Erro geral do Python (bug no código)
        print("!!!!!!!!!! ERRO CRÍTICO !!!!!!!!!!")
        traceback.print_exc()
        return jsonify({"server_error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=False)
