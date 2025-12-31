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
# --- INTEGRAÇÃO CMI (CHINA MOBILE) ---
# ==========================================

# --- Configurações CMI ---
# Configure estas variáveis no Painel do Render (Environment Variables)
# Se preferir hardcoded (não recomendado para github público), substitua os valores aqui.
CMI_URL = os.environ.get("CMI_URL", "https://globalapi.udbac.com:18084/aep/APP_getSubscriberAllQuota_SBO/v2")
CMI_APP_KEY = os.environ.get("CMI_APP_KEY", "o4rnH6VFc_vzqpDW-C5Xpoi-o8yw") # Sua AppKey de Produção
CMI_APP_SECRET = os.environ.get("CMI_APP_SECRET", "Peter@2023") # IMPORTANTE: Preencha ou use ENV var

# Chaves FIXAS para Criptografia do Corpo (AES-128-CBC) conforme documentação CMI
CMI_AES_KEY = b'u1d0b9a2c37U8d46'
CMI_AES_IV = b'1016449182184177'

# --- Funções Auxiliares CMI ---

def cmi_get_wsse_header():
    """Gera o cabeçalho de autenticação WSSE exigido pela CMI."""
    # 1. Nonce (Aleatório)
    nonce = hashlib.md5(str(uuid4()).encode('utf-8')).hexdigest()
    
    # 2. Created (Timestamp UTC ISO 8601)
    created = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    
    # 3. PasswordDigest = Base64(SHA256(Nonce + Created + Password))
    # Nota: O Nonce é concatenado como string
    raw_string = nonce + created + CMI_APP_SECRET
    
    sha256_hash = hashlib.sha256(raw_string.encode('utf-8')).digest()
    password_digest = base64.b64encode(sha256_hash).decode('utf-8')

    return {
        'Authorization': 'WSSE realm="SDP", profile="UsernameToken", type="Appkey"',
        'X-WSSE': f'UsernameToken Username="{CMI_APP_KEY}", PasswordDigest="{password_digest}", Nonce="{nonce}", Created="{created}"'
    }

def cmi_encrypt_body(payload_dict):
    """Criptografa o JSON usando AES-128-CBC e retorna Base64 string."""
    try:
        # A CMI espera que o payload seja uma string JSON
        json_str = json.dumps(payload_dict)
        
        cipher = AES.new(CMI_AES_KEY, AES.MODE_CBC, CMI_AES_IV)
        # Pad usando PKCS7 (padrão do block_size AES)
        padded_data = pad(json_str.encode('utf-8'), AES.block_size)
        encrypted_bytes = cipher.encrypt(padded_data)
        
        # Retorna em Base64 (diferente da Tuge que usa Hex)
        return base64.b64encode(encrypted_bytes).decode('utf-8')
    except Exception as e:
        print(f"Erro na criptografia CMI: {str(e)}")
        raise

def cmi_decrypt_response(encrypted_base64_str):
    """Descriptografa a resposta da CMI (Base64 -> AES-128-CBC -> JSON)."""
    try:
        if not encrypted_base64_str:
            return {}
            
        encrypted_bytes = base64.b64decode(encrypted_base64_str)
        cipher = AES.new(CMI_AES_KEY, AES.MODE_CBC, CMI_AES_IV)
        decrypted_padded = cipher.decrypt(encrypted_bytes)
        
        decrypted_data = unpad(decrypted_padded, AES.block_size)
        return json.loads(decrypted_data.decode('utf-8'))
    except Exception as e:
        # Se falhar, pode ser que a resposta não esteja criptografada (ex: erro de gateway)
        print(f"Erro/Aviso na descriptografia CMI: {str(e)}")
        # Tenta retornar como string pura caso seja um erro de texto plano
        return {"raw_response": str(encrypted_base64_str)}

# --- Rota CMI ---

@app.route('/cmi_check_usage', methods=['POST'])
def cmi_check_usage():
    try:
        request_body = request.get_json()
        iccid = request_body.get("iccid")
        
        if not iccid:
            return jsonify({"error": "ICCID is required"}), 400

        # 1. Montar Payload Bruto
        # O endpoint getSubscriberAllQuota requer 'iccid' e 'uuid'
        raw_payload = {
            "iccid": iccid,
            "uuid": str(uuid4())
        }

        # 2. Criptografar Corpo
        encrypted_body = cmi_encrypt_body(raw_payload)

        # 3. Gerar Headers
        headers = cmi_get_wsse_header()
        headers['Content-Type'] = 'application/json'
        headers['Accept'] = 'application/json'

        # 4. Enviar Requisição
        # Importante: O corpo vai como texto puro (a string criptografada), não como JSON {data: ...}
        print(f"Consultando CMI para ICCID: {iccid}")
        response = requests.post(CMI_URL, data=encrypted_body, headers=headers, timeout=30)
        
        # 5. Processar Resposta
        # A CMI retorna o status 200 mesmo se houver erro de negócio, mas o corpo vem cifrado.
        # Se houver erro HTTP (4xx, 5xx), tentamos ler também.
        
        try:
            # Tenta descriptografar a resposta
            decrypted_json = cmi_decrypt_response(response.text)
            
            # Se o status code for erro, retorna o JSON descriptografado com o status code original
            if response.status_code >= 400:
                return jsonify(decrypted_json), response.status_code
                
            return jsonify(decrypted_json), 200

        except Exception as decrypt_error:
            # Se não conseguiu descriptografar, retorna o texto original
            return jsonify({
                "error": "Failed to decrypt CMI response", 
                "raw": response.text,
                "status": response.status_code
            }), 500

    except Exception as e:
        print("!!!!!!!!!! ERRO EM /cmi_check_usage !!!!!!!!!!")
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=False)
