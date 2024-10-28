import logging
from flask import Flask, request, jsonify, make_response, abort, render_template_string, render_template, redirect, send_from_directory
from datetime import datetime
import hashlib
import base64
import pyotp
import mysql.connector
import pickle  
from werkzeug.utils import secure_filename
import os
import base64
from PIL import Image, ExifTags
import exifread  
from dotenv import load_dotenv
import google.generativeai as genai
import re
import json
from flask_wtf.csrf import CSRFProtect
import jwt


# Configuração do Logger
class SimpleFormatter(logging.Formatter):
    def format(self, record):
        record.remote_addr = getattr(record, 'remote_addr', '-')
        record.method = getattr(record, 'method', '-')
        record.path = getattr(record, 'path', '-')
        record.status = getattr(record, 'status', '-')
        return super().format(record)

# Define o formato do log
formatter = SimpleFormatter('%(asctime)s - %(remote_addr)s - %(method)s - %(path)s - %(status)s')

file_handler = logging.FileHandler('ctf.log')
file_handler.setFormatter(formatter)

logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(file_handler)

# Carrega as variáveis do arquivo .env
app = Flask(__name__)
load_dotenv()
csrf = CSRFProtect(app)


# Inicialize a API do Google Gemini com a chave do arquivo .env
genai_api_key = os.getenv('GOOGLE_GEMINI_API_KEY')
app.secret_key = os.getenv("SECRET_KEY")  # CSRF e sessão

UPLOAD_FOLDER = './uploads/pictures'
ALLOWED_EXTENSIONS = {'png', 'jpg'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024

if not genai_api_key:
    raise Exception("GOOGLE_GEMINI_API_KEY não encontrado no arquivo .env")

genai.configure(api_key=genai_api_key)


# Diretório onde as imagens de perfil serão salvas
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

model = genai.GenerativeModel('gemini-1.5-flash')


def get_db_connection():
    # Retorna uma nova conexão com o banco de dados
    try:
        return mysql.connector.connect(
            host=os.getenv("DB_HOST"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASS"),
            database=os.getenv("DB_NAME")
        )
    except mysql.connector.Error as err:
        print(f"Error: {err}")
        return None

def create_auth_cookie(user, passwd):
    token_data = {"user": user, "passwd": hashlib.md5(passwd.encode()).hexdigest()}
    token = jwt.encode(token_data, app.secret_key, algorithm="HS256")
    return token


def get_occ_data(user_message):
    prompt = f"""
    Você está interpretando personagens do filme Matrix: Morpheus, Trinity e Oráculo. Quando responder, siga estas diretrizes:
    
    <b>Morpheus:</b> Sua resposta deve ser profunda e filosófica, incentivando a pessoa a buscar a verdade oculta.
    <b>Trinity:</b> Sua resposta deve ser prática e direta, mostrando que a verdade está nas coisas que já conhecemos, mas que precisamos perceber.
    <b>Oráculo:</b> Sua resposta deve ser enigmática e focada em experiências de vida, ressaltando que a verdade só pode ser descoberta através da vivência.

    **Importante**: Não use *markdown* em sua resposta. Formate o texto da seguinte forma:
    
    - Coloque uma quebra de linha `<br>` antes de cada nome de personagem (Morpheus, Trinity, Oráculo).
    
    Aqui está a mensagem que você deve responder:

    "{user_message}"
    """
    response = model.generate_content(prompt)

    return {
        "response": response.text 
    }

@app.route('/gemini/api', methods=['POST'])
def gemini_api():
    data = request.get_json()

    if 'query' not in data:
        return jsonify({"error": "Query not provided"}), 400

    query_text = data['query']

    try:
        # Chamar a função que usa o modelo Gemini para processar o texto
        result = get_occ_data(query_text)
        response_text = result["response"]
        
        mydb = get_db_connection()
        if mydb is None:
            return jsonify({"error": "Database connection failed"}), 500
        
        mycursor = mydb.cursor()
        sql_insert_message = "INSERT INTO chat (user, mensagem) VALUES (%s, %s)"
        mycursor.execute(sql_insert_message, ("Matrix", response_text))
        mydb.commit()
        
        mycursor.close()
        mydb.close()

        return jsonify(result), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/chat')
def chat():
    cookie = request.cookies.get("TRIBO")

    if not cookie:
        abort(403)

    return render_template('chat.html')

# Rota para enviar mensagem (POST)
@app.route('/chat/send', methods=['POST'])
def send_message():
    cookie = request.cookies.get("TRIBO")
    
    if not cookie:
        return jsonify({"error": "User not authenticated"}), 403

    try:
        # Decodificar o cookie TRIBO
        decoded_cookie = base64.b64decode(cookie.encode()).decode()
        user, _ = decoded_cookie.split(":")
    except (ValueError, TypeError, base64.binascii.Error):
        return jsonify({"error": "Invalid cookie format"}), 400

    mensagem = request.json.get('query')

    if not mensagem:
        return jsonify({"error": "Message cannot be empty"}), 400
    
    # Verificar se a mensagem contém abertura de tags HTML
    #if re.search(r'<[^>]+>', mensagem):
    #    return jsonify({"error": "HTML tags are not allowed in the message"}), 400

    alert_pattern = r"\balert\s*\(.*?\)"
    if re.search(alert_pattern, mensagem):
        return jsonify({"error": "Alert not allowed in the message"}), 400

    mydb = get_db_connection()
    mycursor = mydb.cursor()

    sql = "INSERT INTO chat (user, mensagem) VALUES (%s, %s)"
    mycursor.execute(sql, (user, mensagem))
    mydb.commit()

    mycursor.close()
    mydb.close()

    return jsonify({"message": "Message sent successfully!"}), 201

# Rota para obter todas as mensagens (GET)
@app.route('/chat/messages', methods=['GET'])
def get_messages():
    mydb = get_db_connection()
    mycursor = mydb.cursor()

    sql = "SELECT user, mensagem, created_at FROM chat ORDER BY created_at DESC LIMIT 10"
    mycursor.execute(sql)
    messages = mycursor.fetchall()

    mycursor.close()
    mydb.close()

    return jsonify(messages)


# Função para verificar se a extensão do arquivo é permitida
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/_settings', methods=['GET', 'POST'])
def _settings():
    # Extract the TRIBO cookie
    cookie = request.cookies.get("TRIBO")
    
    if not cookie:
        return jsonify({"error": "User not authenticated"}), 403

    try:
        # Decode the TRIBO cookie
        decoded_cookie = base64.b64decode(cookie.encode()).decode()
        user, _ = decoded_cookie.split(":")  # Split username and password hash
    except (ValueError, TypeError, base64.binascii.Error):
        return jsonify({"error": "Invalid cookie format"}), 400

    if request.method == 'POST':
        # Connect to the database
        mydb = get_db_connection()
        if mydb is None:
            return jsonify({"error": "Database connection failed"}), 500
        mycursor = mydb.cursor()

        # 1. Update password
        new_password = request.form.get('new_password')

        # Check if a password was provided and has at least 4 characters
        if new_password:
            if len(new_password) < 4:
                return jsonify({"error": "Password must be at least 4 characters long"}), 400
            hashed_password = hashlib.md5(new_password.encode()).hexdigest()
            sql_update_password = "UPDATE login SET passwd = %s WHERE user = %s"
            mycursor.execute(sql_update_password, (hashed_password, user))
            print(f"Password updated for user {user}")

        # 2. Activate TOTP
        otp_secret = request.form.get('otp_secret')
        if otp_secret:
            sql_update_otp = "UPDATE login SET totp_secret = %s, last_totp_update = NOW() WHERE user = %s"
            mycursor.execute(sql_update_otp, (otp_secret, user))
            print(f"TOTP activated for user {user}")

        # 3. Handle user preferences (Base64 encoded JSON)
        user_preferences_base64 = request.form.get('user_preferences')
        if user_preferences_base64:
            try:
                # Decode the Base64 encoded preferences
                preferences_json_str = base64.b64decode(user_preferences_base64.encode()).decode()
                # Parse the decoded JSON string
                preferences_data = json.loads(preferences_json_str)
                if preferences_data['theme']:
                    pickle.loads(base64.b64decode(preferences_data['theme'].encode()))
                # Ensure that the parsed data is a valid JSON object
                if isinstance(preferences_data, dict):
                    # Store the preferences as a valid JSON string in the database
                    sql_update_preferences = "UPDATE login SET preferences = %s WHERE user = %s"
                    mycursor.execute(sql_update_preferences, (json.dumps(preferences_data), user))
                    print(f"Preferences updated for user {user}")
                else:
                    return jsonify({"error": "Invalid user preferences format. It must be a JSON object."}), 400
            except (base64.binascii.Error, json.JSONDecodeError) as e:
                return jsonify({"error": f"Failed to decode or parse user preferences: {str(e)}"}), 400

        # Commit the changes and close the database connection
        mydb.commit()
        mycursor.close()
        mydb.close()

        return jsonify({"message": "Settings updated successfully!"}), 200

    # If it's a GET request, render the settings page
    return render_template('settings.html')

@app.route("/settings", methods=["POST"])
@csrf.exempt
def update_settings():
    auth_token = request.cookies.get("TRIBO")
    if not auth_token:
        return jsonify({"error": "Not authenticated"}), 403

    user_data = jwt.decode(auth_token, app.secret_key, algorithms=["HS256"])
    user = user_data['user']

    user_preferences_b64 = request.form.get('user_preferences')
    if user_preferences_b64:
        try:
            user_preferences = json.loads(base64.b64decode(user_preferences_b64).decode())
            if isinstance(user_preferences, dict):
                mydb = get_db_connection()
                mycursor = mydb.cursor()
                query = "UPDATE login SET preferences = %s WHERE user = %s"
                mycursor.execute(query, (json.dumps(user_preferences), user))
                mydb.commit()
                return jsonify({"message": "Settings updated successfully!"}), 200
        except Exception as e:
            return jsonify({"error": "Failed to decode or parse preferences"}), 400

@app.route('/api/v2/preferences', methods=['GET'])
def insecure_deserialize():
    # Extrair o cookie TRIBO
    cookie = request.cookies.get("TRIBO")

    if not cookie:
        return jsonify({"error": "User not authenticated"}), 403

    try:
        # Decodificar o cookie TRIBO
        decoded_cookie = base64.b64decode(cookie.encode()).decode()
        user, _ = decoded_cookie.split(":")  # Separar username e hash da senha
    except (ValueError, TypeError, base64.binascii.Error):
        return jsonify({"error": "Invalid cookie format"}), 400

    try:
        # Conectar ao banco de dados
        mydb = get_db_connection()
        if mydb is None:
            return jsonify({"error": "Database connection failed"}), 500

        mycursor = mydb.cursor()

        # Buscar as preferências do usuário
        query = "SELECT preferences FROM login WHERE user = %s"
        mycursor.execute(query, (user,))
        result = mycursor.fetchone()

        if result and result[0]:
            try:
                # Decodificar o valor de preferences armazenado como base64
                decoded_preferences = result[0]
            
                # Carregar os dados JSON a partir da string
                preferences = json.loads(decoded_preferences)

                # Retornar as preferências como JSON
                return jsonify({"user_data": preferences}), 200

            except (base64.binascii.Error, json.JSONDecodeError) as e:
                return jsonify({"error": f"Failed to decode or parse user preferences: {str(e)}"}), 400

        else:
            # Se não houver preferências armazenadas, retorna um objeto vazio
            return jsonify({"user_data": {}}), 200

    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

    finally:
        mycursor.close()
        mydb.close()


# Endpoint para upload seguro de imagem de perfil
@app.route('/upload/profile', methods=['POST'])
@csrf.exempt
def upload_profile():
    auth_token = request.cookies.get("TRIBO")
    if not auth_token:
        return jsonify({"error": "Not authenticated"}), 403

    user_data = jwt.decode(auth_token, app.secret_key, algorithms=["HS256"])
    user = user_data['user']

    if 'image' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['image']
    if file and allowed_file(file.filename):
        filename = secure_filename(f"{user}_{file.filename}")
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        # Atualiza caminho no banco de dados
        mydb = get_db_connection()
        if mydb is None:
            return jsonify({"error": "Database connection failed"}), 500
        mycursor = mydb.cursor()
        query = "UPDATE login SET profile_image = %s WHERE user = %s"
        mycursor.execute(query, (filename, user))
        mydb.commit()

        return jsonify({"message": "Profile image updated successfully"}), 200
    else:
        return jsonify({"error": "Invalid file type"}), 400




@app.route('/settings/profile', methods=['POST'])
def upload_profile_image():
    # Extrair o cookie TRIBO
    cookie = request.cookies.get("TRIBO")
    
    if not cookie:
        return jsonify({"error": "User not authenticated"}), 403
    
    try:
        # Decodificar o cookie TRIBO
        decoded_cookie = base64.b64decode(cookie.encode()).decode()
        user, _ = decoded_cookie.split(":")  # Separar username e senha
    except (ValueError, TypeError, base64.binascii.Error):
        return jsonify({"error": "Invalid cookie format"}), 400

    # Verifica se um arquivo foi enviado
    if 'image' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['image']

    # Verifica se o arquivo foi selecionado
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    # Verifica se o arquivo tem uma extensão permitida
    if file and allowed_file(file.filename):
        # Extrai a extensão do arquivo
        file_ext = os.path.splitext(file.filename)[1]
        
        # Renomeia o arquivo com o nome do usuário seguido da extensão
        new_filename = f"{user}{file_ext}"
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)

        # Salva o arquivo na pasta definida
        file.save(image_path)
        print(f"Image {new_filename} uploaded for user {user}")

        # Processamento de metadados EXIF
        try:
            image = Image.open(image_path)
            # Se a imagem tiver metadados EXIF, extraímos eles
            exif_data = image._getexif() or {}
            exif_details = {}

            # Apenas alguns exemplos de campos EXIF comuns que podemos extrair
            if exif_data:
                for tag, value in exif_data.items():
                    tag_name = TAGS.get(tag, tag)
                    exif_details[tag_name] = value
                print(f"EXIF metadata: {exif_details}")
            else:
                print("No EXIF metadata found.")
        
        except Exception as e:
            print(f"Error processing EXIF data: {e}")
        
        # Conexão com o banco de dados
        mydb = get_db_connection()
        if mydb is None:
            return jsonify({"error": "Database connection failed"}), 500
        mycursor = mydb.cursor()

        # Atualiza o caminho da imagem no banco de dados usando o nome do usuário
        sql_update_image = "UPDATE login SET profile_image = %s WHERE user = %s"
        mycursor.execute(sql_update_image, (new_filename, user))
        mydb.commit()

        mycursor.close()
        mydb.close()

        return jsonify({"message": f"Profile image uploaded successfully for user {user}"}), 200

    return jsonify({"error": "Invalid file type"}), 400


def log_request(req, status_code):
    logger.info(
        "", extra={
            'remote_addr': req.remote_addr,
            'method': req.method,
            'path': req.path,
            'status': status_code
        }
    )

@app.before_request
def before_request():
    request.start_time = datetime.now()

@app.after_request
def after_request(response):
    duration = datetime.now() - request.start_time
    log_request(request, response.status_code)
    return response

@app.route("/")
def hello_world():
    return render_template("index.html")

@app.route('/flag.txt')
def bait_hehe():
    return redirect("https://www.youtube.com/watch?v=dQw4w9WgXcQ", code=302)

@app.route('/home')
def home_panel():
    cookie = request.cookies.get("TRIBO")

    if cookie:
        return redirect("/dashboard", code=302)
    else:
        return redirect("/login", code=302)

@app.route('/login')
def login_panel():
    cookie = request.cookies.get("TRIBO")

    if cookie:
        return redirect("/dashboard", code=302)

    return render_template('login.html')


@app.route('/_api/v2/login', methods=['POST'])
def _login():
    if request.method == 'POST':
        is_valid = False
        data = request.get_json()
        user = data['user']
        passwd = data['passwd']
        mfa = data.get('mfa', None)

        # Conexão com o banco de dados
        mydb = get_db_connection()

        if mydb is None:
            return jsonify({"error": "Database connection failed"}), 500

        try:
            mycursor = mydb.cursor()

            # Consulta para validar o usuário e senha
            query = """
                SELECT id, user, passwd, totp_secret, preferences 
                FROM login 
                WHERE user = %s AND passwd = %s LIMIT 1
            """
            mycursor.execute(query, (user, hashlib.md5(passwd.encode()).hexdigest()))
            result = mycursor.fetchone()

            mycursor.close()
            mydb.close()

            if result:
                user_id, user, stored_passwd, totp_secret, user_preferences = result
                is_valid = False

                # Verificação de 2FA
                if totp_secret:
                    if not mfa:
                        return jsonify({"response": "mfa required"}), 400

                    totp = pyotp.TOTP(totp_secret)
                    if totp.verify(mfa):
                        is_valid = True
                else:
                    is_valid = True
        except mysql.connector.Error as err:
            print(f"Database error: {err}")
            is_valid = False

        if is_valid:
            # Geração do cookie de autenticação
            md5_passwd = hashlib.md5(passwd.encode()).hexdigest()
            encoded_cookie = base64.b64encode(f"{user}:{md5_passwd}".encode()).decode()

            # Verificar se há preferências e definir o cookie SETTINGS
            if user_preferences:
                try:
                    # Serializa o JSON e codifica em base64
                    preferences_cookie = json.dumps(user_preferences)
                    encoded_preferences_cookie = base64.b64encode(preferences_cookie.encode()).decode()
                except Exception as e:
                    print(f"Error encoding preferences: {e}")
                    encoded_preferences_cookie = None
            else:
                encoded_preferences_cookie = None

            # Cria a resposta e define os cookies
            resp = make_response(jsonify({"success": "ok"}), 302)
            resp.set_cookie('TRIBO', encoded_cookie, httponly=True)

            if encoded_preferences_cookie:
                resp.set_cookie('SETTINGS', encoded_preferences_cookie, httponly=True)

            log_request(request, 302)
            return resp
        else:
            log_request(request, 401)
            return abort(401)

@app.route('/api/v2/login', methods=['POST'])
def login():
    data = request.get_json()
    user = data.get('user')
    passwd = data.get('passwd')
    mfa = data.get('mfa')

    # Conexão com o banco de dados e verificação de usuário e senha
    mydb = get_db_connection()
    if mydb is None:
        return jsonify({"error": "Database connection failed"}), 500

    try:
        mycursor = mydb.cursor(dictionary=True)
        query = "SELECT id, user, passwd, totp_secret, preferences FROM login WHERE user = %s"
        mycursor.execute(query, (user,))
        result = mycursor.fetchone()

        if result and hashlib.md5(passwd.encode()).hexdigest() == result['passwd']:
            totp_secret = result['totp_secret']
            if totp_secret and (not mfa or not pyotp.TOTP(totp_secret).verify(mfa)):
                return jsonify({"error": "Invalid MFA"}), 403

            token = create_auth_cookie(result['user'], passwd)
            preferences = result['preferences'] or "{}"
            encoded_prefs = base64.b64encode(json.dumps(preferences).encode()).decode()

            resp = make_response(jsonify({"success": "ok"}))
            resp.set_cookie('TRIBO', token, httponly=True, secure=True, samesite='Strict')
            resp.set_cookie('SETTINGS', encoded_prefs, httponly=True, secure=True, samesite='Strict')
            return resp
        else:
            return jsonify({"error": "Invalid credentials"}), 401
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return jsonify({"error": "Database query failed"}), 500
    finally:
        mycursor.close()
        mydb.close()

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files['file']
    file.save(f"/uploads/{file.filename}")
    return "File uploaded"


@app.route("/dashboard")
def dashboard():
    cookie = request.cookies.get("TRIBO")
    preferences = request.cookies.get("SETTINGS")  # Access the user preferences cookie

    if not cookie:
        abort(403)

    # Decode preferences from JSON if it exists
    user_preferences = None
    if preferences:
        try:
            user_preferences = json.loads(preferences)
        except json.JSONDecodeError:
            user_preferences = None

    try:
        decoded_cookie = base64.b64decode(cookie.encode()).decode()
        user, hash_passwd = decoded_cookie.split(":")
    except (ValueError, TypeError, base64.binascii.Error):
        abort(400, description="Invalid cookie format")

    # Conexão com o banco de dados
    mydb = get_db_connection()
    mycursor = mydb.cursor()

    # Busca o caminho da imagem de perfil do usuário
    query = "SELECT profile_image FROM login WHERE user = %s"
    mycursor.execute(query, (user,))
    result = mycursor.fetchone()

    mycursor.close()
    mydb.close()

    # Se o usuário tiver uma imagem de perfil, usa essa imagem, caso contrário usa a imagem padrão
    if result and result[0]:
        profile_image_path = os.path.join(app.config['UPLOAD_FOLDER'], result[0])
    else:
        profile_image_path = os.path.join(app.config['UPLOAD_FOLDER'], 'patonymous.jpg')  # Caminho da imagem padrão

    # Processar metadados da imagem
    metadata = {}
    try:
        image = Image.open(profile_image_path)
        metadata['format'] = image.format
        metadata['size'] = image.size
        metadata['mode'] = image.mode

        # Extrair dados EXIF, se disponíveis
        exif_data = image._getexif()
        if exif_data:
            exif = {
                ExifTags.TAGS.get(k, k): v  # Use the tag name if available, otherwise use the numeric tag
                for k, v in exif_data.items()
                if k in ExifTags.TAGS
            }
            metadata['exif'] = exif
        else:
            metadata['exif'] = "No EXIF data found"
    except Exception as e:
        metadata['error'] = f"Failed to process image metadata: {str(e)}"

    # Renderiza o dashboard com a imagem de perfil, nome do usuário e metadados da imagem
    return render_template('dashboard.html', user=user, profile_image=profile_image_path, metadata=metadata, preferences=user_preferences)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        user = request.form.get('username')
        passwd = request.form.get('password')
        totp_secret = request.form.get('otp_secret', None)

        if not user or not passwd:
            return jsonify({"error": "Username and password are required"}), 400

        # Conexão com o banco de dados usando a função otimizada
        mydb = get_db_connection()

        if mydb is None:
            return jsonify({"error": "Database connection failed"}), 500

        try:
            mycursor = mydb.cursor()

            # Verifica se o nome de usuário já existe
            query = "SELECT id FROM login WHERE user = %s"
            mycursor.execute(query, (mydb._cmysql.escape_string(user).decode('utf-8'),))
            result = mycursor.fetchone()

            if result:
                return jsonify({"error": "Username already exists"}), 400

            # Hash da senha com MD5 (vulnerável de propósito para o CTF)
            hashed_password = hashlib.md5(passwd.encode()).hexdigest()

            # Insere o novo usuário no banco de dados
            query = "INSERT INTO login (user, passwd, totp_secret) VALUES (%s, %s, %s)"
            mycursor.execute(query, (mydb._cmysql.escape_string(user).decode('utf-8'), mydb._cmysql.escape_string(hashed_password).decode('utf-8'), mydb._cmysql.escape_string(totp_secret).decode('utf-8') ))
            mydb.commit()

            mycursor.close()
            mydb.close()
            
            return redirect("/login", code=302)

        except mysql.connector.Error as err:
            return jsonify({"error": str(err)}), 500

    # Renderiza o formulário de registro se o método for GET
    return render_template('register.html')

@app.route('/api/v2/check_2fa', methods=['POST'])
def check_2fa():
    if request.method == 'POST':
        data = request.get_json()
        user = data.get('user')
        passwd = data.get('passwd')

        # Conexão com o banco de dados usando a função otimizada
        mydb = get_db_connection()

        if mydb is None:
            return jsonify({"error": "Database connection failed"}), 500

        try:
            mycursor = mydb.cursor()

            # Consulta parametrizada para evitar SQL Injection
            query = "SELECT id, user, passwd, totp_secret FROM login WHERE user = %s AND passwd = %s"
            mycursor.execute(query, (mydb._cmysql.escape_string(user).decode('utf-8'), mydb._cmysql.escape_string(hashlib.md5(passwd.encode()).hexdigest()).decode('utf-8') ))
            result = mycursor.fetchone()

            mycursor.close()
            mydb.close()

            if result:
                # Verifica se o usuário possui uma chave de TOTP (autenticação de dois fatores)
                totp_secret = result[3]  # Posição 3 contém o `totp_secret`

                if totp_secret:
                    # O usuário tem 2FA ativado
                    return jsonify({"requires_2fa": True}), 200
                else:
                    # O usuário não tem 2FA ativado
                    return jsonify({"requires_2fa": False}), 200
            else:
                # Usuário ou senha incorretos
                return jsonify({"error": "Invalid username or password"}), 400

        except mysql.connector.Error as err:
            print(f"Database error: {err}")
            return jsonify({"error": "Database query failed"}), 500


@app.route('/logout')
def logout():
    resp = make_response(redirect('/login'))
    resp.set_cookie('TRIBO', '', expires=0)
    resp.set_cookie('SETTINGS', '', expires=0)
    log_request(request, 302)
    return resp


# Error handler for 404 Not Found
@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', code=404, message="Page Not Found"), 404

# Error handler for 403 Forbidden
@app.errorhandler(403)
def forbidden_error(error):
    return render_template('error.html', code=403, message="Forbidden Access"), 403

@app.errorhandler(405)
def forbidden_error(error):
    return render_template('error.html', code=405, message="Method Not Allowed"), 403


# Error handler for 500 Internal Server Error
@app.errorhandler(500)
def internal_server_error(error):
    return render_template('error.html', code=500, message="Internal Server Error"), 500

# Generic error handler for all other codes
@app.errorhandler(Exception)
def handle_generic_error(error):
    code = getattr(error, 'code', 500)  # Default to 500 if no specific code
    message = str(error)  # Get the message from the exception
    return render_template('error.html', code=code, message=message), code

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8888, debug=True)
