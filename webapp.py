# webapp.py - Price Finder USA con OpenAI Agent
from flask import Flask, request, jsonify, session, redirect, url_for, render_template_string, flash
import requests
import os
import re
import html
import time
import io
import json
import base64
from datetime import datetime
from urllib.parse import urlparse, quote_plus
from functools import wraps

# Imports para procesamiento de imagen
try:
    from PIL import Image
    PIL_AVAILABLE = True
    print("PIL (Pillow) disponible para procesamiento de imagen")
except ImportError:
    PIL_AVAILABLE = False
    print("PIL (Pillow) no disponible - busqueda por imagen limitada")

try:
    import openai
    OPENAI_AVAILABLE = True
    print("OpenAI disponible")
except ImportError:
    openai = None
    OPENAI_AVAILABLE = False
    print("OpenAI no disponible - instalar con: pip install openai")

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'fallback-key-change-in-production')
app.config['PERMANENT_SESSION_LIFETIME'] = 1800
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True if os.environ.get('RENDER') else False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max

# Configuracion de OpenAI
OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY')
if OPENAI_AVAILABLE and OPENAI_API_KEY:
    try:
        openai.api_key = OPENAI_API_KEY
        print("API de OpenAI configurada correctamente")
        OPENAI_READY = True
    except Exception as e:
        print(f"Error configurando OpenAI: {e}")
        OPENAI_READY = False
elif OPENAI_AVAILABLE and not OPENAI_API_KEY:
    print("OpenAI disponible pero falta OPENAI_API_KEY en variables de entorno")
    OPENAI_READY = False
else:
    print("OpenAI no esta disponible - funcionalidades limitadas")
    OPENAI_READY = False

# Firebase Auth Class
class FirebaseAuth:
    def __init__(self):
        self.firebase_web_api_key = os.environ.get("FIREBASE_WEB_API_KEY")
        if not self.firebase_web_api_key:
            print("WARNING: FIREBASE_WEB_API_KEY no configurada")
        else:
            print("SUCCESS: Firebase Auth configurado")
    
    def login_user(self, email, password):
        if not self.firebase_web_api_key:
            return {'success': False, 'message': 'Servicio no configurado', 'user_data': None, 'error_code': 'SERVICE_NOT_CONFIGURED'}
        
        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={self.firebase_web_api_key}"
        payload = {'email': email, 'password': password, 'returnSecureToken': True}
        
        try:
            response = requests.post(url, json=payload, timeout=8)
            response.raise_for_status()
            user_data = response.json()
            
            return {
                'success': True,
                'message': 'Bienvenido! Has iniciado sesion correctamente.',
                'user_data': {
                    'user_id': user_data['localId'],
                    'email': user_data['email'],
                    'display_name': user_data.get('displayName', email.split('@')[0]),
                    'id_token': user_data['idToken']
                },
                'error_code': None
            }
        except requests.exceptions.HTTPError as e:
            try:
                error_msg = e.response.json().get('error', {}).get('message', 'ERROR')
                if 'INVALID' in error_msg or 'EMAIL_NOT_FOUND' in error_msg:
                    return {'success': False, 'message': 'Correo o contraseña incorrectos', 'user_data': None, 'error_code': 'INVALID_CREDENTIALS'}
                elif 'TOO_MANY_ATTEMPTS' in error_msg:
                    return {'success': False, 'message': 'Demasiados intentos fallidos', 'user_data': None, 'error_code': 'TOO_MANY_ATTEMPTS'}
                else:
                    return {'success': False, 'message': 'Error de autenticacion', 'user_data': None, 'error_code': 'FIREBASE_ERROR'}
            except:
                return {'success': False, 'message': 'Error de conexion', 'user_data': None, 'error_code': 'CONNECTION_ERROR'}
        except Exception as e:
            print(f"Firebase auth error: {e}")
            return {'success': False, 'message': 'Error interno del servidor', 'user_data': None, 'error_code': 'UNEXPECTED_ERROR'}
    
    def set_user_session(self, user_data):
        session['user_id'] = user_data['user_id']
        session['user_name'] = user_data['display_name']
        session['user_email'] = user_data['email']
        session['id_token'] = user_data['id_token']
        session['login_time'] = datetime.now().isoformat()
        session.permanent = True
    
    def clear_user_session(self):
        important_data = {key: session.get(key) for key in ['timestamp'] if key in session}
        session.clear()
        for key, value in important_data.items():
            session[key] = value
    
    def is_user_logged_in(self):
        if 'user_id' not in session or session['user_id'] is None:
            return False
        if 'login_time' in session:
            try:
                login_time = datetime.fromisoformat(session['login_time'])
                time_diff = (datetime.now() - login_time).total_seconds()
                if time_diff > 7200:  # 2 horas maximo
                    return False
            except:
                pass
        return True
    
    def get_current_user(self):
        if not self.is_user_logged_in():
            return None
        return {
            'user_id': session.get('user_id'),
            'user_name': session.get('user_name'),
            'user_email': session.get('user_email'),
            'id_token': session.get('id_token')
        }

firebase_auth = FirebaseAuth()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not firebase_auth.is_user_logged_in():
            flash('Tu sesion ha expirado. Inicia sesion nuevamente.', 'warning')
            return redirect(url_for('auth_login_page'))
        return f(*args, **kwargs)
    return decorated_function

# Funciones de busqueda con OpenAI Agent
class OpenAIAgent:
    """Agente de OpenAI para busqueda de productos e identificacion de imagenes"""
    
    def __init__(self):
        if not OPENAI_READY:
            print("OpenAI Agent no disponible")
        else:
            print("OpenAI Agent inicializado")
    
    def encode_image(self, image_content):
        """Codifica imagen a base64 para OpenAI Vision"""
        if not image_content:
            return None
        try:
            return base64.b64encode(image_content).decode('utf-8')
        except Exception as e:
            print(f"Error codificando imagen: {e}")
            return None
    
    def analyze_image_with_vision(self, image_content):
        """Analiza imagen con OpenAI Vision para generar consulta de busqueda"""
        if not OPENAI_READY or not image_content:
            print("OpenAI no disponible para analisis de imagen")
            return None
        
        try:
            base64_image = self.encode_image(image_content)
            if not base64_image:
                return None
            
            print("Analizando imagen con OpenAI Vision...")
            
            response = openai.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {
                        "role": "system",
                        "content": """Eres un experto en identificacion de productos para e-commerce. 
                        Tu tarea es analizar imagenes de productos y generar consultas de busqueda especificas y efectivas.
                        
                        Instrucciones:
                        1. Identifica el producto principal en la imagen
                        2. Determina marca, modelo, caracteristicas distintivas
                        3. Incluye color, tamaño, material si son visibles
                        4. Genera una consulta optimizada para tiendas online estadounidenses
                        5. Usa terminos en ingles que funcionan bien en Amazon, Walmart, Target
                        
                        Responde SOLO con la consulta de busqueda, sin explicaciones adicionales.
                        Ejemplo: "blue painter's tape 2 inch width ScotchBlue"
                        """
                    },
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "text",
                                "text": "Analiza esta imagen de producto y genera una consulta de busqueda especifica para encontrarlo en tiendas online estadounidenses."
                            },
                            {
                                "type": "image_url",
                                "image_url": {
                                    "url": f"data:image/jpeg;base64,{base64_image}",
                                    "detail": "high"
                                }
                            }
                        ]
                    }
                ],
                max_tokens=100,
                temperature=0.3
            )
            
            if response.choices and response.choices[0].message.content:
                search_query = response.choices[0].message.content.strip()
                print(f"Consulta generada desde imagen: '{search_query}'")
                return search_query
            
            return None
            
        except Exception as e:
            print(f"Error analizando imagen con OpenAI: {e}")
            return None
    
    def search_products_with_agent(self, query):
        """Usa OpenAI Agent mode para buscar productos con web browsing"""
        if not OPENAI_READY or not query:
            print("OpenAI Agent no disponible para busqueda")
            return []
        
        try:
            print(f"Buscando productos con OpenAI Agent: '{query}'")
            
            response = openai.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {
                        "role": "system",
                        "content": """Eres un agente especializado en busqueda de productos en tiendas online estadounidenses.
                        
                        Tu tarea:
                        1. Buscar el producto especificado en tiendas como Amazon, Walmart, Target, Best Buy
                        2. Encontrar al menos 3-6 opciones con precios reales
                        3. Evitar sitios como Alibaba, AliExpress, Temu, Wish
                        4. Priorizar tiendas estadounidenses confiables
                        
                        Formato de respuesta requerido (JSON valido):
                        {
                            "products": [
                                {
                                    "title": "Nombre completo del producto",
                                    "price": "$XX.XX",
                                    "price_numeric": XX.XX,
                                    "source": "Nombre de la tienda",
                                    "link": "URL del producto",
                                    "rating": "X.X",
                                    "reviews": "XXX",
                                    "search_source": "openai_agent"
                                }
                            ]
                        }
                        
                        Importante: Responde SOLO con el JSON, sin texto adicional."""
                    },
                    {
                        "role": "user",
                        "content": f"Busca precios y opciones para: {query}. Encuentra productos reales en tiendas estadounidenses con precios actuales."
                    }
                ],
                max_tokens=1500,
                temperature=0.3
            )
            
            if response.choices and response.choices[0].message.content:
                content = response.choices[0].message.content.strip()
                
                # Intentar parsear JSON
                try:
                    # Limpiar el contenido si tiene markdown
                    if content.startswith('```json'):
                        content = content.replace('```json', '').replace('```', '').strip()
                    
                    data = json.loads(content)
                    products = data.get('products', [])
                    
                    # Validar y limpiar productos
                    valid_products = []
                    for product in products:
                        if self._validate_product(product):
                            valid_products.append(product)
                    
                    print(f"OpenAI Agent encontro {len(valid_products)} productos validos")
                    return valid_products
                    
                except json.JSONDecodeError as e:
                    print(f"Error parseando JSON de OpenAI: {e}")
                    print(f"Contenido recibido: {content[:200]}...")
                    return []
            
            return []
            
        except Exception as e:
            print(f"Error en busqueda con OpenAI Agent: {e}")
            return []
    
    def _validate_product(self, product):
        """Valida que un producto tenga la estructura correcta"""
        required_fields = ['title', 'price', 'source', 'link']
        
        for field in required_fields:
            if not product.get(field):
                return False
        
        # Validar precio numerico
        try:
            price_str = product.get('price', '')
            price_match = re.search(r'\$\s*(\d+\.?\d*)', price_str)
            if price_match:
                price_numeric = float(price_match.group(1))
                product['price_numeric'] = price_numeric
            else:
                product['price_numeric'] = 0.0
        except:
            product['price_numeric'] = 0.0
        
        # Asegurar campos obligatorios
        product['rating'] = product.get('rating', '')
        product['reviews'] = product.get('reviews', '')
        product['search_source'] = 'openai_agent'
        
        return True

def validate_image(image_content):
    """Valida imagen"""
    if not PIL_AVAILABLE or not image_content:
        return False
    
    try:
        image = Image.open(io.BytesIO(image_content))
        if image.size[0] < 10 or image.size[1] < 10:
            return False
        if image.format not in ['JPEG', 'PNG', 'GIF', 'BMP', 'WEBP']:
            return False
        return True
    except:
        return False

# Price Finder Class - ACTUALIZADO para OpenAI Agent
class PriceFinder:
    def __init__(self):
        self.openai_agent = OpenAIAgent()
        self.cache = {}
        self.cache_ttl = 180
        self.blacklisted_stores = ['alibaba', 'aliexpress', 'temu', 'wish', 'banggood', 'dhgate']
        
        print("PriceFinder inicializado con OpenAI Agent")
    
    def is_api_configured(self):
        return OPENAI_READY
    
    def _extract_price(self, price_str):
        if not price_str:
            return 0.0
        try:
            match = re.search(r'\$\s*(\d{1,4}(?:,\d{3})*(?:\.\d{2})?)', str(price_str))
            if match:
                price_value = float(match.group(1).replace(',', ''))
                return price_value if 0.01 <= price_value <= 50000 else 0.0
        except:
            pass
        return 0.0
    
    def _generate_realistic_price(self, query, index=0):
        query_lower = query.lower()
        if any(word in query_lower for word in ['phone', 'laptop', 'computer']):
            base_price = 400
        elif any(word in query_lower for word in ['shirt', 'shoes', 'clothing']):
            base_price = 35
        elif any(word in query_lower for word in ['book', 'notebook']):
            base_price = 15
        else:
            base_price = 25
        return round(base_price * (1 + index * 0.15), 2)
    
    def _clean_text(self, text):
        if not text:
            return "Sin informacion"
        return html.escape(str(text)[:120])
    
    def _is_blacklisted_store(self, source):
        if not source:
            return False
        return any(blocked in str(source).lower() for blocked in self.blacklisted_stores)
    
    def _get_valid_link(self, item):
        if not item:
            return "#"
        
        link = item.get('link', '')
        if link and link.startswith('http'):
            return link
        
        # Generar link de busqueda si no hay link directo
        title = item.get('title', '')
        if title:
            search_query = quote_plus(str(title)[:50])
            source = item.get('source', '').lower()
            
            if 'amazon' in source:
                return f"https://www.amazon.com/s?k={search_query}"
            elif 'walmart' in source:
                return f"https://www.walmart.com/search?q={search_query}"
            elif 'target' in source:
                return f"https://www.target.com/s?searchTerm={search_query}"
            else:
                return f"https://www.google.com/search?tbm=shop&q={search_query}"
        
        return "#"
    
    def search_products(self, query=None, image_content=None):
        """Busqueda mejorada con OpenAI Agent y soporte para imagen"""
        # Determinar consulta final
        final_query = None
        search_source = "text"
        
        if image_content and OPENAI_READY and PIL_AVAILABLE:
            if validate_image(image_content):
                if query:
                    # Texto + imagen
                    image_query = self.openai_agent.analyze_image_with_vision(image_content)
                    if image_query:
                        final_query = f"{query} {image_query}"
                        search_source = "combined"
                        print("Busqueda combinada: texto + imagen")
                    else:
                        final_query = query
                        search_source = "text_fallback"
                        print("Imagen fallo, usando solo texto")
                else:
                    # Solo imagen
                    final_query = self.openai_agent.analyze_image_with_vision(image_content)
                    search_source = "image"
                    print("Busqueda basada en imagen")
            else:
                print("Imagen invalida")
                final_query = query or "producto"
                search_source = "text"
        else:
            # Solo texto o imagen no disponible
            final_query = query or "producto"
            search_source = "text"
            if image_content and not OPENAI_READY:
                print("Imagen proporcionada pero OpenAI no esta configurado")
        
        if not final_query or len(final_query.strip()) < 2:
            return self._get_examples("producto")
        
        final_query = final_query.strip()
        print(f"Busqueda final: '{final_query}' (fuente: {search_source})")
        
        # Verificar cache
        cache_key = f"search_{hash(final_query.lower())}"
        if cache_key in self.cache:
            cache_data, timestamp = self.cache[cache_key]
            if (time.time() - timestamp) < self.cache_ttl:
                print("Usando resultado desde cache")
                return cache_data
        
        # Buscar con OpenAI Agent
        if OPENAI_READY:
            products = self.openai_agent.search_products_with_agent(final_query)
            
            if products:
                # Procesar y validar productos
                processed_products = []
                for product in products:
                    if not self._is_blacklisted_store(product.get('source', '')):
                        # Asegurar link valido
                        product['link'] = self._get_valid_link(product)
                        # Añadir metadata
                        product['search_source'] = search_source
                        product['original_query'] = query if query else "imagen"
                        processed_products.append(product)
                
                if processed_products:
                    # Ordenar por precio
                    processed_products.sort(key=lambda x: x.get('price_numeric', 0))
                    final_products = processed_products[:6]
                    
                    # Guardar en cache
                    self.cache[cache_key] = (final_products, time.time())
                    if len(self.cache) > 10:
                        oldest_key = min(self.cache.keys(), key=lambda k: self.cache[k][1])
                        del self.cache[oldest_key]
                    
                    return final_products
        
        # Fallback a ejemplos si no hay resultados
        print("No se encontraron productos, usando ejemplos")
        return self._get_examples(final_query)
    
    def _get_examples(self, query):
        """Genera productos de ejemplo cuando no hay resultados reales"""
        stores = ['Amazon', 'Walmart', 'Target', 'Best Buy', 'Home Depot', 'Costco']
        examples = []
        
        for i in range(min(6, len(stores))):
            price = self._generate_realistic_price(query, i)
            store = stores[i]
            search_query = quote_plus(str(query)[:30])
            
            if store == 'Amazon':
                link = f"https://www.amazon.com/s?k={search_query}"
            elif store == 'Walmart':
                link = f"https://www.walmart.com/search?q={search_query}"
            elif store == 'Target':
                link = f"https://www.target.com/s?searchTerm={search_query}"
            elif store == 'Best Buy':
                link = f"https://www.bestbuy.com/site/searchpage.jsp?st={search_query}"
            elif store == 'Home Depot':
                link = f"https://www.homedepot.com/s/{search_query}"
            else:
                link = f"https://www.costco.com/CatalogSearch?keyword={search_query}"
            
            examples.append({
                'title': f'{self._clean_text(query)} - {["Mejor Precio", "Oferta Especial", "Popular", "Recomendado", "Calidad Premium", "Mas Vendido"][i]}',
                'price': f'${price:.2f}',
                'price_numeric': price,
                'source': store,
                'link': link,
                'rating': ['4.5', '4.3', '4.1', '4.0', '4.4', '4.2'][i],
                'reviews': ['1200', '856', '643', '421', '289', '167'][i],
                'image': '',
                'search_source': 'example',
                'original_query': query
            })
        
        return examples

# Instancia global de PriceFinder
price_finder = PriceFinder()

# Templates
def render_page(title, content):
    template = '''<!DOCTYPE html>
<html lang="es">
<head>
    <title>''' + title + '''</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 15px; }
        .container { max-width: 650px; margin: 0 auto; background: white; padding: 25px; border-radius: 12px; box-shadow: 0 8px 25px rgba(0,0,0,0.15); }
        h1 { color: #1a73e8; text-align: center; margin-bottom: 8px; font-size: 1.8em; }
        .subtitle { text-align: center; color: #666; margin-bottom: 25px; }
        input { width: 100%; padding: 12px; margin: 8px 0; border: 2px solid #e1e5e9; border-radius: 6px; font-size: 16px; }
        input:focus { outline: none; border-color: #1a73e8; }
        button { width: 100%; padding: 12px; background: #1a73e8; color: white; border: none; border-radius: 6px; cursor: pointer; font-size: 16px; font-weight: 600; }
        button:hover { background: #1557b0; }
        .search-bar { display: flex; gap: 8px; margin-bottom: 20px; }
        .search-bar input { flex: 1; }
        .search-bar button { width: auto; padding: 12px 20px; }
        .tips { background: #e8f5e8; border: 1px solid #4caf50; padding: 15px; border-radius: 6px; margin-bottom: 15px; font-size: 14px; }
        .error { background: #ffebee; color: #c62828; padding: 12px; border-radius: 6px; margin: 12px 0; display: none; }
        .loading { text-align: center; padding: 30px; display: none; }
        .spinner { border: 3px solid #f3f3f3; border-top: 3px solid #1a73e8; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 0 auto 15px; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .user-info { background: #e3f2fd; padding: 12px; border-radius: 6px; margin-bottom: 15px; text-align: center; font-size: 14px; display: flex; align-items: center; justify-content: center; }
        .user-info a { color: #1976d2; text-decoration: none; font-weight: 600; }
        .flash { padding: 12px; margin-bottom: 8px; border-radius: 6px; font-size: 14px; }
        .flash.success { background-color: #d4edda; color: #155724; }
        .flash.danger { background-color: #f8d7da; color: #721c24; }
        .flash.warning { background-color: #fff3cd; color: #856404; }
        .image-upload { background: #f8f9fa; border: 2px dashed #dee2e6; border-radius: 8px; padding: 20px; text-align: center; margin: 15px 0; transition: all 0.3s ease; }
        .image-upload input[type="file"] { display: none; }
        .image-upload label { cursor: pointer; color: #1a73e8; font-weight: 600; }
        .image-upload:hover { border-color: #1a73e8; background: #e3f2fd; }
        .image-preview { max-width: 150px; max-height: 150px; margin: 10px auto; border-radius: 8px; display: none; }
        .or-divider { text-align: center; margin: 20px 0; color: #666; font-weight: 600; position: relative; }
        .or-divider:before { content: ''; position: absolute; top: 50%; left: 0; right: 0; height: 1px; background: #dee2e6; z-index: 1; }
        .or-divider span { background: white; padding: 0 15px; position: relative; z-index: 2; }
    </style>
</head>
<body>''' + content + '''</body>
</html>'''
    return template

AUTH_LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Iniciar Sesion | Price Finder USA</title>
    <style>
        body { font-family: -apple-system, sans-serif; background: linear-gradient(135deg, #4A90E2 0%, #50E3C2 100%); min-height: 100vh; display: flex; justify-content: center; align-items: center; padding: 20px; }
        .auth-container { max-width: 420px; width: 100%; background: white; border-radius: 15px; box-shadow: 0 20px 40px rgba(0,0,0,0.1); overflow: hidden; }
        .form-header { text-align: center; padding: 30px 25px 15px; background: linear-gradient(45deg, #2C3E50, #4A90E2); color: white; }
        .form-header h1 { font-size: 1.8em; margin-bottom: 8px; }
        .form-header p { opacity: 0.9; font-size: 1em; }
        .form-body { padding: 25px; }
        form { display: flex; flex-direction: column; gap: 18px; }
        .input-group { display: flex; flex-direction: column; gap: 6px; }
        .input-group label { font-weight: 600; color: #2C3E50; font-size: 14px; }
        .input-group input { padding: 14px 16px; border: 2px solid #e0e0e0; border-radius: 8px; font-size: 16px; transition: border-color 0.3s ease; }
        .input-group input:focus { outline: 0; border-color: #4A90E2; }
        .submit-btn:hover { transform: translateY(-2px); }
        .flash-messages { list-style: none; padding: 0 25px 15px; }
        .flash { padding: 12px; margin-bottom: 10px; border-radius: 6px; text-align: center; font-size: 14px; }
        .flash.success { background-color: #d4edda; color: #155724; }
        .flash.danger { background-color: #f8d7da; color: #721c24; }
        .flash.warning { background-color: #fff3cd; color: #856404; }
    </style>
</head>
<body>
    <div class="auth-container">
        <div class="form-header">
            <h1>Price Finder USA</h1>
            <p>Iniciar Sesion</p>
        </div>
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                <ul class="flash-messages">
                    {% for category, message in messages %}
                        <li class="flash {{ category }}">{{ message }}</li>
                    {% endfor %}
                </ul>
            {% endif %}
        {% endwith %}
        <div class="form-body">
            <form action="{{ url_for('auth_login') }}" method="post">
                <div class="input-group">
                    <label for="email">Correo Electronico</label>
                    <input type="email" name="email" id="email" required>
                </div>
                <div class="input-group">
                    <label for="password">Contraseña</label>
                    <input type="password" name="password" id="password" required>
                </div>
                <button type="submit" class="submit-btn">Entrar</button>
            </form>
        </div>
    </div>
</body>
</html>
"""

# Routes
@app.route('/auth/login-page')
def auth_login_page():
    return render_template_string(AUTH_LOGIN_TEMPLATE)

@app.route('/auth/login', methods=['POST'])
def auth_login():
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '').strip()
    
    if not email or not password:
        flash('Por favor completa todos los campos.', 'danger')
        return redirect(url_for('auth_login_page'))
    
    print(f"Login attempt for {email}")
    result = firebase_auth.login_user(email, password)
    
    if result['success']:
        firebase_auth.set_user_session(result['user_data'])
        flash(result['message'], 'success')
        print(f"Successful login for {email}")
        return redirect(url_for('index'))
    else:
        flash(result['message'], 'danger')
        print(f"Failed login for {email}")
        return redirect(url_for('auth_login_page'))

@app.route('/auth/logout')
def auth_logout():
    firebase_auth.clear_user_session()
    flash('Has cerrado la sesion correctamente.', 'success')
    return redirect(url_for('auth_login_page'))

@app.route('/')
def index():
    if not firebase_auth.is_user_logged_in():
        return redirect(url_for('auth_login_page'))
    return redirect(url_for('search_page'))

@app.route('/search')
@login_required
def search_page():
    current_user = firebase_auth.get_current_user()
    user_name = current_user['user_name'] if current_user else 'Usuario'
    user_name_escaped = html.escape(user_name)
    
    # Verificar si busqueda por imagen esta disponible
    image_search_available = OPENAI_READY and PIL_AVAILABLE
    
    content = '''
    <div class="container">
        <div class="user-info">
            <span><strong>''' + user_name_escaped + '''</strong></span>
            <div style="display: inline-block; margin-left: 15px;">
                <a href="''' + url_for('auth_logout') + '''" style="background: #dc3545; color: white; padding: 6px 12px; border-radius: 4px; text-decoration: none; font-size: 13px; margin-right: 8px;">Salir</a>
                <a href="''' + url_for('index') + '''" style="background: #28a745; color: white; padding: 6px 12px; border-radius: 4px; text-decoration: none; font-size: 13px;">Inicio</a>
            </div>
        </div>
        
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="flash {{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        <h1>Buscar Productos</h1>
        <p class="subtitle">''' + ('🤖 Búsqueda con IA: Texto o Imagen' if image_search_available else 'Búsqueda inteligente por texto') + ''' - Powered by OpenAI</p>
        
        <form id="searchForm" enctype="multipart/form-data">
            <div class="search-bar">
                <input type="text" id="searchQuery" name="query" placeholder="Busca cualquier producto...">
                <button type="submit">🔍 Buscar</button>
            </div>
            
            ''' + ('<div class="or-divider"><span>O usa inteligencia artificial</span></div>' if image_search_available else '') + '''
            
            ''' + ('<div class="image-upload" id="imageUpload"><input type="file" id="imageFile" name="image_file" accept="image/*"><label for="imageFile">🤖 Subir imagen para análisis con IA<br><small>JPG, PNG, GIF hasta 10MB - OpenAI Vision</small></label><img id="imagePreview" class="image-preview" src="#" alt="Vista previa"></div>' if image_search_available else '') + '''
        </form>
        
        <div class="tips">
            <h4>🚀 Sistema con Inteligencia Artificial''' + (' + Visión por Computadora:' if image_search_available else ':') + '''</h4>
            <ul style="margin: 8px 0 0 15px; font-size: 13px;">
                <li><strong>🤖 OpenAI Agent:</strong> Búsqueda inteligente con navegación web</li>
                <li><strong>🇺🇸 Tiendas USA:</strong> Amazon, Walmart, Target, Best Buy, Home Depot</li>
                <li><strong>🚫 Sin basura:</strong> Filtrado automático de Alibaba, Temu, AliExpress</li>
                ''' + ('<li><strong>👁️ IA Vision:</strong> Identifica productos en imágenes automáticamente</li>' if image_search_available else '<li><strong>⚠️ Imagen:</strong> Configura OPENAI_API_KEY para activar vision</li>') + '''
                <li><strong>⚡ Velocidad:</strong> Resultados inteligentes en tiempo real</li>
            </ul>
        </div>
        
        <div id="loading" class="loading">
            <div class="spinner"></div>
            <h3>🤖 IA buscando productos...</h3>
            <p id="loadingText">OpenAI Agent trabajando...</p>
        </div>
        <div id="error" class="error"></div>
    </div>
    
    <script>
        let searching = false;
        const imageSearchAvailable = ''' + str(image_search_available).lower() + ''';
        
        // Manejo de vista previa de imagen
        if (imageSearchAvailable) {
            document.getElementById('imageFile').addEventListener('change', function(e) {
                const file = e.target.files[0];
                const preview = document.getElementById('imagePreview');
                
                if (file) {
                    if (file.size > 10 * 1024 * 1024) {
                        alert('La imagen es demasiado grande (máximo 10MB)');
                        this.value = '';
                        return;
                    }
                    
                    const reader = new FileReader();
                    reader.onload = function(e) {
                        preview.src = e.target.result;
                        preview.style.display = 'block';
                        document.getElementById('searchQuery').value = '';
                    }
                    reader.readAsDataURL(file);
                } else {
                    preview.style.display = 'none';
                }
            });
        }
        
        document.getElementById('searchForm').addEventListener('submit', function(e) {
            e.preventDefault();
            if (searching) return;
            
            const query = document.getElementById('searchQuery').value.trim();
            const imageFile = imageSearchAvailable ? document.getElementById('imageFile').files[0] : null;
            
            if (!query && !imageFile) {
                return showError('Por favor ingresa un producto' + (imageSearchAvailable ? ' o sube una imagen' : ''));
            }
            
            searching = true;
            if (imageFile) {
                showLoading('🤖 OpenAI analizando imagen...');
            } else {
                showLoading('🔍 OpenAI Agent buscando...');
            }
            
            const timeoutId = setTimeout(() => { 
                searching = false; 
                hideLoading(); 
                showError('Búsqueda muy lenta - Intenta de nuevo'); 
            }, 30000);
            
            const formData = new FormData();
            if (query) formData.append('query', query);
            if (imageFile) formData.append('image_file', imageFile);
            
            fetch('/api/search', {
                method: 'POST',
                body: formData
            })
            .then(response => { 
                clearTimeout(timeoutId); 
                searching = false; 
                return response.json(); 
            })
            .then(data => { 
                hideLoading(); 
                if (data.success) {
                    window.location.href = '/results';
                } else {
                    showError(data.error || 'Error en la búsqueda con IA');
                }
            })
            .catch(error => { 
                clearTimeout(timeoutId); 
                searching = false; 
                hideLoading(); 
                showError('Error de conexión con OpenAI'); 
            });
        });
        
        function showLoading(text = '🤖 IA trabajando...') { 
            document.getElementById('loadingText').textContent = text;
            document.getElementById('loading').style.display = 'block'; 
            document.getElementById('error').style.display = 'none'; 
        }
        function hideLoading() { document.getElementById('loading').style.display = 'none'; }
        function showError(msg) { 
            hideLoading(); 
            const e = document.getElementById('error'); 
            e.textContent = msg; 
            e.style.display = 'block'; 
        }
    </script>'''
    
    return render_template_string(render_page('Búsqueda con IA', content))

@app.route('/api/search', methods=['POST'])
@login_required
def api_search():
    try:
        # Obtener parametros
        query = request.form.get('query', '').strip() if request.form.get('query') else None
        image_file = request.files.get('image_file')
        
        # Procesar imagen si existe
        image_content = None
        if image_file and image_file.filename != '':
            try:
                image_content = image_file.read()
                print(f"📷 Imagen recibida: {len(image_content)} bytes")
                
                # Validar tamaño (maximo 10MB)
                if len(image_content) > 10 * 1024 * 1024:
                    return jsonify({'success': False, 'error': 'La imagen es demasiado grande (máximo 10MB)'}), 400
                    
            except Exception as e:
                print(f"Error al leer imagen: {e}")
                return jsonify({'success': False, 'error': 'Error al procesar la imagen'}), 400
        
        # Validar que hay al menos una entrada
        if not query and not image_content:
            return jsonify({'success': False, 'error': 'Debe proporcionar una consulta o una imagen'}), 400
        
        # Limitar longitud de query
        if query and len(query) > 80:
            query = query[:80]
        
        user_email = session.get('user_email', 'Unknown')
        search_type = "imagen" if image_content and not query else "texto+imagen" if image_content and query else "texto"
        print(f"🔍 OpenAI search request from {user_email}: {search_type}")
        
        # Realizar busqueda con soporte para imagen
        products = price_finder.search_products(query=query, image_content=image_content)
        
        session['last_search'] = {
            'query': query or "búsqueda por imagen con IA",
            'products': products,
            'timestamp': datetime.now().isoformat(),
            'user': user_email,
            'search_type': search_type,
            'ai_powered': True
        }
        
        print(f"✅ OpenAI search completed for {user_email}: {len(products)} products found")
        return jsonify({'success': True, 'products': products, 'total': len(products)})
        
    except Exception as e:
        print(f"❌ OpenAI search error: {e}")
        try:
            query = request.form.get('query', 'producto') if request.form.get('query') else 'producto'
            fallback = price_finder._get_examples(query)
            session['last_search'] = {
                'query': str(query), 
                'products': fallback, 
                'timestamp': datetime.now().isoformat(),
                'search_type': 'fallback',
                'ai_powered': False
            }
            return jsonify({'success': True, 'products': fallback, 'total': len(fallback)})
        except:
            return jsonify({'success': False, 'error': 'Error interno del servidor'}), 500

@app.route('/results')
@login_required
def results_page():
    try:
        if 'last_search' not in session:
            flash('No hay búsquedas recientes.', 'warning')
            return redirect(url_for('search_page'))
        
        current_user = firebase_auth.get_current_user()
        user_name = current_user['user_name'] if current_user else 'Usuario'
        user_name_escaped = html.escape(user_name)
        
        search_data = session['last_search']
        products = search_data.get('products', [])
        query = html.escape(str(search_data.get('query', 'busqueda')))
        search_type = search_data.get('search_type', 'texto')
        ai_powered = search_data.get('ai_powered', False)
        
        products_html = ""
        badges = ['🥇 MEJOR', '🥈 2do', '🥉 3ro', '4to', '5to', '6to']
        colors = ['#4caf50', '#ff9800', '#9c27b0', '#2196f3', '#ff5722', '#607d8b']
        
        for i, product in enumerate(products[:6]):
            if not product:
                continue
            
            badge = '<div style="position: absolute; top: 8px; right: 8px; background: ' + colors[min(i, 5)] + '; color: white; padding: 4px 8px; border-radius: 12px; font-size: 11px; font-weight: bold;">' + badges[min(i, 5)] + '</div>'
            
            # Badge de fuente de busqueda
            search_source_badge = ''
            source = product.get('search_source', '')
            if source == 'image':
                search_source_badge = '<div style="position: absolute; top: 8px; left: 8px; background: #673ab7; color: white; padding: 4px 8px; border-radius: 12px; font-size: 10px; font-weight: bold;">🤖 IA VISION</div>'
            elif source == 'combined':
                search_source_badge = '<div style="position: absolute; top: 8px; left: 8px; background: #607d8b; color: white; padding: 4px 8px; border-radius: 12px; font-size: 10px; font-weight: bold;">🔗 IA MIXTO</div>'
            elif source == 'openai_agent':
                search_source_badge = '<div style="position: absolute; top: 8px; left: 8px; background: #00acc1; color: white; padding: 4px 8px; border-radius: 12px; font-size: 10px; font-weight: bold;">🤖 OPENAI</div>'
            elif source == 'example':
                search_source_badge = '<div style="position: absolute; top: 8px; left: 8px; background: #ff7043; color: white; padding: 4px 8px; border-radius: 12px; font-size: 10px; font-weight: bold;">📋 EJEMPLO</div>'
            
            title = html.escape(str(product.get('title', 'Producto')))
            price = html.escape(str(product.get('price', '$0.00')))
            source_store = html.escape(str(product.get('source', 'Tienda')))
            link = html.escape(str(product.get('link', '#')))
            rating = product.get('rating', '')
            reviews = product.get('reviews', '')
            
            # Informacion adicional del producto
            additional_info = ''
            if rating and reviews:
                additional_info = f'<p style="color: #666; margin-bottom: 8px; font-size: 13px;">⭐ {rating} ({reviews} reseñas)</p>'
            
            products_html += '''
                <div style="border: 1px solid #ddd; border-radius: 8px; padding: 15px; margin-bottom: 15px; background: white; position: relative; box-shadow: 0 2px 4px rgba(0,0,0,0.08);">
                    ''' + badge + '''
                    ''' + search_source_badge + '''
                    <h3 style="color: #1a73e8; margin-bottom: 8px; font-size: 16px; margin-top: ''' + ('20px' if search_source_badge else '0') + ';">''' + title + '''</h3>
                    <div style="font-size: 28px; color: #2e7d32; font-weight: bold; margin: 12px 0;">''' + price + ''' <span style="font-size: 12px; color: #666;">USD</span></div>
                    <p style="color: #666; margin-bottom: 8px; font-size: 14px;">🏪 Tienda: ''' + source_store + '''</p>
                    ''' + additional_info + '''
                    <a href="''' + link + '''" target="_blank" rel="noopener noreferrer" style="background: #1a73e8; color: white; padding: 10px 16px; text-decoration: none; border-radius: 6px; font-weight: 600; display: inline-block; font-size: 14px; transition: background 0.3s;">🛒 Ver Producto</a>
                </div>'''
        
        prices = [p.get('price_numeric', 0) for p in products if p.get('price_numeric', 0) > 0]
        stats = ""
        if prices:
            min_price = min(prices)
            avg_price = sum(prices) / len(prices)
            max_price = max(prices)
            search_type_text = {
                "texto": "texto con IA", 
                "imagen": "imagen con IA Vision", 
                "texto+imagen": "texto + imagen IA", 
                "combined": "búsqueda mixta IA",
                "fallback": "ejemplos"
            }.get(search_type, search_type)
            
            ai_badge = "🤖 " if ai_powered else "📋 "
            
            stats = '''
                <div style="background: #e8f5e8; border: 1px solid #4caf50; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
                    <h3 style="color: #2e7d32; margin-bottom: 8px;">''' + ai_badge + '''Resultados (''' + search_type_text + ''')</h3>
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; font-size: 14px;">
                        <p><strong>📊 Productos:</strong> ''' + str(len(products)) + '''</p>
                        <p><strong>💰 Mejor precio:</strong> -btn { background: linear-gradient(45deg, #4A90E2, #2980b9); color: white; border: none; padding: 14px 25px; font-size: 16px; font-weight: 600; border-radius: 8px; cursor: pointer; transition: transform 0.2s ease; }
        .submit'' + f'{min_price:.2f}' + '''</p>
                        <p><strong>📈 Promedio:</strong> -btn { background: linear-gradient(45deg, #4A90E2, #2980b9); color: white; border: none; padding: 14px 25px; font-size: 16px; font-weight: 600; border-radius: 8px; cursor: pointer; transition: transform 0.2s ease; }
        .submit'' + f'{avg_price:.2f}' + '''</p>
                        <p><strong>💸 Más caro:</strong> -btn { background: linear-gradient(45deg, #4A90E2, #2980b9); color: white; border: none; padding: 14px 25px; font-size: 16px; font-weight: 600; border-radius: 8px; cursor: pointer; transition: transform 0.2s ease; }
        .submit'' + f'{max_price:.2f}' + '''</p>
                    </div>
                </div>'''
        
        content = '''
        <div style="max-width: 800px; margin: 0 auto;">
            <div style="background: rgba(255,255,255,0.15); padding: 12px; border-radius: 8px; margin-bottom: 15px; text-align: center; display: flex; align-items: center; justify-content: center;">
                <span style="color: white; font-size: 14px;"><strong>''' + user_name_escaped + '''</strong></span>
                <div style="margin-left: 15px;">
                    <a href="''' + url_for('auth_logout') + '''" style="background: rgba(220,53,69,0.9); color: white; padding: 6px 12px; border-radius: 4px; text-decoration: none; font-size: 13px; margin-right: 8px;">Salir</a>
                    <a href="''' + url_for('search_page') + '''" style="background: rgba(40,167,69,0.9); color: white; padding: 6px 12px; border-radius: 4px; text-decoration: none; font-size: 13px;">🔍 Nueva Búsqueda</a>
                </div>
            </div>
            
            <h1 style="color: white; text-align: center; margin-bottom: 8px;">🤖 Resultados: "''' + query + '''"</h1>
            <p style="text-align: center; color: rgba(255,255,255,0.9); margin-bottom: 25px;">Powered by OpenAI Agent</p>
            
            ''' + stats + '''
            ''' + products_html + '''
        </div>'''
        
        return render_template_string(render_page('Resultados IA - Price Finder USA', content))
    except Exception as e:
        print(f"❌ Results page error: {e}")
        flash('Error al mostrar resultados.', 'danger')
        return redirect(url_for('search_page'))

@app.route('/api/health')
def health_check():
    try:
        return jsonify({
            'status': 'OK', 
            'timestamp': datetime.now().isoformat(),
            'firebase_auth': 'enabled' if firebase_auth.firebase_web_api_key else 'disabled',
            'openai_api': 'enabled' if OPENAI_READY else 'disabled',
            'openai_vision': 'enabled' if OPENAI_READY else 'disabled',
            'pil_available': 'enabled' if PIL_AVAILABLE else 'disabled',
            'version': '2.0 - OpenAI Agent'
        })
    except Exception as e:
        return jsonify({'status': 'ERROR', 'message': str(e)}), 500

# Middleware
@app.before_request
def before_request():
    if 'timestamp' in session:
        try:
            timestamp_str = session['timestamp']
            if isinstance(timestamp_str, str) and len(timestamp_str) > 10:
                last_activity = datetime.fromisoformat(timestamp_str)
                time_diff = (datetime.now() - last_activity).total_seconds()
                if time_diff > 1200:  # 20 minutos
                    session.clear()
        except:
            session.clear()
    
    session['timestamp'] = datetime.now().isoformat()

@app.after_request
def after_request(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return response

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return '<h1>404 - Pagina no encontrada</h1><p><a href="/">Volver al inicio</a></p>', 404

@app.errorhandler(500)
def internal_error(error):
    return '<h1>500 - Error interno</h1><p><a href="/">Volver al inicio</a></p>', 500

if __name__ == '__main__':
    print("🚀 Price Finder USA con OpenAI Agent - Starting...")
    print(f"🔐 Firebase: {'✅ OK' if os.environ.get('FIREBASE_WEB_API_KEY') else '❌ NOT_CONFIGURED'}")
    print(f"🤖 OpenAI API: {'✅ OK' if OPENAI_READY else '❌ NOT_CONFIGURED'}")
    print(f"👁️ OpenAI Vision: {'✅ OK' if OPENAI_READY and PIL_AVAILABLE else '❌ NOT_CONFIGURED'}")
    print(f"🖼️ PIL/Pillow: {'✅ OK' if PIL_AVAILABLE else '❌ NOT_CONFIGURED'}")
    print(f"🌐 Puerto: {os.environ.get('PORT', '5000')}")
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False, threaded=True)
else:
    import logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')
    logging.getLogger('werkzeug').setLevel(logging.WARNING)-btn { background: linear-gradient(45deg, #4A90E2, #2980b9); color: white; border: none; padding: 14px 25px; font-size: 16px; font-weight: 600; border-radius: 8px; cursor: pointer; transition: transform 0.2s ease; }
        .submit
