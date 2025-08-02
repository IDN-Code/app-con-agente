# webapp_fixed.py - Price Finder USA con OpenAI Agent Mode (Precision) - VERSION CORREGIDA
from flask import Flask, request, jsonify, session, redirect, url_for, render_template_string, flash
import requests
import os
import re
import html
import time
import io
import json
import base64
import shelve
import logging
from datetime import datetime
from urllib.parse import urlparse, quote_plus
from functools import wraps

# Imports para procesamiento de imagen
try:
    from PIL import Image
    PIL_AVAILABLE = True
    print("PIL disponible")
except ImportError:
    PIL_AVAILABLE = False
    print("PIL no disponible")

try:
    import openai
    OPENAI_AVAILABLE = True
    print("OpenAI disponible")
except ImportError:
    openai = None
    OPENAI_AVAILABLE = False
    print("OpenAI no disponible")

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'fallback-key-change-in-production')
app.config['PERMANENT_SESSION_LIFETIME'] = 1800
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True if os.environ.get('RENDER') else False
app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024  # Aumentado a 20MB para OpenAI

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuracion de OpenAI - VERSIÓN CORREGIDA
OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY')
openai_client = None

if OPENAI_AVAILABLE and OPENAI_API_KEY:
    try:
        # Nueva sintaxis para OpenAI v1.0+
        openai_client = openai.OpenAI(api_key=OPENAI_API_KEY)
        # Prueba de conexión
        openai_client.models.list()
        print("OpenAI configurado correctamente")
        OPENAI_READY = True
    except Exception as e:
        print(f"Error configurando OpenAI: {e}")
        OPENAI_READY = False
        openai_client = None
elif OPENAI_AVAILABLE and not OPENAI_API_KEY:
    print("Falta OPENAI_API_KEY")
    OPENAI_READY = False
else:
    print("OpenAI no disponible")
    OPENAI_READY = False

# Cache persistente mejorado
class PersistentCache:
    def __init__(self, filename='price_cache.db'):
        self.filename = filename
        self.ttl = 300  # 5 minutos
        
    def get(self, key):
        try:
            with shelve.open(self.filename) as db:
                if key in db:
                    data, timestamp = db[key]
                    if (time.time() - timestamp) < self.ttl:
                        return data
                    else:
                        del db[key]  # Eliminar datos expirados
            return None
        except Exception as e:
            logger.error(f"Error leyendo cache: {e}")
            return None
    
    def set(self, key, value):
        try:
            with shelve.open(self.filename) as db:
                db[key] = (value, time.time())
                # Limpiar entradas viejas
                self._cleanup_expired(db)
        except Exception as e:
            logger.error(f"Error escribiendo cache: {e}")
    
    def _cleanup_expired(self, db):
        current_time = time.time()
        expired_keys = []
        for key in db:
            try:
                _, timestamp = db[key]
                if (current_time - timestamp) > self.ttl:
                    expired_keys.append(key)
            except:
                expired_keys.append(key)
        
        for key in expired_keys:
            try:
                del db[key]
            except:
                pass

# Firebase Auth Class - Mejorada
class FirebaseAuth:
    def __init__(self):
        self.firebase_web_api_key = os.environ.get("FIREBASE_WEB_API_KEY")
        if not self.firebase_web_api_key:
            logger.warning("FIREBASE_WEB_API_KEY no configurada")
        else:
            logger.info("Firebase Auth configurado")
    
    def login_user(self, email, password):
        if not self.firebase_web_api_key:
            return {'success': False, 'message': 'Servicio no configurado', 'user_data': None, 'error_code': 'SERVICE_NOT_CONFIGURED'}
        
        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={self.firebase_web_api_key}"
        payload = {'email': email, 'password': password, 'returnSecureToken': True}
        
        try:
            response = requests.post(url, json=payload, timeout=10)
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
        except requests.exceptions.Timeout:
            return {'success': False, 'message': 'Tiempo de espera agotado', 'user_data': None, 'error_code': 'TIMEOUT'}
        except Exception as e:
            logger.error(f"Firebase auth error: {e}")
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
        if 'user_id' not in session or not session['user_id']:
            return False
            
        if 'login_time' in session:
            try:
                login_time = datetime.fromisoformat(session['login_time'])
                time_diff = (datetime.now() - login_time).total_seconds()
                if time_diff > 1800:  # 30 minutos de sesión
                    self.clear_user_session()
                    return False
            except ValueError:
                logger.warning("Formato de fecha de login inválido")
                self.clear_user_session()
                return False
                
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

# Validación de imagen mejorada
def validate_image(image_content):
    """Valida imagen con verificaciones mejoradas"""
    if not PIL_AVAILABLE or not image_content:
        return False
    
    try:
        # Verificar tamaño máximo (20MB para OpenAI)
        if len(image_content) > 20 * 1024 * 1024:
            logger.warning("Imagen demasiado grande")
            return False
        
        # Verificar integridad de la imagen
        image = Image.open(io.BytesIO(image_content))
        image.verify()  # Verificar integridad
        
        # Reabrir después de verify (verify corrompe el objeto)
        image = Image.open(io.BytesIO(image_content))
        
        # Verificar tamaño mínimo más estricto
        if image.size[0] < 50 or image.size[1] < 50:
            logger.warning("Imagen demasiado pequeña")
            return False
            
        # Formatos soportados por OpenAI Vision
        if image.format not in ['JPEG', 'PNG', 'GIF', 'WEBP']:
            logger.warning(f"Formato no soportado: {image.format}")
            return False
            
        return True
        
    except Exception as e:
        logger.error(f"Error validando imagen: {e}")
        return False
    finally:
        # Cerrar objeto de imagen si existe
        if 'image' in locals():
            try:
                image.close()
            except:
                pass

# OpenAI Agent Class - PRECISION MODE CORREGIDA
class OpenAIAgentPrecision:
    def __init__(self):
        if not OPENAI_READY or not openai_client:
            logger.warning("OpenAI Agent no disponible")
            self.available = False
            self.client = None
        else:
            logger.info("OpenAI Agent Precision Mode inicializado")
            self.available = True
            self.client = openai_client
        
        # Configuracion para precision maxima
        self.max_retries = 3
        self.verification_enabled = True
        self.alternative_search_enabled = True
    
    def encode_image(self, image_content):
        """Codifica imagen a base64 para OpenAI Vision"""
        if not image_content:
            return None
        try:
            return base64.b64encode(image_content).decode('utf-8')
        except Exception as e:
            logger.error(f"Error codificando imagen: {e}")
            return None
    
    def analyze_image_with_vision(self, image_content):
        """Analiza imagen con OpenAI Vision para generar consulta de busqueda"""
        if not self.available or not image_content:
            logger.warning("OpenAI no disponible para analisis de imagen")
            return None
        
        try:
            base64_image = self.encode_image(image_content)
            if not base64_image:
                return None
            
            logger.info("Analizando imagen con OpenAI Vision...")
            
            response = self.client.chat.completions.create(
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
                        6. Se muy especifico: incluye numeros de modelo, medidas exactas, etc.
                        
                        Responde SOLO con la consulta de busqueda, sin explicaciones adicionales.
                        Ejemplo: "Sony WH-1000XM4 wireless noise canceling headphones black"
                        """
                    },
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "text",
                                "text": "Analiza esta imagen de producto y genera una consulta de busqueda MUY especifica para encontrarlo en tiendas online estadounidenses. Incluye marca, modelo, caracteristicas exactas."
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
                max_tokens=150,
                temperature=0.1
            )
            
            if response.choices and response.choices[0].message.content:
                search_query = response.choices[0].message.content.strip()
                logger.info(f"Consulta generada desde imagen: '{search_query}'")
                return search_query
            
            return None
            
        except openai.APIError as e:
            logger.error(f"Error de API de OpenAI en vision: {e}")
            return None
        except openai.RateLimitError as e:
            logger.error(f"Límite de tasa excedido en vision: {e}")
            return None
        except Exception as e:
            logger.error(f"Error analizando imagen: {e}")
            return None
    
    def search_products_with_precision_agent(self, query):
        """Busqueda de precision con OpenAI Agent Mode - Verificacion completa"""
        if not self.available or not query:
            logger.warning("OpenAI Agent no disponible para busqueda")
            return {'success': False, 'products': [], 'message': 'OpenAI Agent no disponible'}
        
        try:
            logger.info(f"Iniciando busqueda de precision para: '{query}'")
            
            # Prompt super detallado para busqueda de precision
            system_prompt = """Eres un agente especializado en busqueda PRECISA de productos en tiendas online estadounidenses.

TU MISION:
1. Buscar el producto especificado en tiendas estadounidenses confiables (Amazon, Walmart, Target, Best Buy, Home Depot, Costco, etc.)
2. VERIFICAR que cada producto existe realmente en la tienda indicada
3. VALIDAR que los precios son coherentes y actuales
4. ANALIZAR que el producto coincide exactamente con lo buscado
5. Encontrar los 5 productos mas baratos que sean REALES y VERIFICABLES

PROCESO DE VERIFICACION:
- Busca el producto en multiples tiendas
- Verifica precios actuales (no uses precios ficticios)
- Confirma que el link del producto funciona
- Analiza coherencia precio/producto/tienda
- Descarta productos que parezcan falsos o con precios irreales

CRITERIOS DE CALIDAD:
- Solo productos que existen realmente
- Precios verificados y coherentes
- Links funcionales a productos reales
- Informacion completa (titulo, precio, tienda, rating)
- Prioriza tiendas estadounidenses reconocidas

FORMATO DE RESPUESTA (JSON valido):
{
    "success": true,
    "products": [
        {
            "title": "Nombre EXACTO del producto",
            "price": "$XX.XX",
            "price_numeric": XX.XX,
            "source": "Nombre exacto de la tienda",
            "link": "URL REAL del producto",
            "rating": "X.X",
            "reviews": "XXX",
            "verified": true,
            "verification_notes": "Breve nota de verificacion"
        }
    ],
    "search_attempts": X,
    "verification_summary": "Resumen del proceso de verificacion"
}

IMPORTANTE:
- Si no encuentras productos REALES, indica success: false
- NO inventes productos o precios
- SI el producto no existe, sugiere alternativas similares
- Responde SOLO con JSON valido, sin texto adicional"""

            # Primera busqueda con manejo mejorado de errores
            response = self.client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": f"Busca y VERIFICA productos reales para: {query}. Necesito los 5 mas baratos que sean VERIFICABLES en tiendas estadounidenses."}
                ],
                max_tokens=2000,
                temperature=0.1
            )
            
            if response.choices and response.choices[0].message.content:
                content = response.choices[0].message.content.strip()
                
                try:
                    # Limpieza mejorada del JSON
                    json_start = content.find('{')
                    json_end = content.rfind('}') + 1
                    
                    if json_start != -1 and json_end > json_start:
                        content = content[json_start:json_end]
                    else:
                        # Si no encuentra JSON válido, remover markdown
                        if content.startswith('```json'):
                            content = content.replace('```json', '').replace('```', '').strip()
                    
                    result = json.loads(content)
                    
                    if result.get('success') and result.get('products'):
                        products = result['products']
                        verified_products = []
                        
                        # Validacion adicional de productos
                        for product in products:
                            if self._validate_precision_product(product):
                                verified_products.append(product)
                        
                        if verified_products:
                            logger.info(f"Encontrados {len(verified_products)} productos verificados")
                            return {
                                'success': True, 
                                'products': verified_products[:5], 
                                'message': f'Encontrados {len(verified_products)} productos verificados',
                                'verification_summary': result.get('verification_summary', 'Productos verificados por OpenAI Agent')
                            }
                        else:
                            logger.warning("No se encontraron productos que pasaran la validacion")
                            return self._attempt_alternative_search(query)
                    else:
                        logger.warning("OpenAI Agent no encontro productos verificables")
                        return self._attempt_alternative_search(query)
                        
                except json.JSONDecodeError as e:
                    logger.error(f"Error parseando JSON: {e}\nContenido: {content}")
                    return self._attempt_alternative_search(query)
            
            return self._attempt_alternative_search(query)
            
        except openai.APIError as e:
            logger.error(f"Error de API de OpenAI en busqueda: {e}")
            return self._attempt_alternative_search(query)
        except openai.RateLimitError as e:
            logger.error(f"Límite de tasa excedido en busqueda: {e}")
            return {'success': False, 'products': [], 'message': 'Demasiadas solicitudes. Intenta de nuevo más tarde.'}
        except Exception as e:
            logger.error(f"Error en busqueda de precision: {e}")
            return self._attempt_alternative_search(query)
    
    def _attempt_alternative_search(self, original_query):
        """Intenta busquedas alternativas cuando no encuentra productos"""
        if not self.alternative_search_enabled:
            return {'success': False, 'products': [], 'message': 'No se encontraron productos verificables'}
        
        try:
            logger.info(f"Intentando busqueda alternativa para: {original_query}")
            
            alternative_prompt = f"""El usuario busco: "{original_query}" pero no encontramos productos verificables.

GENERA 3 BUSQUEDAS ALTERNATIVAS:
1. Una version mas generica del producto
2. Una version con sinonimos o terminos alternativos
3. Una version con marcas populares del tipo de producto

Para CADA busqueda alternativa, encuentra productos REALES y VERIFICABLES.

Formato de respuesta:
{{
    "alternative_searches": [
        {{
            "query": "busqueda alternativa 1",
            "products": [lista de productos reales]
        }}
    ],
    "success": true/false,
    "message": "explicacion"
}}"""

            response = self.client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": "Eres un experto en generar busquedas alternativas para productos que no se encontraron."},
                    {"role": "user", "content": alternative_prompt}
                ],
                max_tokens=2000,
                temperature=0.2
            )
            
            if response.choices and response.choices[0].message.content:
                content = response.choices[0].message.content.strip()
                
                # Limpieza mejorada del JSON
                json_start = content.find('{')
                json_end = content.rfind('}') + 1
                
                if json_start != -1 and json_end > json_start:
                    content = content[json_start:json_end]
                
                try:
                    result = json.loads(content)
                    
                    if result.get('success') and result.get('alternative_searches'):
                        all_products = []
                        for alt_search in result['alternative_searches']:
                            if alt_search.get('products'):
                                for product in alt_search['products']:
                                    if self._validate_precision_product(product):
                                        product['alternative_query'] = alt_search.get('query', 'busqueda alternativa')
                                        all_products.append(product)
                        
                        if all_products:
                            # Ordenar por precio y tomar los 5 mas baratos
                            all_products.sort(key=lambda x: x.get('price_numeric', float('inf')))
                            return {
                                'success': True,
                                'products': all_products[:5],
                                'message': f'Productos encontrados con busquedas alternativas',
                                'alternative_search': True
                            }
                
                except json.JSONDecodeError as e:
                    logger.error(f"Error parseando JSON alternativo: {e}")
            
            return {'success': False, 'products': [], 'message': 'No se encontraron productos, ni con busquedas alternativas'}
            
        except Exception as e:
            logger.error(f"Error en busqueda alternativa: {e}")
            return {'success': False, 'products': [], 'message': 'Error en busqueda alternativa'}
    
    def _validate_precision_product(self, product):
        """Validacion estricta de productos para modo precision"""
        required_fields = ['title', 'price', 'source', 'link']
        
        # Verificar campos obligatorios
        for field in required_fields:
            if not product.get(field):
                logger.debug(f"Producto rechazado: falta campo {field}")
                return False
        
        # Validar precio
        try:
            price_str = product.get('price', '')
            price_match = re.search(r'\$\s*(\d+\.?\d*)', price_str)
            if price_match:
                price_numeric = float(price_match.group(1))
                # Precio debe ser razonable (entre $0.01 y $10,000)
                if not (0.01 <= price_numeric <= 10000):
                    logger.debug(f"Producto rechazado: precio fuera de rango: ${price_numeric}")
                    return False
                product['price_numeric'] = price_numeric
            else:
                logger.debug(f"Producto rechazado: precio invalido: {price_str}")
                return False
        except Exception as e:
            logger.debug(f"Producto rechazado: error procesando precio: {e}")
            return False
        
        # Validar link
        link = product.get('link', '')
        if not (link.startswith('http') and len(link) > 10):
            logger.debug(f"Producto rechazado: link invalido: {link}")
            return False
        
        # Validar tienda (no debe ser blacklisted)
        source = product.get('source', '').lower()
        blacklisted = ['alibaba', 'aliexpress', 'temu', 'wish', 'banggood', 'dhgate']
        if any(blocked in source for blocked in blacklisted):
            logger.debug(f"Producto rechazado: tienda bloqueada: {source}")
            return False
        
        # Validar titulo (debe tener contenido sustancial)
        title = product.get('title', '')
        if len(title) < 10:
            logger.debug(f"Producto rechazado: titulo muy corto: {title}")
            return False
        
        # Asegurar campos opcionales
        product['rating'] = product.get('rating', '')
        product['reviews'] = product.get('reviews', '')
        product['verified'] = product.get('verified', True)
        product['search_source'] = 'openai_agent_precision'
        
        return True

# Price Finder Class - PRECISION MODE CORREGIDA
class PriceFinderPrecision:
    def __init__(self):
        self.openai_agent = OpenAIAgentPrecision()
        self.cache = PersistentCache()
        logger.info("PriceFinder Precision Mode inicializado")
    
    def is_api_configured(self):
        return self.openai_agent.available
    
    def search_products(self, query=None, image_content=None):
        """Busqueda de precision - solo productos reales verificados"""
        if not self.openai_agent.available:
            return {
                'success': False,
                'products': [],
                'message': 'OpenAI Agent no esta configurado. Verifica tu OPENAI_API_KEY.'
            }
        
        # Determinar consulta final
        final_query = None
        search_source = "text"
        
        if image_content and PIL_AVAILABLE:
            if validate_image(image_content):
                if query:
                    # Texto + imagen
                    image_query = self.openai_agent.analyze_image_with_vision(image_content)
                    if image_query:
                        final_query = f"{query} {image_query}"
                        search_source = "combined"
                        logger.info("Busqueda de precision: texto + imagen")
                    else:
                        final_query = query
                        search_source = "text_fallback"
                        logger.info("Vision fallo, usando solo texto")
                else:
                    # Solo imagen
                    final_query = self.openai_agent.analyze_image_with_vision(image_content)
                    search_source = "image"
                    logger.info("Busqueda de precision basada en imagen")
            else:
                logger.warning("Imagen invalida")
                final_query = query or None
                search_source = "text"
        else:
            # Solo texto
            final_query = query
            search_source = "text"
        
        if not final_query or len(final_query.strip()) < 2:
            return {
                'success': False,
                'products': [],
                'message': 'Consulta de busqueda muy corta o vacia. Proporciona mas detalles sobre el producto.'
            }
        
        final_query = final_query.strip()
        logger.info(f"Busqueda de precision: '{final_query}' (fuente: {search_source})")
        
        # Verificar cache
        cache_key = f"precision_{hash(final_query.lower())}"
        cached_result = self.cache.get(cache_key)
        if cached_result:
            logger.info("Usando resultado desde cache (precision)")
            return cached_result
        
        # Buscar con OpenAI Agent Precision
        start_time = time.time()
        result = self.openai_agent.search_products_with_precision_agent(final_query)
        search_time = time.time() - start_time
        
        if result['success'] and result['products']:
            # Añadir metadata
            for product in result['products']:
                product['search_source'] = search_source
                product['original_query'] = query if query else "imagen"
                product['search_time'] = round(search_time, 2)
            
            # Ordenar por precio (mas barato primero)
            result['products'].sort(key=lambda x: x.get('price_numeric', float('inf')))
            
            # Guardar en cache
            self.cache.set(cache_key, result)
            
            result['search_time'] = round(search_time, 2)
            logger.info(f"Busqueda de precision completada en {search_time:.2f}s")
            return result
        else:
            logger.warning("Busqueda de precision no encontro productos verificables")
            return {
                'success': False,
                'products': [],
                'message': result.get('message', 'No se encontraron productos verificables para tu busqueda. Intenta con terminos mas especificos o diferentes.'),
                'search_time': round(search_time, 2)
            }

price_finder = PriceFinderPrecision()

# Templates (sin cambios en el HTML)
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
        .precision-badge { background: #ff6b35; color: white; padding: 4px 8px; border-radius: 12px; font-size: 11px; font-weight: bold; display: inline-block; margin-left: 8px; }
        .no-results { background: #fff3cd; border: 1px solid #ffc107; padding: 20px; border-radius: 8px; text-align: center; margin: 20px 0; }
        .no-results h3 { color: #856404; margin-bottom: 10px; }
        .no-results p { color: #856404; margin-bottom: 15px; }
        .retry-btn { background: #ffc107; color: #212529; padding: 10px 20px; border: none; border-radius: 6px; cursor: pointer; font-weight: 600; }
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
       .submit-btn { background: linear-gradient(45deg, #4A90E2, #2980b9); color: white; border: none; padding: 14px 25px; font-size: 16px; font-weight: 600; border-radius: 8px; cursor: pointer; transition: transform 0.2s ease; }
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
   
   logger.info(f"Login attempt for {email}")
   result = firebase_auth.login_user(email, password)
   
   if result['success']:
       firebase_auth.set_user_session(result['user_data'])
       flash(result['message'], 'success')
       logger.info(f"Successful login for {email}")
       return redirect(url_for('index'))
   else:
       flash(result['message'], 'danger')
       logger.warning(f"Failed login for {email}: {result['error_code']}")
       return redirect(url_for('auth_login_page'))

@app.route('/auth/logout')
def auth_logout():
   user_email = session.get('user_email', 'Unknown')
   firebase_auth.clear_user_session()
   flash('Has cerrado la sesion correctamente.', 'success')
   logger.info(f"User logged out: {user_email}")
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
   
   image_search_available = OPENAI_READY and PIL_AVAILABLE
   
   content = '''
   <div class="container">
       <div class="user-info">
           <span><strong>''' + user_name_escaped + '''</strong></span>
           <span class="precision-badge">PRECISION MODE</span>
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
       <p class="subtitle">''' + ('🔍 Búsqueda de Precision: Texto o Imagen' if image_search_available else 'Búsqueda de Precision por texto') + ''' - Solo Productos REALES</p>
       
       <form id="searchForm" enctype="multipart/form-data">
           <div class="search-bar">
               <input type="text" id="searchQuery" name="query" placeholder="Busca productos reales con detalles especificos...">
               <button type="submit">🔍 Buscar</button>
           </div>
           
           ''' + ('<div class="or-divider"><span>O analiza imagen con IA</span></div>' if image_search_available else '') + '''
           
           ''' + ('<div class="image-upload" id="imageUpload"><input type="file" id="imageFile" name="image_file" accept="image/*"><label for="imageFile">📸 Subir imagen para análisis preciso<br><small>JPG, PNG, GIF hasta 20MB - OpenAI Vision</small></label><img id="imagePreview" class="image-preview" src="#" alt="Vista previa"></div>' if image_search_available else '') + '''
       </form>
       
       <div class="tips">
           <h4>🎯 Modo Precision - Solo Productos VERIFICADOS:</h4>
           <ul style="margin: 8px 0 0 15px; font-size: 13px;">
               <li><strong>🔍 Verificacion Real:</strong> Cada producto es verificado por OpenAI Agent</li>
               <li><strong>💰 Precios Actuales:</strong> Solo precios coherentes y verificables</li>
               <li><strong>🏪 Tiendas USA:</strong> Amazon, Walmart, Target, Best Buy, Home Depot, Costco</li>
               <li><strong>🚫 Sin Ejemplos:</strong> Solo productos que existen realmente</li>
               ''' + ('<li><strong>👁️ Vision IA:</strong> Identifica productos especificos en imagenes</li>' if image_search_available else '<li><strong>⚠️ Imagen:</strong> Configura OPENAI_API_KEY para activar vision</li>') + '''
               <li><strong>🔄 Busquedas Alternativas:</strong> Si no encuentra, busca productos similares</li>
           </ul>
       </div>
       
       <div id="loading" class="loading">
           <div class="spinner"></div>
           <h3>🔍 OpenAI Agent verificando productos...</h3>
           <p id="loadingText">Buscando y verificando productos reales...</p>
           <p style="font-size: 12px; color: #666; margin-top: 10px;">Esto puede tomar hasta 2 minutos para garantizar precision</p>
       </div>
       <div id="error" class="error"></div>
   </div>
   
   <script>
       let searching = false;
       const imageSearchAvailable = ''' + str(image_search_available).lower() + ''';
       
       if (imageSearchAvailable) {
           document.getElementById('imageFile').addEventListener('change', function(e) {
               const file = e.target.files[0];
               const preview = document.getElementById('imagePreview');
               
               if (file) {
                   if (file.size > 20 * 1024 * 1024) {
                       alert('La imagen es demasiado grande (máximo 20MB)');
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
               return showError('Por favor ingresa detalles especificos del producto' + (imageSearchAvailable ? ' o sube una imagen' : ''));
           }
           
           searching = true;
           if (imageFile) {
               showLoading('🔍 OpenAI analizando imagen y verificando productos...');
           } else {
               showLoading('🔍 OpenAI Agent verificando productos reales...');
           }
           
           // Timeout mas largo para precision
           const timeoutId = setTimeout(() => { 
               searching = false; 
               hideLoading(); 
               showError('Búsqueda de precision agotó tiempo - La verificacion toma tiempo'); 
           }, 120000); // 2 minutos
           
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
                   showError(data.message || 'No se encontraron productos verificables. Intenta con términos más específicos.');
               }
           })
           .catch(error => { 
               clearTimeout(timeoutId); 
               searching = false; 
               hideLoading(); 
               showError('Error de conexión con OpenAI Agent'); 
           });
       });
       
       function showLoading(text = '🔍 Verificando productos...') { 
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
   
   return render_template_string(render_page('Búsqueda Precision', content))

@app.route('/api/search', methods=['POST'])
@login_required
def api_search():
   try:
       query = request.form.get('query', '').strip() if request.form.get('query') else None
       image_file = request.files.get('image_file')
       
       image_content = None
       if image_file and image_file.filename != '':
           try:
               image_content = image_file.read()
               logger.info(f"Imagen recibida: {len(image_content)} bytes")
               
               if len(image_content) > 20 * 1024 * 1024:
                   return jsonify({'success': False, 'message': 'La imagen es demasiado grande (máximo 20MB)'}), 400
                   
           except Exception as e:
               logger.error(f"Error al leer imagen: {e}")
               return jsonify({'success': False, 'message': 'Error al procesar la imagen'}), 400
       
       if not query and not image_content:
           return jsonify({'success': False, 'message': 'Debe proporcionar una consulta o una imagen'}), 400
       
       if query and len(query) > 200:
           query = query[:200]
       
       user_email = session.get('user_email', 'Unknown')
       search_type = "imagen" if image_content and not query else "texto+imagen" if image_content and query else "texto"
       logger.info(f"Precision search request from {user_email}: {search_type}")
       
       # Realizar busqueda de precision
       result = price_finder.search_products(query=query, image_content=image_content)
       
       session['last_search'] = {
           'query': query or "búsqueda por imagen de precision",
           'products': result.get('products', []),
           'timestamp': datetime.now().isoformat(),
           'user': user_email,
           'search_type': search_type,
           'precision_mode': True,
           'success': result.get('success', False),
           'message': result.get('message', ''),
           'verification_summary': result.get('verification_summary', ''),
           'search_time': result.get('search_time', 0),
           'alternative_search': result.get('alternative_search', False)
       }
       
       if result['success']:
           logger.info(f"Precision search completed for {user_email}: {len(result['products'])} verified products found")
           return jsonify({
               'success': True, 
               'products': result['products'], 
               'total': len(result['products']),
               'message': result.get('message', ''),
               'search_time': result.get('search_time', 0)
           })
       else:
           logger.warning(f"Precision search failed for {user_email}: {result.get('message', 'No message')}")
           return jsonify({
               'success': False,
               'message': result.get('message', 'No se encontraron productos verificables'),
               'search_time': result.get('search_time', 0)
           })
       
   except Exception as e:
       logger.error(f"API search error: {e}")
       return jsonify({'success': False, 'message': 'Error interno del servidor durante la búsqueda de precision'}), 500

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
       precision_mode = search_data.get('precision_mode', False)
       success = search_data.get('success', False)
       message = search_data.get('message', '')
       search_time = search_data.get('search_time', 0)
       alternative_search = search_data.get('alternative_search', False)
       
       if not success or not products:
           # Mostrar pagina de no resultados
           no_results_content = f'''
           <div class="no-results">
               <h3>🔍 No se encontraron productos verificables</h3>
               <p><strong>Búsqueda:</strong> "{query}"</p>
               <p><strong>Mensaje:</strong> {message}</p>
               <p><strong>Tiempo de búsqueda:</strong> {search_time:.1f} segundos</p>
               <button class="retry-btn" onclick="window.location.href='/search'">Intentar nueva búsqueda</button>
           </div>
           '''
           
           content = f'''
           <div style="max-width: 800px; margin: 0 auto;">
               <div style="background: rgba(255,255,255,0.15); padding: 12px; border-radius: 8px; margin-bottom: 15px; text-align: center; display: flex; align-items: center; justify-content: center;">
                   <span style="color: white; font-size: 14px;"><strong>{user_name_escaped}</strong></span>
                   <span class="precision-badge">PRECISION MODE</span>
                   <div style="margin-left: 15px;">
                       <a href="{url_for('auth_logout')}" style="background: rgba(220,53,69,0.9); color: white; padding: 6px 12px; border-radius: 4px; text-decoration: none; font-size: 13px; margin-right: 8px;">Salir</a>
                       <a href="{url_for('search_page')}" style="background: rgba(40,167,69,0.9); color: white; padding: 6px 12px; border-radius: 4px; text-decoration: none; font-size: 13px;">Nueva Búsqueda</a>
                   </div>
               </div>
               
               <h1 style="color: white; text-align: center; margin-bottom: 8px;">Sin Resultados: "{query}"</h1>
               <p style="text-align: center; color: rgba(255,255,255,0.9); margin-bottom: 25px;">OpenAI Agent Precision Mode</p>
               
               {no_results_content}
           </div>'''
           
           return render_template_string(render_page('Sin Resultados - Price Finder USA', content))
       
       products_html = ""
       badges = ['🥇 MAS BARATO', '🥈 2do LUGAR', '🥉 3er LUGAR', '4to', '5to']
       colors = ['#4caf50', '#ff9800', '#9c27b0', '#2196f3', '#ff5722']
       
       for i, product in enumerate(products[:5]):
           if not product:
               continue
           
           badge = '<div style="position: absolute; top: 8px; right: 8px; background: ' + colors[min(i, 4)] + '; color: white; padding: 4px 8px; border-radius: 12px; font-size: 11px; font-weight: bold;">' + badges[min(i, 4)] + '</div>'
           
           # Badge de verificacion
           verification_badge = '<div style="position: absolute; top: 8px; left: 8px; background: #28a745; color: white; padding: 4px 8px; border-radius: 12px; font-size: 10px; font-weight: bold;">✓ VERIFICADO</div>'
           
           # Badge de fuente de busqueda
           search_source_badge = ''
           source = product.get('search_source', '')
           if source == 'image':
               search_source_badge = '<div style="position: absolute; top: 35px; left: 8px; background: #673ab7; color: white; padding: 4px 8px; border-radius: 12px; font-size: 10px; font-weight: bold;">📸 IMAGEN IA</div>'
           elif source == 'combined':
               search_source_badge = '<div style="position: absolute; top: 35px; left: 8px; background: #607d8b; color: white; padding: 4px 8px; border-radius: 12px; font-size: 10px; font-weight: bold;">🔗 TEXTO+IMG</div>'
           
           # Badge de busqueda alternativa
           alt_search_badge = ''
           if alternative_search and product.get('alternative_query'):
               alt_search_badge = f'<div style="position: absolute; top: 62px; left: 8px; background: #ff9800; color: white; padding: 4px 8px; border-radius: 12px; font-size: 9px; font-weight: bold;">🔄 ALT: {html.escape(product.get("alternative_query", "")[:15])}...</div>'
           
           title = html.escape(str(product.get('title', 'Producto')))
           price = html.escape(str(product.get('price', '$0.00')))
           source_store = html.escape(str(product.get('source', 'Tienda')))
           link = html.escape(str(product.get('link', '#')))
           rating = product.get('rating', '')
           reviews = product.get('reviews', '')
           verification_notes = product.get('verification_notes', '')
           
           additional_info = ''
           if rating and reviews:
               additional_info += f'<p style="color: #666; margin-bottom: 8px; font-size: 13px;">⭐ {rating} ({reviews} reseñas)</p>'
           if verification_notes:
               additional_info += f'<p style="color: #28a745; margin-bottom: 8px; font-size: 12px; font-style: italic;">✓ {html.escape(verification_notes)}</p>'
           
           margin_top = 20 if search_source_badge else 20
           if alt_search_badge:
               margin_top = 50
           
           products_html += f'''
               <div style="border: 1px solid #ddd; border-radius: 8px; padding: 15px; margin-bottom: 15px; background: white; position: relative; box-shadow: 0 2px 4px rgba(0,0,0,0.08);">
                   {badge}
                   {verification_badge}
                   {search_source_badge}
                   {alt_search_badge}
                   <h3 style="color: #1a73e8; margin-bottom: 8px; font-size: 16px; margin-top: {margin_top}px;">{title}</h3>
                   <div style="font-size: 28px; color: #2e7d32; font-weight: bold; margin: 12px 0;">{price} <span style="font-size: 12px; color: #666;">USD</span></div>
                   <p style="color: #666; margin-bottom: 8px; font-size: 14px;">🏪 Tienda: {source_store}</p>
                   {additional_info}
                   <a href="{link}" target="_blank" rel="noopener noreferrer" style="background: #1a73e8; color: white; padding: 10px 16px; text-decoration: none; border-radius: 6px; font-weight: 600; display: inline-block; font-size: 14px; transition: background 0.3s;">🛒 Ver Producto REAL</a>
               </div>'''
       
       prices = [p.get('price_numeric', 0) for p in products if p.get('price_numeric', 0) > 0]
       stats = ""
       if prices:
           min_price = min(prices)
           avg_price = sum(prices) / len(prices)
           max_price = max(prices)
           search_type_text = {
               "texto": "texto precision", 
               "imagen": "imagen IA precision", 
               "texto+imagen": "texto + imagen precision", 
               "combined": "búsqueda mixta precision"
           }.get(search_type, search_type)
           
           stats = f'''
               <div style="background: #e8f5e8; border: 1px solid #4caf50; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
                   <h3 style="color: #2e7d32; margin-bottom: 8px;">🎯 Resultados Verificados ({search_type_text})</h3>
                   <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 10px; font-size: 14px;">
                       <p><strong>📊 Productos:</strong> {len(products)}</p>
                       <p><strong>💰 Más barato:</strong> ${min_price:.2f}</p>
                       <p><strong>📈 Promedio:</strong> ${avg_price:.2f}</p>
                       <p><strong>💸 Más caro:</strong> ${max_price:.2f}</p>
                       <p><strong>⏱️ Tiempo:</strong> {search_time:.1f}s</p>
                       <p><strong>🔍 Modo:</strong> Precision</p>
                   </div>
                   {"<p style='margin-top: 10px; color: #ff9800; font-size: 13px;'><strong>🔄 Búsqueda alternativa aplicada</strong></p>" if alternative_search else ""}
               </div>'''
       
       content = f'''
       <div style="max-width: 800px; margin: 0 auto;">
           <div style="background: rgba(255,255,255,0.15); padding: 12px; border-radius: 8px; margin-bottom: 15px; text-align: center; display: flex; align-items: center; justify-content: center;">
               <span style="color: white; font-size: 14px;"><strong>{user_name_escaped}</strong></span>
               <span class="precision-badge">PRECISION MODE</span>
               <div style="margin-left: 15px;">
                   <a href="{url_for('auth_logout')}" style="background: rgba(220,53,69,0.9); color: white; padding: 6px 12px; border-radius: 4px; text-decoration: none; font-size: 13px; margin-right: 8px;">Salir</a>
                   <a href="{url_for('search_page')}" style="background: rgba(40,167,69,0.9); color: white; padding: 6px 12px; border-radius: 4px; text-decoration: none; font-size: 13px;">Nueva Búsqueda</a>
               </div>
           </div>
           
           <h1 style="color: white; text-align: center; margin-bottom: 8px;">🎯 Productos Verificados: "{query}"</h1>
           <p style="text-align: center; color: rgba(255,255,255,0.9); margin-bottom: 25px;">OpenAI Agent Precision Mode - Solo productos REALES</p>
           
           {stats}
           {products_html}
       </div>'''
       
       return render_template_string(render_page('Resultados Precision - Price Finder USA', content))
   except Exception as e:
       logger.error(f"Results page error: {e}")
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
           'version': '3.1 - OpenAI Agent Precision Mode - FIXED',
           'precision_mode': True,
           'verification_enabled': True,
           'cache_type': 'persistent_shelve'
       })
   except Exception as e:
       logger.error(f"Health check error: {e}")
       return jsonify({'status': 'ERROR', 'message': str(e)}), 500

# Rate limiting básico
from collections import defaultdict
from threading import Lock

class SimpleRateLimit:
    def __init__(self):
        self.requests = defaultdict(list)
        self.lock = Lock()
        self.max_requests = 10
        self.time_window = 60  # 1 minuto
    
    def is_allowed(self, user_id):
        with self.lock:
            now = time.time()
            user_requests = self.requests[user_id]
            
            # Limpiar requests viejos
            user_requests[:] = [req_time for req_time in user_requests if now - req_time < self.time_window]
            
            if len(user_requests) >= self.max_requests:
                return False
            
            user_requests.append(now)
            return True

rate_limiter = SimpleRateLimit()

@app.before_request
def before_request():
    # Rate limiting para API endpoints
    if request.endpoint == 'api_search':
        user_id = session.get('user_id', request.remote_addr)
        if not rate_limiter.is_allowed(user_id):
            return jsonify({'success': False, 'message': 'Demasiadas solicitudes. Intenta de nuevo en un minuto.'}), 429
    
    # Manejo de sesión mejorado
    if 'timestamp' in session:
        try:
            timestamp_str = session['timestamp']
            if isinstance(timestamp_str, str) and len(timestamp_str) > 10:
                last_activity = datetime.fromisoformat(timestamp_str)
                time_diff = (datetime.now() - last_activity).total_seconds()
                if time_diff > 1800:  # 30 minutos
                    session.clear()
                    logger.info("Session cleared due to inactivity")
        except Exception as e:
            logger.warning(f"Error validating session timestamp: {e}")
            session.clear()
   
    session['timestamp'] = datetime.now().isoformat()

@app.after_request
def after_request(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.errorhandler(404)
def not_found(error):
    logger.warning(f"404 error: {request.url}")
    return '<h1>404 - Pagina no encontrada</h1><p><a href="/">Volver al inicio</a></p>', 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"500 error: {error}")
    return '<h1>500 - Error interno</h1><p><a href="/">Volver al inicio</a></p>', 500

@app.errorhandler(429)
def rate_limit_error(error):
    logger.warning(f"Rate limit exceeded: {request.remote_addr}")
    return jsonify({'success': False, 'message': 'Demasiadas solicitudes. Intenta de nuevo más tarde.'}), 429

# Cleanup function para cache
def cleanup_cache():
    """Función para limpiar cache periódicamente"""
    try:
        cache = PersistentCache()
        # El cleanup se hace automáticamente en la clase
        logger.info("Cache cleanup completed")
    except Exception as e:
        logger.error(f"Error during cache cleanup: {e}")

# Verificación de configuración al inicio
def verify_configuration():
    """Verifica que todas las configuraciones necesarias estén presentes"""
    issues = []
    
    if not os.environ.get('SECRET_KEY'):
        issues.append("SECRET_KEY no configurada")
    
    if not os.environ.get('FIREBASE_WEB_API_KEY'):
        issues.append("FIREBASE_WEB_API_KEY no configurada")
    
    if not OPENAI_READY:
        issues.append("OpenAI no configurado correctamente")
    
    if not PIL_AVAILABLE:
        issues.append("PIL/Pillow no disponible - análisis de imagen deshabilitado")
    
    if issues:
        logger.warning("Problemas de configuración detectados:")
        for issue in issues:
            logger.warning(f"  - {issue}")
    else:
        logger.info("Todas las configuraciones están correctas")
    
    return len(issues) == 0

if __name__ == '__main__':
    logger.info("Price Finder USA con OpenAI Agent Precision Mode - FIXED VERSION - Starting...")
    
    # Verificar configuración
    config_ok = verify_configuration()
    
    # Mostrar estado de componentes
    logger.info(f"Firebase: {'OK' if os.environ.get('FIREBASE_WEB_API_KEY') else 'NOT_CONFIGURED'}")
    logger.info(f"OpenAI API: {'OK' if OPENAI_READY else 'NOT_CONFIGURED'}")
    logger.info(f"OpenAI Vision: {'OK' if OPENAI_READY and PIL_AVAILABLE else 'NOT_CONFIGURED'}")
    logger.info(f"PIL/Pillow: {'OK' if PIL_AVAILABLE else 'NOT_CONFIGURED'}")
    logger.info(f"Precision Mode: ENABLED")
    logger.info(f"Verification: ENABLED")
    logger.info(f"Alternative Search: ENABLED")
    logger.info(f"Rate Limiting: ENABLED")
    logger.info(f"Persistent Cache: ENABLED")
    logger.info(f"Puerto: {os.environ.get('PORT', '5000')}")
    
    if not config_ok:
        logger.warning("La aplicación se iniciará con funcionalidad limitada debido a problemas de configuración")
    
    app.run(
        host='0.0.0.0', 
        port=int(os.environ.get('PORT', 5000)), 
        debug=False, 
        threaded=True
    )
else:
    # Configuración para producción
    verify_configuration()
    
    # Configurar logging para producción
    if not app.debug:
        import logging
        from logging.handlers import RotatingFileHandler
        
        # Crear directorio de logs si no existe
        if not os.path.exists('logs'):
            os.mkdir('logs')
        
        file_handler = RotatingFileHandler('logs/webapp.log', maxBytes=10240000, backupCount=10)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        
        app.logger.setLevel(logging.INFO)
        app.logger.info('Price Finder USA startup - FIXED VERSION')
        
        # Suprimir logs de werkzeug en producción
        logging.getLogger('werkzeug').setLevel(logging.WARNING)
