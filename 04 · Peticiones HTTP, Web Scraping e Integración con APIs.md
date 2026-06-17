# 04 · Peticiones HTTP, Web Scraping e Integración con APIs

> Este bloque cubre la interacción automatizada con aplicaciones web y servicios externos. Con la librería `requests` se envían peticiones HTTP, se analizan cabeceras y se detectan configuraciones inseguras. Con `BeautifulSoup` se extrae información estructurada de páginas web. Finalmente, se integran APIs de ciberseguridad reales para enriquecer los análisis con inteligencia de amenazas.

---

## 4.1 · Peticiones HTTP con `requests`

La librería `requests` abstrae la complejidad de trabajar con sockets y protocolos HTTP, permitiendo enviar peticiones, leer respuestas y analizar cabeceras con una sintaxis muy limpia. Es la base de la mayoría de herramientas de reconocimiento web escritas en Python.

> **Instalación:** `pip install requests`

### Conceptos previos

**URL (Uniform Resource Locator):** Dirección única que identifica un recurso en Internet (página, archivo, endpoint de API, etc.).

**Cabeceras HTTP (Headers):** Metadatos que acompañan a cada petición y respuesta. Contienen información sobre el tipo de contenido, cookies, tecnologías del servidor, políticas de seguridad, etc.

**Métodos HTTP más comunes:**

| Método | Uso |
|---|---|
| `GET` | Obtener un recurso (lectura) |
| `POST` | Enviar datos al servidor (formularios, login) |
| `PUT` | Actualizar un recurso existente |
| `DELETE` | Eliminar un recurso |
| `HEAD` | Obtener solo las cabeceras, sin cuerpo |

**Códigos de estado HTTP:**

| Código | Significado |
|---|---|
| `200` | OK — éxito |
| `301/302` | Redirección |
| `403` | Prohibido — sin permisos |
| `404` | No encontrado |
| `500` | Error interno del servidor |

---

### 4.1.1 · Petición GET: código de estado, cabeceras y contenido

> **Inspección básica de una respuesta HTTP:** Se realiza una petición GET y se extraen las tres partes fundamentales de la respuesta: el código de estado (indica si el servidor respondió correctamente), las cabeceras (metadatos de la respuesta) y los primeros 300 caracteres del cuerpo HTML. Útil como punto de partida de cualquier reconocimiento web.

```python
import requests

url = "https://ejemplo.com"
respuesta = requests.get(url)

print("Código de estado:", respuesta.status_code)
print("Encabezados:", respuesta.headers)
print("Contenido:", respuesta.text[:300])
```

### 4.1.2 · Petición POST: envío de credenciales

> **Simulación de envío de formulario:** El método POST envía datos al servidor en el cuerpo de la petición, no en la URL. Aquí se usa para simular el envío de un formulario de login con usuario y contraseña. La respuesta del servidor indica si la autenticación fue aceptada o rechazada.

```python
import requests

datos = {"usuario": "admin", "password": "1234"}
respuesta = requests.post("https://ejemplo.com", data=datos)

print("Datos enviados:", datos)
print("Respuesta del servidor:", respuesta.status_code)
```

### 4.1.3 · Análisis de cabeceras de seguridad y fingerprinting web

> **Detección de tecnologías y configuraciones inseguras:** Las cabeceras HTTP revelan mucho sobre el servidor: versión del software (`Server`), lenguaje de backend (`X-Powered-By`) y presencia (o ausencia) de cabeceras de seguridad críticas. La ausencia de `Content-Security-Policy` indica vulnerabilidad a XSS; la ausencia de `X-Frame-Options` permite ataques de clickjacking. Las cookies se inspeccionan para verificar si tienen los atributos `HttpOnly` y `Secure` activados.

```python
import requests

url = "https://ejemplo.com"
respuesta = requests.get(url)

print("Servidor:", respuesta.headers.get("Server", "No especificado"))
print("Tipo de contenido:", respuesta.headers.get("Content-Type"))
print("Cookies:", respuesta.cookies)
```

### 4.1.4 · Proyecto del bloque: Herramienta de auditoría de cabeceras web

> **Reporte automatizado de análisis web:** Script completo de reconocimiento web que combina todas las técnicas anteriores. Utiliza un `User-Agent` de navegador real para evitar bloqueos básicos, analiza el estado del servidor, realiza fingerprinting tecnológico, audita la presencia de cabeceras de seguridad obligatorias e inspecciona los atributos de seguridad de las cookies. La salida está formateada como un reporte estructurado listo para incluir en un informe de pentest.

```python
import requests

url = "https://wikipedia.org"

# Cabecera de navegador real para evitar bloqueos por User-Agent
cabeceras_navegador = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

respuesta = requests.get(url, headers=cabeceras_navegador)

print("=" * 50)
print(f"  REPORTE DE ANÁLISIS WEB: {url}")
print("=" * 50)

print(f"\n[+] ESTADO: {respuesta.status_code}")

print("\n[+] TECNOLOGÍA DETECTADA (FINGERPRINTING):")
print(f"    - Servidor:        {respuesta.headers.get('Server', 'No especificado')}")
print(f"    - Desarrollado con: {respuesta.headers.get('X-Powered-By', 'No especificado')}")

print("\n[+] SEGURIDAD EN CABECERAS:")
cabeceras_seguridad = [
    "X-Content-Type-Options",
    "Content-Security-Policy",
    "X-Frame-Options"
]

for cabecera in cabeceras_seguridad:
    if cabecera in respuesta.headers:
        print(f"    [ OK ] {cabecera} está presente.")
    else:
        print(f"    [ALERTA] {cabecera} FALTANTE.")

print("\n[+] COOKIES DETECTADAS:")
if not respuesta.cookies:
    print("    No se detectaron cookies.")
else:
    for cookie in respuesta.cookies:
        print(f"    - Cookie: '{cookie.name}'")
        print(f"      * HttpOnly: {'SÍ' if cookie.has_nonstandard_attr('HttpOnly') else 'NO'}")
        print(f"      * Secure:   {'SÍ' if cookie.secure else 'NO (Alerta)'}")
```

---

## 4.2 · Web Scraping con BeautifulSoup

El web scraping consiste en parsear el HTML de una página web para extraer información estructurada de forma automatizada. La librería `BeautifulSoup` facilita la navegación por el árbol DOM de un documento HTML, permitiendo buscar elementos por etiqueta, clase, atributo o cualquier combinación.

> **Instalación:** `pip install requests beautifulsoup4`

### 4.2.1 · Extracción de citas y autores

> **Scraping básico de elementos por clase CSS:** Se parsea el HTML de la página con `BeautifulSoup` y se buscan todos los elementos `<span>` con clase `text` (citas) y todos los `<small>` con clase `author` (autores). La función `zip()` empareja cada cita con su autor correspondiente y se imprimen juntos.

```python
import requests
from bs4 import BeautifulSoup

url = "https://quotes.toscrape.com"
respuesta = requests.get(url)

if respuesta.status_code == 200:
    soup = BeautifulSoup(respuesta.text, "html.parser")

    citas = soup.find_all("span", class_="text")
    autores = soup.find_all("small", class_="author")

    print("Citas encontradas:\n")
    for c, a in zip(citas, autores):
        print(f"{a.text}: {c.text}")
else:
    print("No se pudo acceder a la página.")
```

### 4.2.2 · Proyecto del bloque: Extractor genérico de datos y enlaces

> **Herramienta de scraping parametrizable:** La función `buscar_dato_o_enlace()` acepta una URL, una etiqueta HTML, una clase CSS opcional y un flag para indicar si se quieren extraer enlaces (`href`) o texto plano. Este diseño modular permite reutilizarla sobre cualquier web sin modificar el código central, simplemente cambiando los parámetros de llamada.

```python
import requests
from bs4 import BeautifulSoup

def buscar_dato_o_enlace(url, etiqueta, clase=None, es_enlace=False):
    respuesta = requests.get(url)

    if respuesta.status_code == 200:
        soup = BeautifulSoup(respuesta.text, "html.parser")

        # Filtrado por clase si se especifica
        filtros = {"class": clase} if clase else {}
        elementos = soup.find_all(etiqueta, filtros)

        resultados = []
        for el in elementos:
            if es_enlace:
                enlace = el.get("href")
                if enlace:
                    resultados.append(enlace)
            else:
                resultados.append(el.text.strip())

        return resultados
    else:
        print("No se pudo acceder a la página.")
        return []


url_objetivo = "https://quotes.toscrape.com/"

# Ejemplo A: Extracción de enlaces
print("--- Enlaces encontrados ---")
enlaces = buscar_dato_o_enlace(url_objetivo, etiqueta="a", es_enlace=True)
print(enlaces[:5])

# Ejemplo B: Extracción de texto por clase CSS
print("\n--- Citas encontradas ---")
citas = buscar_dato_o_enlace(url_objetivo, etiqueta="span", clase="text")
print(citas[:3])
```

---

## 4.3 · Integración con APIs de Ciberseguridad

Las APIs permiten que nuestros scripts consulten bases de datos de inteligencia de amenazas en tiempo real: filtraciones de credenciales, reputación de URLs, análisis de malware, etc. La mayoría requieren una API key que identifica al usuario y se envía en la cabecera de la petición.

> **Buena práctica de seguridad:** Nunca escribir la API key directamente en el código. Almacenarla en una variable de entorno (`VT_API_KEY`) y leerla con `os.getenv()`.

### 4.3.1 · Conexión a una API pública sin autenticación

> **Petición básica a una API REST:** Se realiza una petición GET a `jsonplaceholder.typicode.com`, una API de prueba pública. `response.json()` parsea automáticamente la respuesta JSON y la convierte en un diccionario Python. Este patrón es idéntico para cualquier API REST.

```python
import requests

url = "https://jsonplaceholder.typicode.com/posts/1"
response = requests.get(url)

print("Código de estado:", response.status_code)
print("Contenido recibido:")
print(response.json())
```

### 4.3.2 · Consulta de filtraciones con HaveIBeenPwned

> **Verificación de correos en bases de datos de filtraciones:** La API de HaveIBeenPwned permite comprobar si una dirección de correo ha aparecido en alguna filtración de datos conocida. La API key se envía en la cabecera `hibp-api-key`. Si el correo aparece en filtraciones (`200 OK`), se listan los nombres de los servicios comprometidos. Si no aparece (`404`), el correo está limpio.

```python
import requests
import os

api_key = os.getenv("HIBP_API_KEY")

email = "adri@prueba.com"
url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"

headers = {
    "hibp-api-key": api_key,
    "user-agent": "python-security-tool"
}

response = requests.get(url, headers=headers)

if response.status_code == 200:
    filtraciones = response.json()
    print(f"El correo {email} fue encontrado en {len(filtraciones)} filtraciones:")
    for b in filtraciones:
        print("-", b["Name"])
elif response.status_code == 404:
    print("El correo no aparece en ninguna filtración conocida.")
else:
    print("Error:", response.status_code, response.text)
```

### 4.3.3 · Proyecto del bloque: Verificador de URLs con VirusTotal

> **Análisis de reputación de URLs vía API de VirusTotal:** VirusTotal agrega los resultados de más de 70 motores antivirus y herramientas de análisis web. Para consultar una URL, primero hay que codificarla en Base64 sin relleno (requisito de la API para manejar caracteres especiales en la ruta del endpoint). Se extraen las estadísticas del análisis y se determina si la URL es segura, sospechosa o maliciosa en función del número de motores que la marcan negativamente.

```python
import os
import base64
import requests

# Lectura de la API key desde variable de entorno
api_key = os.getenv("VT_API_KEY")

if not api_key:
    print("Error: No se encontró la variable de entorno VT_API_KEY")
    exit()

url_a_revisar = "https://www.google.com"

# VirusTotal requiere la URL codificada en Base64 sin el relleno '='
url_id = base64.urlsafe_b64encode(url_a_revisar.encode()).decode().strip("=")

endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
headers = {
    "accept": "application/json",
    "x-apikey": api_key
}

response = requests.get(endpoint, headers=headers)

if response.status_code == 200:
    resultado = response.json()
    stats = resultado["data"]["attributes"]["last_analysis_stats"]

    maliciosos  = stats["malicious"]
    sospechosos = stats["suspicious"]
    limpios     = stats["harmless"] + stats["undetected"]

    print(f"Resultados del análisis para: {url_a_revisar}")
    print("-" * 45)
    print(f"  Motores que la marcan como MALICIOSA:   {maliciosos}")
    print(f"  Motores que la marcan como SOSPECHOSA:  {sospechosos}")
    print(f"  Motores que la marcan como LIMPIA:      {limpios}")
    print("-" * 45)

    if maliciosos > 0 or sospechosos > 1:
        print("⚠️  CONCLUSIÓN: La URL NO es segura.")
    else:
        print("✅ CONCLUSIÓN: La URL parece segura.")

elif response.status_code == 404:
    print("La URL no está en la base de datos. Es necesario enviarla a analizar primero.")
else:
    print(f"Error {response.status_code}: {response.text}")
```
