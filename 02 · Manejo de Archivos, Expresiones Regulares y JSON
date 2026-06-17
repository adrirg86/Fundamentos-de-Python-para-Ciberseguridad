# 02 · Manejo de Archivos, Expresiones Regulares y JSON

> Este bloque cubre tres habilidades fundamentales para el análisis de datos en ciberseguridad: leer y escribir archivos (logs, reportes, evidencias), extraer patrones complejos de texto con expresiones regulares y trabajar con el formato JSON, estándar en APIs y herramientas OSINT.

---

## 2.1 · Lectura y Escritura de Archivos

En análisis forense y monitorización de sistemas, los archivos son la fuente primaria de evidencia: logs de acceso, registros de eventos, listas de IPs... Python gestiona archivos con la función `open()` dentro de un bloque `with`, que garantiza el cierre correcto del archivo aunque ocurra un error durante la ejecución.

**Modos de apertura más comunes:**

| Modo | Descripción |
|---|---|
| `"r"` | Lectura (el archivo debe existir) |
| `"w"` | Escritura — sobreescribe el contenido existente |
| `"a"` | Escritura — añade al final sin borrar el contenido |
| `"rb"` | Lectura en modo binario (para archivos no textuales) |

### 2.1.1 · Lectura completa de un archivo

> **Carga de contenido en una sola operación:** `.read()` carga todo el contenido del archivo en una cadena de texto. Útil cuando el archivo es pequeño y se necesita acceso al texto completo para búsquedas o análisis globales.

```python
with open("ejemplo.txt", "r") as f:
    contenido = f.read()
    print(contenido)
```

### 2.1.2 · Lectura línea a línea

> **Procesado de registros individuales:** Al iterar sobre el objeto de archivo con un `for`, Python lee y entrega una línea en cada vuelta. El método `.strip()` elimina saltos de línea (`\n`) y espacios en blanco al inicio y final, limpiando cada registro antes de procesarlo.

```python
with open("ejemplo.txt", "r") as f:
    for linea in f:
        print("Linea:", linea.strip())
```

### 2.1.3 · Escritura en un archivo

> **Generación de alertas o reportes:** El modo `"w"` crea el archivo si no existe o sobreescribe su contenido si ya existe. Ideal para volcar resultados de escaneos o registrar eventos de seguridad. Para añadir sin borrar, se usa el modo `"a"` (append).

```python
with open("ejemplo.txt", "w") as f:
    f.write("Intruso detectado")
```

### 2.1.4 · Proyecto del bloque: Contador de intentos de intrusión

> **Análisis de log de accesos:** El script abre un archivo donde cada línea representa un intento de acceso registrado, e incrementa un contador por cada una. Al terminar, reporta el total de intrusiones detectadas. Este patrón es directamente aplicable al análisis de logs de SSH, FTP o cualquier servicio con registro de accesos.

```python
contador = 0

with open("contraseña.txt", "r") as f:
    for linea in f:
        contador += 1

print("Hemos tenido", contador, "intrusiones")
```

---

## 2.2 · Expresiones Regulares

La librería `re` de Python permite buscar, extraer y validar patrones complejos dentro de cadenas de texto. Es una herramienta indispensable para analistas forenses que deben procesar grandes volúmenes de logs en busca de IPs, puertos, fechas, hashes o cualquier patrón estructurado.

**Patrones más utilizados:**

| Patrón | Coincide con |
|---|---|
| `\d+` | Uno o más dígitos |
| `\d{1,3}` | Entre 1 y 3 dígitos |
| `\.` | Un punto literal |
| `^` | Inicio de línea |
| `$` | Fin de línea |
| `( )` | Grupo de captura |

### 2.2.1 · Extracción de números en un texto

> **Detección de puertos en mensajes de log:** `re.findall()` devuelve una lista con todas las coincidencias del patrón en el texto. El patrón `\d+` captura cualquier secuencia de dígitos consecutivos, lo que permite extraer números de puerto, códigos de error o cualquier valor numérico de un log.

```python
import re

texto = "EL PUERTO 443 ESTÁ ABIERTO"

patron = r"\d+"

resultado = re.findall(patron, texto)

print("PUERTO encontrado:", resultado)
```

### 2.2.2 · Proyecto del bloque: Filtrado de IPs en un rango concreto

> **Extracción de IPs en un rango válido desde un archivo:** El patrón combina grupos de captura y alternativas numéricas para validar que el último octeto de la IP esté estrictamente entre 2 y 254. El flag `re.MULTILINE` hace que `^` y `$` se apliquen a cada línea del archivo en lugar de al texto completo. Finalmente se itera sobre los resultados extrayendo solo el primer grupo de captura, que contiene la IP completa.

```python
import re

with open("direccionesip.txt", "r") as f:
    patron = r"^(192\.0\.0\.([2-9]|[1-9]\d|1\d\d|2[0-4]\d|25[0-4]))$"
    resultado = re.findall(patron, f.read(), re.MULTILINE)

    for coincidencia in resultado:
        print("Dirección detectada:", coincidencia[0])
```

---

## 2.3 · JSON para OSINT y Generación de Reportes

JSON (JavaScript Object Notation) es el formato estándar de intercambio de datos entre aplicaciones y APIs. En ciberseguridad se usa para estructurar reportes de escaneo, consumir respuestas de APIs de inteligencia de amenazas y almacenar resultados de manera legible y procesable. Python incluye la librería `json` de serie, sin necesidad de instalación adicional.

### 2.3.1 · Estructura de ejemplo

El siguiente archivo JSON representa el resultado básico de un escaneo de host:

```json
{
    "ip": "192.168.1.10",
    "puertos": [22, 80, 443]
}
```

### 2.3.2 · Lectura de un archivo JSON completo

> **Carga de un reporte en memoria:** `json.load()` parsea el archivo y lo convierte en un diccionario de Python (`dict`). A partir de ese momento se puede acceder a sus valores con la misma sintaxis que cualquier diccionario.

```python
import json

with open("archivo.json", "r") as f:
    datos = json.load(f)

print("Contenido:", datos)
```

### 2.3.3 · Acceso a un campo específico

> **Extracción de un dato concreto del JSON:** Usando la clave del diccionario se accede directamente al campo deseado sin necesidad de cargar o imprimir toda la estructura. Especialmente útil cuando el JSON contiene muchos campos y solo se necesita uno.

```python
import json

with open("archivo.json", "r") as f:
    datos = json.load(f)

print("IP objetivo:", datos["ip"])
```

### 2.3.4 · Escritura y generación de reportes JSON

> **Generación de un informe de vulnerabilidades:** `json.dump()` serializa un diccionario Python a formato JSON y lo escribe en el archivo. El parámetro `indent=4` aplica sangría para que el archivo sea legible por humanos. Este patrón es la base de cualquier herramienta que genere reportes estructurados.

```python
import json

resultado = {
    "ip": "192.168.1.20",
    "puertos": [21, 8080, 443],
    "vulnerabilidades": "FTP Abierto"
}

with open("archivo.json", "w") as f:
    json.dump(resultado, f, indent=4)

print("REPORTE GENERADO EXITOSAMENTE")
```

### 2.3.5 · Proyecto del bloque: Generador de reportes interactivo

> **Reporte de escaneo a partir de entrada del usuario:** Combina `input()` con `json.dump()` para generar un archivo de reporte personalizado en tiempo de ejecución. El analista introduce la IP y los puertos detectados, y el script los estructura y persiste en un archivo JSON listo para ser procesado por otras herramientas o incluido en un informe.

```python
import json

ip_pedida = input("Dame una IP: ")
puertos_pedida = input("Dime los puertos abiertos: ")

reporte = {
    "ip": ip_pedida,
    "puertos_y_estados": puertos_pedida
}

with open("archivo.json", "w") as f:
    json.dump(reporte, f, indent=4)

print("Reporte guardado correctamente.")
```
