# 05 · Hashing y Cracking de Contraseñas

> Este bloque cubre dos conceptos fundamentales en la seguridad de credenciales: el hashing criptográfico, utilizado para garantizar la integridad de datos y el almacenamiento seguro de contraseñas, y el cracking de hashes, técnica ofensiva que permite recuperar contraseñas en texto claro a partir de su representación hasheada.

---

## 5.1 · Hashing Criptográfico

Un hash es el resultado de aplicar una función matemática unidireccional sobre un dato, produciendo una cadena de longitud fija (el "digest") que actúa como huella digital de ese dato. Las propiedades que hacen al hashing útil en ciberseguridad son:

- **Determinista:** El mismo input siempre produce el mismo hash.
- **Unidireccional:** No es posible reconstruir el input original a partir del hash.
- **Sensible a cambios:** Un mínimo cambio en el input produce un hash completamente diferente (efecto avalancha).
- **Sin colisiones prácticas:** Dos inputs distintos no deben producir el mismo hash.

**Algoritmos más comunes:**

| Algoritmo | Longitud del digest | Estado |
|---|---|---|
| MD5 | 128 bits / 32 hex | Obsoleto para seguridad |
| SHA-1 | 160 bits / 40 hex | Deprecado |
| SHA-256 | 256 bits / 64 hex | Recomendado |
| SHA-512 | 512 bits / 128 hex | Recomendado para alta seguridad |

**Usos principales en ciberseguridad:**
- Verificación de integridad de archivos (detectar si un archivo ha sido modificado o corrompido).
- Almacenamiento seguro de contraseñas en bases de datos.
- Detección de malware por firma (comparación de hashes).
- Verificación de evidencias digitales en análisis forense.

### 5.1.1 · Hashing básico de una cadena de texto

> **Generación de hash SHA-256 sobre texto:** La función `hashlib.sha256()` recibe los datos en formato bytes (por eso se llama a `.encode()` sobre el texto). El método `.hexdigest()` devuelve el hash en representación hexadecimal legible, que es el formato estándar utilizado en ciberseguridad.

```python
import hashlib

texto = "ciberseguridad"

hash_resultado = hashlib.sha256(texto.encode())

print("Hash SHA-256:", hash_resultado.hexdigest())
```

### 5.1.2 · Hashing de archivos por bloques

> **Cálculo de hash SHA-256 sobre un archivo completo:** Para archivos grandes no se carga todo el contenido en memoria de golpe. En su lugar se lee el archivo en bloques de 4096 bytes y se actualiza el hash progresivamente con cada bloque usando `.update()`. El archivo se abre en modo binario (`"rb"`) para procesar cualquier tipo de archivo, no solo texto. La función `iter(lambda: f.read(4096), b"")` genera bloques hasta que `.read()` devuelve un bytestring vacío, señal de que se llegó al final del archivo.

```python
import hashlib

def hash_archivo(ruta):
    hash_256 = hashlib.sha256()

    with open(ruta, "rb") as f:
        for bloque in iter(lambda: f.read(4096), b""):
            hash_256.update(bloque)

    return hash_256.hexdigest()

print("Hash del archivo:", hash_archivo("ejemplo.txt"))
```

### 5.1.3 · Proyecto del bloque: Herramienta de verificación de integridad

> **Comparador de integridad entre dos archivos:** La herramienta calcula el hash SHA-256 de dos archivos y los compara. Si los hashes son idénticos, los archivos son bit a bit iguales; si difieren, el contenido ha sido modificado. Incluye verificación de existencia previa de cada archivo con `os.path.exists()` para ofrecer mensajes de error descriptivos. Esta herramienta tiene aplicación directa en análisis forense (verificar que una evidencia no ha sido alterada) y en distribución de software (comprobar que un descargado no está corrompido).

```python
import hashlib
import os

def hash_archivo(ruta):
    """Calcula el hash SHA-256 de un archivo procesándolo por bloques."""
    hash_256 = hashlib.sha256()

    if not os.path.exists(ruta):
        return None

    with open(ruta, "rb") as f:
        for bloque in iter(lambda: f.read(4096), b""):
            hash_256.update(bloque)

    return hash_256.hexdigest()


def comparar_archivos(archivo1, archivo2):
    """Compara los hashes SHA-256 de dos archivos y determina si son idénticos."""
    print("Analizando archivos...\n")

    hash1 = hash_archivo(archivo1)
    hash2 = hash_archivo(archivo2)

    # Control de errores si alguno de los archivos no existe
    if hash1 is None:
        print(f"❌ Error: El archivo '{archivo1}' no existe.")
        return
    if hash2 is None:
        print(f"❌ Error: El archivo '{archivo2}' no existe.")
        return

    print(f"Hash de '{archivo1}':\n  {hash1}")
    print(f"Hash de '{archivo2}':\n  {hash2}")
    print("-" * 65)

    if hash1 == hash2:
        print("✅ Los archivos son IDÉNTICOS.")
        print("   El contenido de ambos archivos es exactamente el mismo (bit a bit).")
    else:
        print("⚠️  Los archivos son DIFERENTES.")
        print("   El contenido ha sido modificado, alterado o son archivos distintos.")


# Reemplaza con las rutas de los archivos que quieras comparar
archivo_a = "ejemplo.txt"
archivo_b = "ejemplo_copia.txt"

comparar_archivos(archivo_a, archivo_b)
```

---

## 5.2 · Cracking de Contraseñas

El cracking de contraseñas es el proceso de intentar recuperar una contraseña en texto claro a partir de su hash. Dado que el hashing es unidireccional, los métodos de cracking no "revierten" el hash, sino que comparan el hash objetivo con los hashes de contraseñas candidatas hasta encontrar una coincidencia.

**Métodos principales de cracking:**

| Método | Descripción | Velocidad | Cobertura |
|---|---|---|---|
| Diccionario | Prueba palabras de una lista predefinida | Alta | Limitada al diccionario |
| Fuerza bruta | Prueba todas las combinaciones posibles | Baja | Total (dado tiempo suficiente) |
| Rainbow tables | Tablas precomputadas de hashes | Muy alta | Limitada por el espacio en disco |
| Híbrido | Combina diccionario con mutaciones | Media-alta | Amplia |

> **Nota:** El cracking de contraseñas sin autorización es ilegal. Estas técnicas se aplican en pentesting autorizado, auditorías de seguridad, recuperación de credenciales propias o entornos de laboratorio.

### 5.2.1 · Ataque de diccionario sobre hash SHA-256

> **Implementación de un ataque de diccionario:** El script hashea cada candidato del diccionario en tiempo real y lo compara con el hash objetivo. Si hay coincidencia, la contraseña ha sido encontrada. Este enfoque es más eficiente en memoria que las rainbow tables (no requiere almacenar hashes precomputados) y es el más usado en herramientas como `hashcat` o `John the Ripper` en su modo de diccionario. El contador `i` registra el número de intentos realizados hasta el hallazgo.

```python
import hashlib

def sha256_hash(texto: str) -> str:
    """Devuelve el hash SHA-256 de una cadena de texto."""
    return hashlib.sha256(texto.encode()).hexdigest()


def ataque_diccionario(hash_objetivo: str, ruta_diccionario: str):
    """
    Intenta encontrar la contraseña que produce el hash objetivo
    probando cada entrada del diccionario proporcionado.
    """
    with open(ruta_diccionario, "r", encoding="utf-8") as f:
        for i, linea in enumerate(f, 1):
            candidato = linea.strip()

            # Ignorar líneas vacías
            if not candidato:
                continue

            if sha256_hash(candidato) == hash_objetivo:
                return candidato, i

    # Si se recorre todo el diccionario sin éxito
    return None, i


if __name__ == "__main__":
    # Contraseña objetivo (en un escenario real, solo tendríamos el hash)
    contrasena_objetivo = "P4ssw0rd"
    hash_objetivo = sha256_hash(contrasena_objetivo)

    print(f"Hash objetivo: {hash_objetivo}")
    print("Iniciando ataque de diccionario...\n")

    encontrada, intentos = ataque_diccionario(hash_objetivo, "diccionario_demo.txt")

    if encontrada:
        print(f"✅ Contraseña encontrada: '{encontrada}'")
        print(f"   Intentos realizados:    {intentos}")
    else:
        print(f"❌ Contraseña no encontrada en el diccionario.")
        print(f"   Candidatos probados: {intentos}")
```
