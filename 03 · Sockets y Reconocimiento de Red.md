# 03 · Sockets y Reconocimiento de Red

> Este bloque introduce la programación de red en Python a través del módulo `socket`. Se trabaja desde el establecimiento de conexiones TCP básicas hasta técnicas de reconocimiento activo como el banner grabbing y el fingerprinting de servicios, fundamentales en la fase de enumeración de un pentest.

---

## 3.1 · Fundamentos de Sockets TCP

Un socket es el punto de comunicación entre dos programas a través de la red. Python abstrae toda la complejidad del protocolo TCP/IP mediante el módulo `socket`, permitiendo conectarse a servidores, enviar datos y recibir respuestas con pocas líneas de código.

**Parámetros clave al crear un socket:**

| Parámetro | Valor | Descripción |
|---|---|---|
| Familia de direcciones | `AF_INET` | IPv4 |
| Tipo de socket | `SOCK_STREAM` | Protocolo TCP (orientado a conexión) |

### 3.1.1 · Conexión TCP y petición HTTP manual

> **Ciclo completo cliente-servidor a nivel de socket:** Se crea un socket TCP/IPv4, se establece la conexión con el servidor de destino y se envía una petición HTTP GET de forma manual. Las peticiones HTTP son cadenas de bytes (prefijo `b`), no texto, ya que los protocolos de red trabajan a nivel binario. La respuesta se recibe en un buffer de 1024 bytes y se decodifica ignorando caracteres no válidos. Este ejercicio ilustra exactamente lo que hace un navegador web en su capa más baja.

```python
import socket

# Socket IPv4 con protocolo TCP
cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

host = "google.com"
puerto = 80

cliente.connect((host, puerto))
print("CONEXIÓN CORRECTA")

# Petición HTTP GET manual — los bytes van prefijados con 'b'
peticion = b"GET / HTTP/1.1\r\nHost: google.com\r\n\r\n"
cliente.send(peticion)

respuesta = cliente.recv(1024)

print("Respuesta recibida:\n", respuesta.decode(errors="ignore"))

cliente.close()
print("CONEXIÓN CERRADA EXITOSAMENTE")
```

---

## 3.2 · Banner Grabbing y Fingerprinting

El banner grabbing es una técnica de reconocimiento pasivo que consiste en conectarse a un puerto abierto y capturar el mensaje de bienvenida (banner) que devuelve el servicio. Este banner suele revelar el nombre del software, su versión y en ocasiones el sistema operativo subyacente, información crítica para identificar vulnerabilidades conocidas.

El fingerprinting va un paso más allá: combina múltiples indicadores (banners, cabeceras, comportamiento del servicio) para elaborar un perfil técnico completo del objetivo.

### 3.2.1 · Escáner de banners con timeout y manejo de errores

> **Función de banner grabbing sobre múltiples puertos:** La función `obtener_banner()` encapsula toda la lógica de conexión: crea el socket, fija un timeout de 1 segundo para no quedarse bloqueado en puertos cerrados, envía un saludo genérico (`\r\n`) y captura la respuesta. El bloque `try/except` garantiza que el script continúe aunque un puerto no responda o rechace la conexión. El bloque `if __name__ == "__main__"` asegura que el código de ejecución solo se active cuando el script se lanza directamente, no cuando se importa como módulo.

```python
import socket

def obtener_banner(ip, puerto):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((ip, puerto))

        s.send(b"\r\n")
        # Para servicios HTTP en puerto 8080, usar:
        # s.send(b"HEAD / HTTP/1.1\r\nHost: <ip>\r\n\r\n")

        banner = s.recv(1024).decode(errors="ignore")
        s.close()

        if banner:
            return banner.strip()
        else:
            return "SIN RESPUESTA"
    except Exception as e:
        return f"ERROR: {e}"


if __name__ == "__main__":
    ip = input("Introduce la IP objetivo: ")
    puertos = [21, 22, 25, 80, 443, 100, 8080]
    print(f"\nAnalizando {ip}...\n")

    for p in puertos:
        banner = obtener_banner(ip, p)
        print(f"Puerto {p} -> {banner}")
```

### 3.2.2 · Proyecto del bloque: Escáner con exportación de resultados

> **Persistencia de resultados en archivo de texto:** Amplía el escáner anterior añadiendo escritura de resultados en un archivo `banner.txt`. El modo de apertura `"a"` (append) acumula los resultados sin sobreescribir los anteriores, lo que permite ejecutar el script contra varios objetivos y conservar el historial completo. Cada línea del archivo incluye el puerto, la IP y el banner capturado.

```python
import socket

def obtener_banner(ip, puerto):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((ip, puerto))

        s.send(b"\r\n")

        banner = s.recv(1024).decode(errors="ignore")
        s.close()

        if banner:
            return banner.strip()
        else:
            return "SIN RESPUESTA"
    except Exception as e:
        return f"ERROR: {e}"


if __name__ == "__main__":
    ip = input("Introduce la IP objetivo: ")
    puertos = [21, 22, 25, 80, 443, 100, 8080]
    print(f"\nAnalizando {ip}...\n")

    for p in puertos:
        banner = obtener_banner(ip, p)

        # Construcción del registro a guardar
        registro = f"Puerto {p} -> IP: {ip} | Banner: {banner}"

        # Modo "a" para acumular resultados sin sobreescribir
        with open("banner.txt", "a", encoding="utf-8") as archivo:
            archivo.write(registro + "\n")

    print("Resultados guardados en banner.txt")
```
