# 01 · Fundamentos de Python para Ciberseguridad

> Introducción al lenguaje Python y sus bases sintácticas aplicadas al contexto de la seguridad ofensiva y defensiva. Se cubren los bloques de construcción esenciales: variables, operadores, estructuras de control y funciones, que sirven de base para todos los scripts desarrollados en los módulos posteriores.

---

## 1.1 · ¿Por qué Python es el lenguaje favorito en ciberseguridad?

Python destaca frente a otros lenguajes por su combinación de sencillez, potencia y un ecosistema de librerías especializadas que abarca tanto el lado ofensivo como el defensivo. Herramientas ampliamente usadas en el sector como `wfuzz` o `impacket` están escritas en Python o exponen interfaces Python para su automatización.

**Ventajas principales:**

| Característica | Descripción |
|---|---|
| Legibilidad | Sintaxis limpia que permite centrarse en la lógica, no en el lenguaje |
| Librerías especializadas | Ecosistema maduro: `scapy`, `requests`, `impacket`, `pwntools`... |
| Automatización | Ideal para tareas repetitivas: escaneos, fuzzing, parsing de logs |
| Multiplataforma | Funciona en Windows, Linux y macOS sin cambios |

> **Primer script — Verificación del entorno:** El clásico "Hola Mundo" adaptado al contexto. Sirve para confirmar que Python está correctamente instalado y que la función `print()` muestra salida por pantalla.

```python
print("Hola hackers")
# Muestra por pantalla el mensaje
```

---

## 1.2 · Variables y Operadores

Las variables permiten almacenar datos en memoria para usarlos a lo largo del script. En ciberseguridad son la base para manejar IPs, puertos, credenciales o estados de conexión. Los operadores permiten comparar y combinar esos datos para tomar decisiones.

### 1.2.1 · Tipos de datos básicos

Python es un lenguaje de tipado dinámico: el tipo de la variable se deduce automáticamente del valor que se le asigna.

> **Declaración de variables de red:** Se declaran tres variables con tipos distintos — `str` (cadena de texto), `int` (entero) y `bool` (booleano) — y se combinan en un único `print()` para mostrar el estado de una conexión.

```python
ip = "192.168.1.25"
puerto = 22
activo = True

print("La dirección", ip, "está en el puerto", puerto, "la actividad es:", activo)
```

### 1.2.2 · Operadores de comparación y lógicos

> **Validación simple de contraseña:** El operador `==` compara el valor de la variable con el esperado. La estructura `if/else` bifurca la ejecución según el resultado, permitiendo controlar el acceso.

```python
contraseña = "Adri"

if contraseña == "Adri":
    print("Acceso correcto")
else:
    print("Acceso denegado")
```

> **Validación de credenciales dobles:** El operador lógico `and` exige que ambas condiciones sean verdaderas simultáneamente. Si cualquiera falla, el acceso se deniega. Reproduce la lógica básica de un sistema de autenticación usuario + contraseña.

```python
usuario = "admin"
password = "1234"

if usuario == "admin" and password == "1234":
    print("Acceso concedido")
else:
    print("Acceso denegado")
```

### 1.2.3 · Entrada de datos por consola

> **Entrada de tipo texto (`str`):** La función `input()` detiene la ejecución y espera a que el usuario escriba algo. El valor siempre se recibe como cadena de texto.

```python
nombre = input("¿Cómo te llamas? ")
print("Hola,", nombre)
```

> **Entrada de tipo entero (`int`):** Como `input()` devuelve texto, es necesario convertir el valor con `int()` antes de operar matemáticamente con él. Sin esta conversión, Python lanzaría un error de tipo.

```python
numero = int(input("Dame un número: "))

resultado = numero + 10
print("Tu número más 10 es:", resultado)
```

---

## 1.3 · Estructuras de Control y Bucles

Las estructuras de control determinan el flujo de ejecución de un script: qué camino tomar según una condición, o cuántas veces repetir una acción. Son imprescindibles para construir desde simples validaciones hasta escáneres automatizados.

### 1.3.1 · Condicionales: `if / elif / else`

> **Identificación de servicios por puerto:** La cadena `if/elif/else` evalúa múltiples condiciones en orden. Al encontrar la primera que se cumple, ejecuta su bloque y omite el resto. Aquí se usa para mapear números de puerto a nombres de servicio conocidos.

```python
puerto = 4066

if puerto == 22:
    print("Servicio SSH detectado")
elif puerto == 80:
    print("Servicio HTTP detectado")
elif puerto == 443:
    print("Servicio HTTPS detectado")
else:
    print("Servicio NO DETECTADO")
```

### 1.3.2 · Bucle `for`

El bucle `for` recorre una secuencia de elementos (un rango numérico, una lista, un archivo...) y ejecuta el bloque una vez por cada elemento.

> **Iteración con rango numérico:** `range(1, 6)` genera los enteros del 1 al 5 (el límite superior es excluido). Útil para simular intentos de conexión o cualquier acción que deba repetirse un número fijo de veces.

```python
for i in range(1, 6):
    print("Intento numero: ", i)
```

> **Iteración sobre una lista:** El `for` puede recorrer directamente una lista de valores. En este caso itera sobre puertos concretos, lo que sienta las bases de un escáner de puertos.

```python
lista = [53, 55, 57]

for i in lista:
    print("Intento numero: ", i)
```

### 1.3.3 · Bucle `while`

El bucle `while` repite el bloque mientras su condición sea verdadera. A diferencia del `for`, no sabe de antemano cuántas iteraciones realizará: continúa hasta que algo cambie la condición.

> **Control manual de iteraciones:** Se inicializa un contador en 0 y se incrementa manualmente en cada vuelta. El bucle se detiene cuando el contador llega a 5. Este patrón es típico en scripts donde la condición de parada depende de un factor externo (respuesta de red, entrada de usuario, etc.).

```python
intento = 0

while intento < 5:
    print("Intento: ", intento + 1)
    intento += 1
```

### 1.3.4 · Proyecto del bloque: Simulador de ataque de diccionario

> **Ataque de fuerza bruta por diccionario:** Combina `for`, condicional `if` y la sentencia `break` para simular un ataque de diccionario real. El script prueba cada candidato del diccionario contra el hash objetivo. Al encontrar la coincidencia detiene la ejecución con `break`. Si recorre todo el diccionario sin éxito, el bloque `else` asociado al `for` (que solo se ejecuta si no hubo `break`) lo notifica.

```python
password = "123456"

diccionario = ["123", "456", "789", "123456"]

intentos = 0

for i in diccionario:
    intentos += 1
    print("Intento: ", i)
    if i == password:
        print("La contraseña es:", i)
        print("Total de intentos: ", intentos)
        break
else:
    print("Contraseña no encontrada en el diccionario de ataque")
```

---

## 1.4 · Funciones y Modularidad

Las funciones permiten encapsular bloques de código bajo un nombre, evitando repeticiones y haciendo los scripts más organizados, legibles y reutilizables. Se definen con `def` y pueden aceptar parámetros de entrada y devolver un resultado con `return`.

### 1.4.1 · Definición básica con `return` y f-strings

> **Función de saludo parametrizada:** La función recibe un `nombre` como argumento y construye un mensaje usando una f-string (cadena de formato que interpola variables directamente). El resultado se devuelve con `return` y se almacena en una variable al llamarla.

```python
def saludar(nombre):
    mensaje = f"Hola, {nombre}"
    return mensaje

alumno = saludar("Adri")
print(alumno)
```

### 1.4.2 · Parámetros con valores por defecto

> **Función con argumento opcional:** Al definir un parámetro con `b=5`, Python usa ese valor si no se proporciona al llamar a la función. Esto permite crear funciones flexibles que funcionan con configuración mínima pero que admiten personalización.

```python
def sumar(a, b=5):
    return a + b

resultado = sumar(3)
print(resultado)
```

---

## 1.5 · Manejo de Errores y Excepciones

Un script robusto no debe detenerse ante entradas inesperadas o errores en tiempo de ejecución. El bloque `try/except` permite capturar esos errores y gestionarlos de forma controlada. Con `raise` se pueden lanzar errores personalizados cuando se detecta una condición no válida.

### 1.5.1 · Captura básica de excepciones

> **Prevención de crash por división entre cero:** Sin el bloque `try/except`, Python lanzaría un `ZeroDivisionError` y detendría el programa. El bloque `except` captura cualquier excepción que ocurra dentro del `try` y ejecuta el código alternativo en lugar de terminar abruptamente.

```python
try:
    resultado = 10 / 0
except:
    print("Ocurrió un error")
```

### 1.5.2 · Excepciones personalizadas con `raise`

> **Sistema de login con error personalizado:** Si las credenciales no son válidas, `raise ValueError(...)` lanza una excepción con un mensaje descriptivo. El bloque `except ValueError as e` la captura y muestra el mensaje de error de forma controlada. Este patrón es habitual en herramientas que deben comunicar fallos de autenticación sin exponer detalles internos del sistema.

```python
try:
    usuario = input("Usuario: ")
    password = input("Contraseña: ")

    if usuario == "admin" and password == "1234":
        print("Acceso permitido")
    else:
        raise ValueError("Credenciales incorrectas")
except ValueError as e:
    print("Error:", e)
```
