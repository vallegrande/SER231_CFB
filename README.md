# Proyecto CFB (Cipher Feedback) - Cifrado AES

## 📚 Documentación del Proyecto

### 📄 Archivos de Documentación Disponibles:

- **[README.md](README.md)** - Documentación principal del proyecto
- **[README_CFBCipher.md](README_CFBCipher.md)** - Explicación detallada de la clase CFBCipher.java
- **[README_CFBDemo.md](README_CFBDemo.md)** - Explicación detallada de la clase CFBDemo.java  
- **[README_Technical.md](README_Technical.md)** - Análisis técnico y validación del proyecto CFB

### 🎯 Archivos del Proyecto:

- **[CFBCipher.java](CFBCipher.java)** - Clase principal de cifrado AES-CFB
- **[CFBDemo.java](CFBDemo.java)** - Clase de demostración con ejemplos prácticos

## 📋 Descripción del Proyecto

Este proyecto implementa un sistema de cifrado simétrico utilizando el algoritmo **AES (Advanced Encryption Standard)** en modo **CFB (Cipher Feedback)**. El proyecto está desarrollado en Java y proporciona una implementación completa con ejemplos de uso para cifrado y descifrado de datos.

## 🔧 Componentes del Proyecto

### Archivos Principales:
- **[`CFBCipher.java`](CFBCipher.java)**: Clase principal que implementa las funciones de cifrado y descifrado AES-CFB
- **[`CFBDemo.java`](CFBDemo.java)**: Clase de demostración con ejemplos prácticos de uso
- **[`README.md`](README.md)**: Este archivo con documentación completa

### Documentación Detallada:
- **[`README_CFBCipher.md`](README_CFBCipher.md)**: Explicación detallada de la clase CFBCipher.java
- **[`README_CFBDemo.md`](README_CFBDemo.md)**: Explicación detallada de la clase CFBDemo.java
- **[`README_Technical.md`](README_Technical.md)**: Análisis técnico y validación del proyecto CFB

## 🚀 Cómo Ejecutar el Proyecto

### Requisitos Previos:
- **Java JDK 8 o superior**
- **Acceso a terminal/línea de comandos**

### Pasos para Ejecutar:

1. **Clonar o descargar el proyecto**
   ```bash
   # Si está en un repositorio
   git clone https://github.com/vallegrande/SER231_CFB.git
   cd SER231_CFB
   ```

2. **Compilar los archivos Java**
   ```bash
   javac CFBCipher.java
   javac CFBDemo.java
   ```

3. **Ejecutar la demostración**
   ```bash
   java CFBDemo
   ```

### Ejecución en Windows:
```cmd
# Abrir PowerShell o CMD en la carpeta del proyecto
javac CFBCipher.java
javac CFBDemo.java
java CFBDemo
```

### Ejecución en Linux/macOS:
```bash
# Abrir terminal en la carpeta del proyecto
javac CFBCipher.java
javac CFBDemo.java
java CFBDemo
```

## 🔐 Cómo Funciona el Proyecto

### Algoritmo AES-CFB

El **modo CFB (Cipher Feedback)** convierte el cifrador de bloques AES en un cifrador de flujo, lo que permite:

1. **Procesamiento de datos de cualquier longitud** sin necesidad de padding
2. **Cifrado en tiempo real** (no necesita esperar bloques completos)
3. **Propagación de errores limitada** (un error en un bit afecta solo a ese bloque y al siguiente)

### Flujo de Funcionamiento:

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Texto     │    │    Clave    │    │     IV      │
│   Plano     │    │   Secreta   │    │ (16 bytes)  │
└─────────────┘    └─────────────┘    └─────────────┘
       │                   │                   │
       │                   └───────┬───────────┘
       │                           │
       │            ┌─────────────────────────────┐
       │            │      Cifrador AES-CFB       │
       │            │                             │
       └────────────│→ Cifrado/Descifrado ←──────│
                    └─────────────────────────────┘
                               │
                    ┌─────────────────────┐
                    │   Texto Cifrado     │
                    │   (mismo tamaño)    │
                    └─────────────────────┘
```

### Características Implementadas:

1. **Generación de Claves**: Creación automática de claves AES de 128 bits
2. **Vector de Inicialización (IV)**: Generación aleatoria de IVs únicos
3. **Cifrado CFB8**: Utiliza 8 bits de feedback para mayor flexibilidad
4. **Conversión Base64**: Para almacenamiento y transmisión segura
5. **Manejo de Errores**: Gestión robusta de excepciones

## ✅ Ventajas del Modo CFB

### 🟢 Principales Ventajas:

1. **No Requiere Padding**
   - Procesa datos de cualquier longitud
   - El texto cifrado tiene el mismo tamaño que el original

2. **Cifrado en Tiempo Real**
   - No necesita esperar bloques completos
   - Ideal para streaming de datos

3. **Propagación de Errores Limitada**
   - Un error afecta solo al bloque actual y al siguiente
   - Recuperación automática después de 2 bloques

4. **Seguridad Robusta**
   - Utiliza AES como base (estándar mundial)
   - IVs únicos previenen ataques de repetición

5. **Flexibilidad**
   - Tamaño de feedback configurable (CFB8, CFB64, CFB128)
   - Compatible con diferentes tamaños de datos

6. **Eficiencia**
   - Solo requiere cifrado (no descifrado) en ambas direcciones
   - Menor uso de recursos que algunos modos

## ❌ Desventajas del Modo CFB

### 🔴 Limitaciones:

1. **No Paralelizable para Cifrado**
   - El cifrado debe ser secuencial
   - No puede aprovecharse el procesamiento en paralelo

2. **Sensible a Errores de Sincronización**
   - Pérdida de sincronización puede corromper datos
   - Requiere transmisión confiable

3. **Dependencia del IV**
   - IV debe ser único para cada mensaje
   - Gestión adicional del IV

4. **Propagación de Errores**
   - Aunque limitada, aún existe propagación
   - Un bit corrupto afecta a múltiples bits

5. **Complejidad de Implementación**
   - Más complejo que modos como ECB
   - Requiere cuidado en la gestión del estado

## 🛡️ Consideraciones de Seguridad

### ⚠️ Importantes:

1. **IV Único**: Cada mensaje debe usar un IV diferente
2. **Protección de Claves**: Las claves deben almacenarse de forma segura
3. **Integridad**: CFB solo proporciona confidencialidad, no integridad
4. **Gestión de IVs**: Los IVs pueden ser públicos pero deben ser únicos

### 🔒 Mejores Prácticas:

```java
// ✅ CORRECTO: IV único para cada operación
byte[] iv1 = CFBCipher.generateIV();
byte[] encrypted1 = CFBCipher.encrypt("mensaje1", key, iv1);

byte[] iv2 = CFBCipher.generateIV();
byte[] encrypted2 = CFBCipher.encrypt("mensaje2", key, iv2);

// ❌ INCORRECTO: Reutilizar el mismo IV
byte[] iv = CFBCipher.generateIV();
byte[] encrypted1 = CFBCipher.encrypt("mensaje1", key, iv);
byte[] encrypted2 = CFBCipher.encrypt("mensaje2", key, iv); // ¡PELIGROSO!
```

## 📖 Ejemplos de Uso

### Cifrado Básico:
```java
// Generar clave e IV
SecretKey key = CFBCipher.generateKey();
byte[] iv = CFBCipher.generateIV();

// Cifrar
String mensaje = "Hola mundo secreto";
byte[] cifrado = CFBCipher.encrypt(mensaje, key, iv);

// Descifrar
String descifrado = CFBCipher.decrypt(cifrado, key, iv);
```

### Almacenamiento en Base64:
```java
// Convertir para almacenamiento
String keyB64 = CFBCipher.keyToBase64(key);
String ivB64 = CFBCipher.bytesToBase64(iv);
String cifradoB64 = CFBCipher.bytesToBase64(cifrado);

// Recuperar desde almacenamiento
SecretKey keyRecuperada = CFBCipher.keyFromBase64(keyB64);
byte[] ivRecuperado = CFBCipher.bytesFromBase64(ivB64);
byte[] cifradoRecuperado = CFBCipher.bytesFromBase64(cifradoB64);
```

## 🔬 Casos de Uso Recomendados

### ✅ Ideal para:
- **Transmisión de datos en tiempo real**
- **Cifrado de streams de datos**
- **Protección de comunicaciones**
- **Sistemas donde el tamaño del mensaje es importante**
- **Aplicaciones que requieren recuperación rápida de errores**

### ❌ No recomendado para:
- **Sistemas que requieren procesamiento paralelo masivo**
- **Aplicaciones con requisitos de integridad estrictos** (usar con HMAC)
- **Entornos con alta pérdida de paquetes**
- **Sistemas donde la simplicidad es prioritaria**

## 🆚 Comparación con Otros Modos

| Característica | CFB | CBC | ECB | GCM |
|---|---|---|---|---|
| Padding requerido | No | Sí | Sí | No |
| Paralelización | Parcial | Parcial | Sí | Sí |
| Propagación errores | Limitada | Total | Ninguna | Detección |
| Integridad | No | No | No | Sí |
| Complejidad | Media | Media | Baja | Alta |
| Seguridad | Alta | Alta | Baja | Muy Alta |

## 📝 Comentarios del Código

El código está extensamente comentado para facilitar el aprendizaje:

- **Comentarios de clase**: Explican el propósito y funcionamiento general
- **Comentarios de método**: Describen parámetros, retorno y funcionamiento
- **Comentarios inline**: Explican pasos específicos y decisiones de diseño
- **Ejemplos en comentarios**: Demuestran uso correcto e incorrecto

## 🎯 Objetivos de Aprendizaje

Este proyecto ayuda a entender:

1. **Criptografía simétrica** y sus aplicaciones
2. **Modos de operación** de cifradores de bloque
3. **Gestión de claves** y vectores de inicialización
4. **Implementación práctica** de algoritmos criptográficos
5. **Mejores prácticas** de seguridad en programación
6. **Manejo de excepciones** en operaciones criptográficas

## 🤝 Contribuciones

Para contribuir al proyecto:

1. Fork el repositorio
2. Crea una rama para tu funcionalidad
3. Implementa mejoras con documentación
4. Envía un pull request

## 📄 Licencia

Este proyecto es para fines educativos en el curso SER231.

---

**Desarrollado para SER231 - Sistemas de Seguridad**  
*Proyecto educativo sobre cifrado simétrico AES-CFB*