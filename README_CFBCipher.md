# CFBCipher.java - Documentación Técnica

## 🎯 Propósito del Archivo

`CFBCipher.java` es la **clase principal** del proyecto que implementa el algoritmo de cifrado **AES (Advanced Encryption Standard)** en modo **CFB (Cipher Feedback)**. Esta clase proporciona todas las funcionalidades necesarias para cifrar y descifrar datos de forma segura.

## 📋 Estructura de la Clase

### Constantes Definidas

```java
private static final String ALGORITHM = "AES";
private static final String TRANSFORMATION = "AES/CFB8/NoPadding";
private static final int KEY_SIZE = 128;
private static final int IV_SIZE = 16;
```

**Explicación de cada constante:**

- **`ALGORITHM`**: Define que usaremos AES como algoritmo base
- **`TRANSFORMATION`**: Especifica AES con modo CFB8 y sin padding
  - **CFB8**: Significa que se procesan 8 bits de feedback a la vez
  - **NoPadding**: CFB no requiere padding porque procesa datos de cualquier longitud
- **`KEY_SIZE`**: Tamaño de la clave en bits (128 bits = muy seguro)
- **`IV_SIZE`**: Tamaño del vector de inicialización en bytes (16 bytes = 128 bits)

## 🔧 Métodos Principales

### 1. `generateKey()` - Generación de Claves

```java
public static SecretKey generateKey() throws Exception
```

**¿Qué hace este método?**
- Crea una clave secreta AES de forma completamente aleatoria
- Utiliza `KeyGenerator` de Java para garantizar seguridad criptográfica
- La clave generada es de 128 bits (muy segura para la mayoría de aplicaciones)

**¿Por qué es importante?**
- Una clave fuerte es fundamental para la seguridad
- Cada aplicación debe tener su propia clave única
- El generador usa fuentes de entropía del sistema operativo

### 2. `generateIV()` - Generación de Vector de Inicialización

```java
public static byte[] generateIV()
```

**¿Qué hace este método?**
- Crea un vector de inicialización (IV) aleatorio de 16 bytes
- Usa `SecureRandom` para garantizar aleatoriedad criptográfica
- Cada mensaje debe usar un IV diferente

**¿Por qué necesitamos un IV?**
- **Previene patrones**: El mismo texto con la misma clave produce diferentes resultados
- **Evita ataques**: Sin IV, un atacante podría detectar mensajes repetidos
- **Seguridad**: Es la diferencia entre cifrado seguro y vulnerable

### 3. `encrypt()` - Cifrado de Datos

```java
public static byte[] encrypt(String plaintext, SecretKey key, byte[] iv) throws Exception
```

**Proceso paso a paso:**

1. **Crear el cifrador**: `Cipher.getInstance(TRANSFORMATION)`
2. **Configurar el IV**: `IvParameterSpec(iv)`
3. **Inicializar en modo cifrado**: `cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec)`
4. **Procesar los datos**: `cipher.doFinal(plaintext.getBytes("UTF-8"))`

**¿Cómo funciona internamente?**
- El IV se usa como primer bloque de entrada al cifrador
- Cada byte del texto plano se combina (XOR) con la salida cifrada del registro de desplazamiento
- El resultado se convierte en el siguiente bloque del registro de desplazamiento
- Este proceso continúa hasta procesar todo el texto

### 4. `decrypt()` - Descifrado de Datos

```java
public static String decrypt(byte[] ciphertext, SecretKey key, byte[] iv) throws Exception
```

**Proceso paso a paso:**

1. **Crear el cifrador**: Igual configuración que para cifrar
2. **Inicializar en modo descifrado**: `cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec)`
3. **Procesar los datos cifrados**: `cipher.doFinal(ciphertext)`
4. **Convertir a texto**: `new String(decryptedBytes, "UTF-8")`

**¿Por qué usa la misma configuración?**
- En CFB, tanto cifrado como descifrado usan la operación de cifrado del algoritmo base
- La diferencia está en cómo se aplica el XOR
- Esto es una característica especial del modo CFB

## 🔄 Métodos de Conversión Base64

### ¿Para qué sirven estos métodos?

Los métodos de conversión Base64 son esenciales porque:

- **Almacenamiento seguro**: Los datos binarios no se pueden guardar directamente en texto
- **Transmisión confiable**: Base64 es seguro para enviar por email, web, etc.
- **Compatibilidad**: Funciona en todos los sistemas y plataformas

### Métodos incluidos:

- **`keyToBase64()`**: Convierte una clave a texto Base64
- **`keyFromBase64()`**: Reconstruye una clave desde texto Base64
- **`bytesToBase64()`**: Convierte datos binarios a texto Base64
- **`bytesFromBase64()`**: Convierte texto Base64 a datos binarios

## 🛡️ Características de Seguridad

### Fortalezas de la implementación:

1. **Algoritmo robusto**: AES es el estándar mundial para cifrado
2. **Modo seguro**: CFB elimina patrones y permite streaming
3. **Generación segura**: Usa fuentes criptográficas para claves e IVs
4. **Codificación UTF-8**: Maneja correctamente caracteres especiales
5. **Manejo de excepciones**: Previene fallos de seguridad

### Consideraciones importantes:

1. **IV único**: Cada mensaje DEBE usar un IV diferente
2. **Protección de claves**: Las claves deben almacenarse de forma segura
3. **Integridad**: CFB solo garantiza confidencialidad, no integridad
4. **Gestión de errores**: Las excepciones pueden revelar información

## 📊 Ejemplo de Uso Básico

```java
// 1. Generar clave e IV
SecretKey key = CFBCipher.generateKey();
byte[] iv = CFBCipher.generateIV();

// 2. Cifrar un mensaje
String mensaje = "Información confidencial";
byte[] cifrado = CFBCipher.encrypt(mensaje, key, iv);

// 3. Descifrar el mensaje
String descifrado = CFBCipher.decrypt(cifrado, key, iv);

// 4. Verificar que funcionó
System.out.println("Original: " + mensaje);
System.out.println("Descifrado: " + descifrado);
System.out.println("¿Iguales? " + mensaje.equals(descifrado));
```

## 🔍 Validación Interna

### ¿Cómo valida que el cifrado funciona?

1. **Excepciones controladas**: Si algo falla, se lanza una excepción específica
2. **Verificación de parámetros**: Los métodos validan que los inputs sean válidos
3. **Codificación consistente**: Usa UTF-8 en ambas direcciones
4. **Reversibilidad**: El proceso de cifrado/descifrado es completamente reversible

### Puntos de validación automática:

- **Tamaño del IV**: Debe ser exactamente 16 bytes
- **Clave válida**: Debe ser una clave AES válida
- **Datos de entrada**: Deben estar en formato correcto
- **Configuración del cifrador**: Se valida automáticamente por Java

## 🎓 Conceptos Criptográficos Aplicados

### 1. **Confidencialidad**
- Los datos se vuelven ilegibles sin la clave correcta
- Incluso con acceso al código, sin la clave no se puede descifrar

### 2. **Aleatoriedad**
- IVs generados con fuentes criptográficas
- Cada ejecución produce resultados diferentes

### 3. **Reversibilidad**
- El proceso de cifrado puede deshacerse completamente
- No hay pérdida de información en el proceso

### 4. **Determinismo controlado**
- Con la misma clave e IV, el resultado es siempre el mismo
- Pero cada mensaje debe usar un IV diferente

## 💡 Notas Técnicas Adicionales

### ¿Por qué CFB8 en lugar de CFB128?
- **Flexibilidad**: CFB8 procesa byte por byte, ideal para streaming
- **Eficiencia**: Menor latencia para datos en tiempo real
- **Compatibilidad**: Funciona bien con protocolos de comunicación

### ¿Por qué UTF-8?
- **Universalidad**: Maneja todos los caracteres Unicode
- **Compatibilidad**: Estándar web internacional
- **Consistencia**: Misma codificación en cifrado y descifrado

### Manejo de memoria:
- Los arrays de bytes se limpian automáticamente por el garbage collector
- Para máxima seguridad, se podrían limpiar manualmente con `Arrays.fill()`

---

**Este archivo CFBCipher.java es el corazón del proyecto CFB y proporciona todas las herramientas necesarias para implementar cifrado simétrico seguro en cualquier aplicación Java.**