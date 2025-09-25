# CFBDemo.java - Documentación de Demostración

## 🎯 Propósito del Archivo

`CFBDemo.java` es la **clase de demostración** que muestra cómo usar la implementación de cifrado AES-CFB de manera práctica. Este archivo contiene ejemplos completos y casos de uso reales para entender el funcionamiento del sistema de cifrado.

## 🏗️ Estructura de la Clase

### Método Principal

```java
public static void main(String[] args)
```

**Función**: Ejecuta cuatro demostraciones diferentes en secuencia para mostrar todas las capacidades del sistema de cifrado.

## 🎬 Las Cuatro Demostraciones

### 1. **Demo 1: Cifrado y Descifrado Básico**

```java
private static void demonstrateBasicEncryption() throws Exception
```

**¿Qué hace esta demostración?**

1. **Paso 1**: Genera una clave secreta aleatoria
2. **Paso 2**: Genera un vector de inicialización (IV) aleatorio  
3. **Paso 3**: Cifra un mensaje de ejemplo
4. **Paso 4**: Descifra el mensaje cifrado
5. **Paso 5**: Verifica que el mensaje original y descifrado son iguales

**Código clave explicado:**

```java
// Texto a cifrar
String originalText = "¡Hola! Este es un mensaje secreto que será cifrado con AES-CFB.";

// Generación de elementos criptográficos
SecretKey secretKey = CFBCipher.generateKey();
byte[] iv = CFBCipher.generateIV();

// Proceso de cifrado
byte[] encryptedData = CFBCipher.encrypt(originalText, secretKey, iv);

// Proceso de descifrado
String decryptedText = CFBCipher.decrypt(encryptedData, secretKey, iv);

// Validación
boolean isEqual = originalText.equals(decryptedText);
```

**¿Qué aprende el usuario?**
- Flujo básico de cifrado/descifrado
- Cómo generar claves e IVs
- Verificación de que el proceso es reversible
- Visualización de datos cifrados en hexadecimal

### 2. **Demo 2: Múltiples Textos con la Misma Clave**

```java
private static void demonstrateMultipleTexts() throws Exception
```

**¿Qué demuestra?**

Esta demostración es **crucial** porque enseña una práctica de seguridad fundamental:

- **Una clave puede reutilizarse** para múltiples mensajes
- **Cada mensaje DEBE usar un IV diferente**
- **Diferentes IVs producen diferentes resultados** aunque el mensaje y clave sean iguales

**Mensajes de ejemplo procesados:**

```java
String[] textsToEncrypt = {
    "Mensaje 1: Información confidencial",
    "Mensaje 2: Datos financieros secretos", 
    "Mensaje 3: Contraseña: admin123",
    "Mensaje 4: [Cifrado] Emojis tambien funcionan [Clave]"
};
```

**Proceso para cada mensaje:**

```java
// Genera un IV ÚNICO para cada mensaje
byte[] iv = CFBCipher.generateIV();

// Cifra con la misma clave pero IV diferente
byte[] encrypted = CFBCipher.encrypt(textsToEncrypt[i], sharedKey, iv);

// Descifra para verificar integridad
String decrypted = CFBCipher.decrypt(encrypted, sharedKey, iv);
```

**¿Por qué es importante esta demo?**
- Muestra el uso práctico real (una aplicación, múltiples mensajes)
- Demuestra la importancia de IVs únicos
- Enseña que cada operación de cifrado debe generar un nuevo IV

### 3. **Demo 3: Almacenamiento en Base64**

```java
private static void demonstrateBase64Storage() throws Exception
```

**¿Qué problema resuelve?**

Los datos binarios (claves, IVs, datos cifrados) no se pueden almacenar directamente como texto. Base64 convierte datos binarios en texto seguro.

**Proceso completo de almacenamiento:**

```java
// 1. Cifrar el mensaje
byte[] encrypted = CFBCipher.encrypt(message, key, iv);

// 2. Convertir TODOS los datos binarios a Base64
String keyBase64 = CFBCipher.keyToBase64(key);
String ivBase64 = CFBCipher.bytesToBase64(iv);
String encryptedBase64 = CFBCipher.bytesToBase64(encrypted);

// 3. Simular almacenamiento (estos strings se pueden guardar en archivos/BD)
System.out.println("Clave (Base64): " + keyBase64);
System.out.println("IV (Base64): " + ivBase64);
System.out.println("Datos cifrados (Base64): " + encryptedBase64);
```

**Proceso de recuperación:**

```java
// 4. Recuperar desde almacenamiento (convertir de Base64 a binario)
SecretKey recoveredKey = CFBCipher.keyFromBase64(keyBase64);
byte[] recoveredIV = CFBCipher.bytesFromBase64(ivBase64);
byte[] recoveredEncrypted = CFBCipher.bytesFromBase64(encryptedBase64);

// 5. Descifrar con los datos recuperados
String recoveredMessage = CFBCipher.decrypt(recoveredEncrypted, recoveredKey, recoveredIV);
```

**¿Cuándo usar esto?**
- Guardar datos cifrados en archivos de texto
- Enviar datos cifrados por email
- Almacenar en bases de datos
- Transmitir por protocolos de texto (HTTP, etc.)

### 4. **Demo 4: Importancia del Vector de Inicialización**

```java
private static void demonstrateDifferentIVs() throws Exception
```

**¿Qué demuestra esta demo crítica?**

Esta es quizás la demostración **más importante educativamente** porque muestra por qué los IVs son fundamentales para la seguridad.

**Experimento realizado:**

```java
String message = "Mismo mensaje, diferentes resultados";
SecretKey key = CFBCipher.generateKey(); // UNA sola clave

// Cifrar el MISMO mensaje 3 veces con IVs DIFERENTES
for (int i = 1; i <= 3; i++) {
    byte[] iv = CFBCipher.generateIV(); // IV diferente cada vez
    byte[] encrypted = CFBCipher.encrypt(message, key, iv);
    
    // Mostrar resultados
    System.out.println("IV (hex): " + bytesToHex(iv));
    System.out.println("Cifrado (hex): " + bytesToHex(encrypted));
}
```

**Resultado observado:**
- **Mismo mensaje** + **Misma clave** + **IV diferente** = **Texto cifrado completamente diferente**

**¿Por qué es esto crucial?**
- **Sin IV**: Un atacante podría detectar mensajes repetidos
- **Con IV único**: Cada cifrado es único, incluso para el mismo mensaje
- **Seguridad**: Previene análisis de patrones y ataques de repetición

## 🔧 Métodos Auxiliares

### `bytesToHex()` - Visualización de Datos Binarios

```java
private static String bytesToHex(byte[] bytes)
```

**¿Para qué sirve?**
- Convierte datos binarios a representación hexadecimal legible
- Permite ver exactamente qué bytes se están generando
- Útil para debugging y verificación

**¿Cómo funciona?**

```java
StringBuilder result = new StringBuilder();
for (byte b : bytes) {
    result.append(String.format("%02X", b)); // Convierte cada byte a hex de 2 dígitos
}
return result.toString();
```

## 🎓 Lecciones Pedagógicas de Cada Demo

### Demo 1 enseña:
- **Flujo básico** de cifrado simétrico
- **Reversibilidad** del proceso
- **Validación** de resultados
- **Visualización** de datos cifrados

### Demo 2 enseña:
- **Reutilización segura** de claves
- **Generación de IVs únicos**
- **Procesamiento de múltiples mensajes**
- **Buenas prácticas** de seguridad

### Demo 3 enseña:
- **Almacenamiento práctico** de datos cifrados
- **Conversión Base64** para compatibilidad
- **Ciclo completo** de cifrado-almacenamiento-recuperación-descifrado
- **Aplicabilidad real** del sistema

### Demo 4 enseña:
- **Importancia crítica** de los IVs
- **Prevención de patrones** en cifrado
- **Seguridad criptográfica** fundamental
- **Diferencia entre seguro e inseguro**

## 🔍 Técnicas de Validación Utilizadas

### 1. **Validación por Comparación**
```java
boolean isEqual = originalText.equals(decryptedText);
```
- Verifica que el descifrado restaura exactamente el texto original
- Falla si hay cualquier error en el proceso

### 2. **Validación Visual**
```java
System.out.println("Datos cifrados (hex): " + bytesToHex(encryptedData));
```
- Permite ver que los datos realmente están cifrados
- Muestra que son diferentes del texto original

### 3. **Validación de Unicidad**
```java
// Mostrar que diferentes IVs producen diferentes resultados
for (int i = 1; i <= 3; i++) { ... }
```
- Demuestra que el sistema no produce patrones predecibles
- Verifica la aleatoriedad del proceso

### 4. **Validación de Integridad del Proceso**
```java
// Ciclo completo: cifrar -> Base64 -> almacenar -> recuperar -> Base64 -> descifrar
```
- Prueba que todo el flujo de almacenamiento funciona
- Verifica que no hay pérdida de datos en las conversiones

## 🚀 Cómo Usar las Demostraciones

### Para Aprender:
1. **Ejecutar primero**: `java CFBDemo`
2. **Leer la salida**: Observar cada paso del proceso
3. **Revisar el código**: Entender cómo se implementa cada demo
4. **Experimentar**: Modificar mensajes y observar resultados

### Para Desarrollo:
1. **Copiar patrones**: Usar las demos como plantillas para código propio
2. **Adaptar ejemplos**: Modificar para casos de uso específicos
3. **Validar implementaciones**: Usar las mismas técnicas de verificación

## 💡 Conceptos Clave Demostrados

### Seguridad Criptográfica:
- **Confidencialidad**: Los mensajes se vuelven ilegibles
- **Aleatoriedad**: Cada cifrado es único
- **Reversibilidad**: El proceso puede deshacerse completamente

### Buenas Prácticas:
- **IV único por mensaje**: Fundamental para seguridad
- **Manejo de errores**: Verificación en cada paso  
- **Almacenamiento seguro**: Conversión Base64 apropiada

### Aplicabilidad Real:
- **Múltiples mensajes**: Flujo de trabajo real
- **Almacenamiento**: Persistencia práctica de datos
- **Verificación**: Validación de integridad

---

**Este archivo CFBDemo.java es esencial para entender no solo CÓMO funciona el cifrado CFB, sino también CUÁNDO y POR QUÉ usarlo de manera segura en aplicaciones reales.**