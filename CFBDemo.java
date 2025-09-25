/**
 * CFBDemo - Clase de demostración para el cifrado AES-CFB
 * 
 * Esta clase contiene ejemplos prácticos de cómo utilizar la clase CFBCipher
 * para cifrar y descifrar datos utilizando el algoritmo AES en modo CFB.
 * 
 * Incluye ejemplos de:
 * - Generación de claves y vectores de inicialización
 * - Cifrado de texto plano
 * - Descifrado de texto cifrado
 * - Manejo de errores
 * - Conversión a Base64 para almacenamiento
 * 
 * @author SER231 CFB Project
 * @version 1.0
 */
public class CFBDemo {
    
    /**
     * Método principal que ejecuta las demostraciones
     */
    public static void main(String[] args) {
        System.out.println("=== DEMO: Cifrado AES-CFB ===\n");
        
        try {
            // === DEMO 1: Cifrado y descifrado básico ===
            demonstrateBasicEncryption();
            
            System.out.println("\n" + "=".repeat(50) + "\n");
            
            // === DEMO 2: Múltiples textos con la misma clave ===
            demonstrateMultipleTexts();
            
            System.out.println("\n" + "=".repeat(50) + "\n");
            
            // === DEMO 3: Almacenamiento en Base64 ===
            demonstrateBase64Storage();
            
            System.out.println("\n" + "=".repeat(50) + "\n");
            
            // === DEMO 4: Diferencias con diferentes IVs ===
            demonstrateDifferentIVs();
            
        } catch (Exception e) {
            System.err.println("Error durante la demostración: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * Demuestra el cifrado y descifrado básico
     */
    private static void demonstrateBasicEncryption() throws Exception {
        System.out.println("--- DEMO 1: Cifrado y Descifrado Básico ---");
        
        // Texto original a cifrar
        String originalText = "¡Hola! Este es un mensaje secreto que será cifrado con AES-CFB.";
        System.out.println("Texto original: " + originalText);
        
        // Paso 1: Generar una clave secreta
        System.out.println("\n1. Generando clave secreta...");
        javax.crypto.SecretKey secretKey = CFBCipher.generateKey();
        System.out.println("   Clave generada exitosamente");
        
        // Paso 2: Generar un vector de inicialización (IV)
        System.out.println("\n2. Generando vector de inicialización (IV)...");
        byte[] iv = CFBCipher.generateIV();
        System.out.println("   IV generado exitosamente (16 bytes)");
        
        // Paso 3: Cifrar el texto
        System.out.println("\n3. Cifrando el texto...");
        byte[] encryptedData = CFBCipher.encrypt(originalText, secretKey, iv);
        System.out.println("   Texto cifrado exitosamente");
        System.out.println("   Tamaño del texto cifrado: " + encryptedData.length + " bytes");
        
        // Mostrar datos cifrados en hexadecimal para visualización
        System.out.println("   Datos cifrados (hex): " + bytesToHex(encryptedData));
        
        // Paso 4: Descifrar el texto
        System.out.println("\n4. Descifrando el texto...");
        String decryptedText = CFBCipher.decrypt(encryptedData, secretKey, iv);
        System.out.println("   Texto descifrado: " + decryptedText);
        
        // Paso 5: Verificar que el texto descifrado es igual al original
        boolean isEqual = originalText.equals(decryptedText);
        System.out.println("\n5. Verificación:");
        System.out.println("   ¿Texto original == Texto descifrado? " + isEqual);
        
        if (isEqual) {
            System.out.println("   [V] Cifrado y descifrado exitoso!");
        } else {
            System.out.println("   [X] Error: Los textos no coinciden");
        }
    }
    
    /**
     * Demuestra el cifrado de múltiples textos con la misma clave
     */
    private static void demonstrateMultipleTexts() throws Exception {
        System.out.println("--- DEMO 2: Múltiples Textos con la Misma Clave ---");
        
        // Generar una clave que se reutilizará
        javax.crypto.SecretKey sharedKey = CFBCipher.generateKey();
        System.out.println("Clave compartida generada para múltiples operaciones\n");
        
        // Array de textos para cifrar
        String[] textsToEncrypt = {
            "Mensaje 1: Información confidencial",
            "Mensaje 2: Datos financieros secretos",
            "Mensaje 3: Contraseña: admin123",
            "Mensaje 4: [Cifrado] Emojis tambien funcionan [Clave]"
        };
        
        // Cifrar cada texto con un IV diferente
        for (int i = 0; i < textsToEncrypt.length; i++) {
            System.out.println("Procesando mensaje " + (i + 1) + ":");
            System.out.println("  Original: " + textsToEncrypt[i]);
            
            // Generar un IV único para cada mensaje
            byte[] iv = CFBCipher.generateIV();
            
            // Cifrar
            byte[] encrypted = CFBCipher.encrypt(textsToEncrypt[i], sharedKey, iv);
            
            // Descifrar para verificar
            String decrypted = CFBCipher.decrypt(encrypted, sharedKey, iv);
            
            System.out.println("  Cifrado: " + bytesToHex(encrypted).substring(0, 32) + "...");
            System.out.println("  Descifrado: " + decrypted);
            System.out.println("  [V] Verificado\n");
        }
    }
    
    /**
     * Demuestra cómo almacenar claves e IVs en formato Base64
     */
    private static void demonstrateBase64Storage() throws Exception {
        System.out.println("--- DEMO 3: Almacenamiento en Base64 ---");
        
        String message = "Este mensaje será almacenado de forma segura";
        System.out.println("Mensaje original: " + message);
        
        // Generar clave e IV
        javax.crypto.SecretKey key = CFBCipher.generateKey();
        byte[] iv = CFBCipher.generateIV();
        
        // Cifrar
        byte[] encrypted = CFBCipher.encrypt(message, key, iv);
        
        // Convertir todo a Base64 para almacenamiento
        String keyBase64 = CFBCipher.keyToBase64(key);
        String ivBase64 = CFBCipher.bytesToBase64(iv);
        String encryptedBase64 = CFBCipher.bytesToBase64(encrypted);
        
        System.out.println("\n--- Datos para almacenar ---");
        System.out.println("Clave (Base64): " + keyBase64);
        System.out.println("IV (Base64): " + ivBase64);
        System.out.println("Datos cifrados (Base64): " + encryptedBase64);
        
        // Simular recuperación desde almacenamiento
        System.out.println("\n--- Simulando recuperación desde almacenamiento ---");
        
        // Reconstruir desde Base64
        javax.crypto.SecretKey recoveredKey = CFBCipher.keyFromBase64(keyBase64);
        byte[] recoveredIV = CFBCipher.bytesFromBase64(ivBase64);
        byte[] recoveredEncrypted = CFBCipher.bytesFromBase64(encryptedBase64);
        
        // Descifrar con los datos recuperados
        String recoveredMessage = CFBCipher.decrypt(recoveredEncrypted, recoveredKey, recoveredIV);
        
        System.out.println("Mensaje recuperado: " + recoveredMessage);
        System.out.println("¿Coincide con el original? " + message.equals(recoveredMessage));
    }
    
    /**
     * Demuestra cómo diferentes IVs producen diferentes textos cifrados
     */
    private static void demonstrateDifferentIVs() throws Exception {
        System.out.println("--- DEMO 4: Importancia del Vector de Inicialización ---");
        
        String message = "Mismo mensaje, diferentes resultados";
        javax.crypto.SecretKey key = CFBCipher.generateKey();
        
        System.out.println("Mensaje: " + message);
        System.out.println("Misma clave, diferentes IVs:\n");
        
        // Cifrar el mismo mensaje 3 veces con diferentes IVs
        for (int i = 1; i <= 3; i++) {
            byte[] iv = CFBCipher.generateIV();
            byte[] encrypted = CFBCipher.encrypt(message, key, iv);
            
            System.out.println("Intento " + i + ":");
            System.out.println("  IV (hex): " + bytesToHex(iv));
            System.out.println("  Cifrado (hex): " + bytesToHex(encrypted));
            
            // Verificar que se puede descifrar correctamente
            String decrypted = CFBCipher.decrypt(encrypted, key, iv);
            System.out.println("  Descifrado: " + decrypted);
            System.out.println("  [V] Correcto\n");
        }
        
        System.out.println("[!] Observacion: Aunque el mensaje y la clave son iguales,");
        System.out.println("   los textos cifrados son completamente diferentes debido");
        System.out.println("   a los diferentes vectores de inicializacion (IVs).");
    }
    
    /**
     * Convierte un array de bytes a representación hexadecimal
     * 
     * @param bytes Array de bytes a convertir
     * @return String representación hexadecimal
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02X", b));
        }
        return result.toString();
    }
}