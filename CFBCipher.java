import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * CFBCipher - Implementación de cifrado AES en modo CFB (Cipher Feedback)
 * 
 * Esta clase proporciona métodos para cifrar y descifrar datos utilizando
 * el algoritmo AES (Advanced Encryption Standard) en modo CFB.
 * 
 * El modo CFB convierte un cifrador de bloque en un cifrador de flujo,
 * permitiendo procesar datos de cualquier longitud sin necesidad de padding.
 * 
 * @author SER231 CFB Project
 * @version 1.0
 */
public class CFBCipher {
    
    // Algoritmo de cifrado utilizado
    private static final String ALGORITHM = "AES";
    
    // Transformación completa: Algoritmo/Modo/Padding
    // CFB8 significa que se utiliza 8 bits de feedback
    private static final String TRANSFORMATION = "AES/CFB8/NoPadding";
    
    // Tamaño de la clave en bits (128, 192, o 256)
    private static final int KEY_SIZE = 128;
    
    // Tamaño del vector de inicialización en bytes (16 bytes = 128 bits para AES)
    private static final int IV_SIZE = 16;
    
    /**
     * Genera una clave secreta AES de forma aleatoria
     * 
     * @return SecretKey - Clave secreta generada
     * @throws Exception si ocurre un error durante la generación
     */
    public static SecretKey generateKey() throws Exception {
        // Crear un generador de claves para AES
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        
        // Configurar el tamaño de la clave
        keyGenerator.init(KEY_SIZE);
        
        // Generar y retornar la clave
        return keyGenerator.generateKey();
    }
    
    /**
     * Genera un vector de inicialización (IV) aleatorio
     * 
     * El IV es crucial en CFB ya que asegura que el mismo texto plano
     * produzca diferentes textos cifrados en cada ejecución.
     * 
     * @return byte[] - Vector de inicialización generado
     */
    public static byte[] generateIV() {
        // Crear un generador de números aleatorios criptográficamente seguro
        SecureRandom secureRandom = new SecureRandom();
        
        // Crear el array para el IV
        byte[] iv = new byte[IV_SIZE];
        
        // Llenar el array con bytes aleatorios
        secureRandom.nextBytes(iv);
        
        return iv;
    }
    
    /**
     * Cifra un texto plano utilizando AES-CFB
     * 
     * @param plaintext Texto a cifrar
     * @param key Clave secreta para el cifrado
     * @param iv Vector de inicialización
     * @return byte[] - Datos cifrados
     * @throws Exception si ocurre un error durante el cifrado
     */
    public static byte[] encrypt(String plaintext, SecretKey key, byte[] iv) throws Exception {
        // Crear instancia del cifrador con la transformación especificada
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        
        // Crear el parámetro del IV
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        
        // Inicializar el cifrador en modo de cifrado con la clave e IV
        cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
        
        // Realizar el cifrado y retornar los bytes cifrados
        return cipher.doFinal(plaintext.getBytes("UTF-8"));
    }
    
    /**
     * Descifra datos cifrados utilizando AES-CFB
     * 
     * @param ciphertext Datos cifrados a descifrar
     * @param key Clave secreta para el descifrado
     * @param iv Vector de inicialización utilizado en el cifrado
     * @return String - Texto plano descifrado
     * @throws Exception si ocurre un error durante el descifrado
     */
    public static String decrypt(byte[] ciphertext, SecretKey key, byte[] iv) throws Exception {
        // Crear instancia del cifrador con la transformación especificada
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        
        // Crear el parámetro del IV
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        
        // Inicializar el cifrador en modo de descifrado con la clave e IV
        cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
        
        // Realizar el descifrado y convertir a String
        byte[] decryptedBytes = cipher.doFinal(ciphertext);
        return new String(decryptedBytes, "UTF-8");
    }
    
    /**
     * Convierte una clave a formato Base64 para almacenamiento o transmisión
     * 
     * @param key Clave secreta a convertir
     * @return String - Clave en formato Base64
     */
    public static String keyToBase64(SecretKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }
    
    /**
     * Convierte una clave desde formato Base64 a SecretKey
     * 
     * @param base64Key Clave en formato Base64
     * @return SecretKey - Clave secreta reconstruida
     */
    public static SecretKey keyFromBase64(String base64Key) {
        byte[] keyBytes = Base64.getDecoder().decode(base64Key);
        return new SecretKeySpec(keyBytes, ALGORITHM);
    }
    
    /**
     * Convierte un array de bytes a formato Base64
     * 
     * @param bytes Array de bytes a convertir
     * @return String - Datos en formato Base64
     */
    public static String bytesToBase64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }
    
    /**
     * Convierte datos desde formato Base64 a array de bytes
     * 
     * @param base64Data Datos en formato Base64
     * @return byte[] - Array de bytes reconstruido
     */
    public static byte[] bytesFromBase64(String base64Data) {
        return Base64.getDecoder().decode(base64Data);
    }
}