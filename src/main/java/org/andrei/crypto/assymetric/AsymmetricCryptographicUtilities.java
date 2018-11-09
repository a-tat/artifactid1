package org.andrei.crypto.assymetric;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.util.*;

public class AsymmetricCryptographicUtilities {
    private static final String RSA = "RSA";
    static int key_size_RSA = 8192;
    private static final String DSA = "DSA";
    static int key_size_DSA = 1024;
    // RSA
    public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        SecureRandom secureRandom = new SecureRandom();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA);
        keyPairGenerator.initialize(key_size_RSA, secureRandom);
        return keyPairGenerator.generateKeyPair();
    }

    public static byte[] encryptRSA(String plainText, PublicKey publicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(RSA);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(plainText.getBytes());
    }

    public static String decryptRSA(byte[] cipherText, PrivateKey privateKey) throws Exception{
        Cipher cipher = Cipher.getInstance(RSA);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] result = cipher.doFinal(cipherText);
        return new String(result);
    }
    // DSA  for signing
    public static KeyPair generateDSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(DSA);
        SecureRandom random = SecureRandom.getInstanceStrong();
        keyPairGenerator.initialize(key_size_DSA);
        SecureRandom secureRandom = new SecureRandom();
        keyPairGenerator.initialize(key_size_DSA, secureRandom);
        return keyPairGenerator.generateKeyPair();
    }



    /**
     * Returns a Set of Strings containing the names of all available
     * algorithms or types for the specified Java cryptographic service
     * (e.g., Signature, MessageDigest, Cipher, Mac, KeyStore). Returns
     * an empty Set if there is no provider that supports the
     * specified service or if serviceName is null. For a complete list
     * of Java cryptographic services, please see the
     * <a href="../../../technotes/guides/security/crypto/CryptoSpec.html">Java
     * Cryptography Architecture API Specification &amp; Reference</a>.
     * Note: the returned set is immutable.
     *
     * @param serviceName the name of the Java cryptographic
     * service (e.g., Signature, MessageDigest, Cipher, Mac, KeyStore).
     * Note: this parameter is case-insensitive.
     *
     * @return a Set of Strings containing the names of all available
     * algorithms or types for the specified Java cryptographic service
     * or an empty set if no provider supports the specified service.
     *
     * @since 1.4
     **/


        public static Set<String> getAlgorithms(String serviceName) {

            if ((serviceName == null) || (serviceName.length() == 0) ||
                    (serviceName.endsWith("."))) {
                return Collections.emptySet();
            }

            HashSet<String> result = new HashSet<>();
            Provider[] providers = Security.getProviders();

            for (int i = 0; i < providers.length; i++) {
                // Check the keys for each provider.
                for (Enumeration<Object> e = providers[i].keys();
                     e.hasMoreElements(); ) {
                    String currentKey =
                            ((String)e.nextElement()).toUpperCase(Locale.ENGLISH);
                    if (currentKey.startsWith(
                            serviceName.toUpperCase(Locale.ENGLISH))) {
                        // We should skip the currentKey if it contains a
                        // whitespace. The reason is: such an entry in the
                        // provider property contains attributes for the
                        // implementation of an algorithm. We are only interested
                        // in entries which lead to the implementation
                        // classes.
                        if (currentKey.indexOf(" ") < 0) {
                            result.add(currentKey.substring(
                                    serviceName.length() + 1));
                        }
                    }
                }
            }
            return Collections.unmodifiableSet(result);
        }


}
