package org.andrei.crypto.assymetric;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;

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
  


}
