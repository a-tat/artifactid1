package org.andrei.crypto.symmetric;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;


public class SymmetricCryptographicUtilities {
    // symmetric - AES standard implementation
    private static final String AES = "AES";
    private static final String AES_CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String AES_128_NoPadding_ALGORITHM = "AES/EBC/NoPadding";

    public static SecretKey createAESKey() throws Exception{
        SecureRandom secureRandom = new SecureRandom();
        KeyGenerator keyGenerator = KeyGenerator.getInstance(AES);
        keyGenerator.init(256, secureRandom);
        return keyGenerator.generateKey();
    }
    // with 128 bit secret key
    public static SecretKey createAESKey(int size) throws Exception{
        SecureRandom secureRandom = new SecureRandom();
        KeyGenerator keyGenerator = KeyGenerator.getInstance(AES);
        keyGenerator.init(size, secureRandom);
        return keyGenerator.generateKey();
    }

    public static byte[] createInitializationVector(){
        byte[] initializationVector = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(initializationVector);
        return initializationVector;
    }

    public static byte[] performAESEncyption(String plainText, SecretKey secretKey, byte[] initializationVector) throws Exception{
        Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        return cipher.doFinal(plainText.getBytes());
    }
    // encryption with 128 bit secret key
    //TODO continue here
    public static byte[] perform_basic_AESEncyption(String plainText, SecretKey secretKey) throws Exception{
        Cipher cipher = Cipher.getInstance(AES_128_NoPadding_ALGORITHM );
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        SecretKeySpec skeySpec = new SecretKeySpec(secretKey.getEncoded(), secretKey.getAlgorithm()); // 128 bits
        Cipher encryptor = Cipher.getInstance("AES");
        encryptor.init(Cipher.ENCRYPT_MODE, skeySpec);
        byte[] encrypted = encryptor.doFinal(plainText.getBytes());
        return encrypted;
        //return cipher.doFinal(plainText.getBytes());
    }
    public static String perform_basic_AESDecryption(byte[] cipherText, SecretKey secretKey) throws Exception{
        Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] result = cipher.doFinal(cipherText);
        return new String(result);
    }

    public static String performAESDecryption(byte[] cipherText, SecretKey secretKey, byte[] initializationVector) throws Exception{
        Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        byte[] result = cipher.doFinal(cipherText);
        return new String(result);
    }

}
