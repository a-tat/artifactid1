package org.andrei.crypto.symmetric;

import org.junit.jupiter.api.Test;
import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;
import static org.junit.jupiter.api.Assertions.*;


public class SymmetricCryptographicUtilitiesTest {

    @Test
    void createAESKey() throws Exception {
        SecretKey key =  SymmetricCryptographicUtilities .createAESKey();
        assertNotNull(key);
        System.out.println(DatatypeConverter.printHexBinary(key.getEncoded()));
    }

    @Test
    void createInitializationVector() {
    }

    @Test
    void performAESEncyption() {
    }

    @Test
    void performAESDecryption() {
    }
    @Test
    void testAESCyrptoRoutine() throws Exception{
        SecretKey key =  SymmetricCryptographicUtilities .createAESKey();
        byte[] initializationVector =  SymmetricCryptographicUtilities .createInitializationVector();
        String plainText = "hello, salut, हाय, سلام, привет, 嗨";
        byte[] cipherText =  SymmetricCryptographicUtilities .performAESEncyption(plainText, key, initializationVector);
        assertNotNull(cipherText);
        System.out.println(DatatypeConverter.printHexBinary(cipherText));
        String decryptedText =  SymmetricCryptographicUtilities .performAESDecryption(cipherText, key, initializationVector);
        assertEquals(plainText, decryptedText);
        //System.out.println(decryptedText);
    }
}