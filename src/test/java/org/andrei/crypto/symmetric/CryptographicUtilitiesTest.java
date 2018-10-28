package org.andrei.crypto.symmetric;

import org.junit.jupiter.api.Test;
import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;
import static org.junit.jupiter.api.Assertions.*;


class CryptographicUtilitiesTest {

    @Test
    void createAESKey() throws Exception {
        SecretKey key = CryptographicUtilities.createAESKey();
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
        SecretKey key = CryptographicUtilities.createAESKey();
        byte[] initializationVector = CryptographicUtilities.createInitializationVector();
        String plainText = "hello, salut, हाय, سلام, привет, 嗨";
        byte[] cipherText = CryptographicUtilities.performAESEncyption(plainText, key, initializationVector);
        assertNotNull(cipherText);
        System.out.println(DatatypeConverter.printHexBinary(cipherText));
        String decryptedText = CryptographicUtilities.performAESDecryption(cipherText, key, initializationVector);
        assertEquals(plainText, decryptedText);
    }
}