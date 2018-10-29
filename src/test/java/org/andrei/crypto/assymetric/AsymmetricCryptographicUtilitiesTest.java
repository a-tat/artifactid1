package org.andrei.crypto.assymetric;

import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.bind.DatatypeConverter;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;

class AsymmetricCryptographicUtilitiesTest {

    @Test
    void generateRSAKeyPair()  throws NoSuchAlgorithmException {
        KeyPair keyPair = AsymmetricCryptographicUtilities.generateRSAKeyPair();
        assertNotNull(keyPair);
        System.out.println("Private Key: " + DatatypeConverter.printHexBinary(keyPair.getPrivate().getEncoded()));
        System.out.println("Public Key:  " + DatatypeConverter.printHexBinary(keyPair.getPublic().getEncoded()));
    }

    @Test
    void encryptRSA() {
    }

    @Test
    void decryptRSA() {
    }
    @Test
    void testRSA() throws Exception {
        KeyPair keyPair = AsymmetricCryptographicUtilities.generateRSAKeyPair();
        String plainText = "hello, salut, हाय, سلام, привет, 嗨";
        byte[] cipherText = AsymmetricCryptographicUtilities.encryptRSA(plainText, keyPair.getPublic());
        assertNotNull(cipherText);
        System.out.println(DatatypeConverter.printHexBinary(cipherText));
        String decryptedText = AsymmetricCryptographicUtilities.decryptRSA(cipherText, keyPair.getPrivate());
        assertEquals(plainText, decryptedText);
    }
}