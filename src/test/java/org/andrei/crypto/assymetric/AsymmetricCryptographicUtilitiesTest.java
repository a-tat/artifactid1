package org.andrei.crypto.assymetric;

import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.bind.DatatypeConverter;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;
import java.util.Set;
import java.security.*;

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

    @Test
    void generateDSAKeyPair() {
    }

    @Test
    void getAlgorithms() {
    }

    @Test
    void generateRSAKeyPair1() {
    }

    @Test
    void encryptRSA1() {
    }

    @Test
    void decryptRSA1() {
    }

    @Test
    void generateDSAKeyPair1() {
    }

    @Test
    void getAlgorithms1() {
        Set<String> algo = AsymmetricCryptographicUtilities.getAlgorithms("DSA");
        Iterator<String> it = algo.iterator();
        while(it.hasNext()){
            System.out.println(it.next());
        }
        System.out.println("done with algos\n");
        for (Provider provider: Security.getProviders()) {
            System.out.println(provider.getName());
            for (String key: provider.stringPropertyNames())
                System.out.println("\t" + key + "\t" + provider.getProperty(key));
        }
    }
}