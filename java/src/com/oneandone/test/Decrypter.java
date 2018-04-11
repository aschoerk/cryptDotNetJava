package com.oneandone.test;

import java.io.File;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.RSAPrivateKeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

import org.apache.commons.codec.binary.Base64;

/**
 * @author aschoerk
 */
public class Decrypter {




    public static void main(String[] args) throws Exception {

        Cipher cipher = Cipher.getInstance("RSA");


        byte[] toDecrypt = Files.readAllBytes(Paths.get("files/example.encrypted"));
        byte[] expectedResult = Files.readAllBytes(Paths.get("files/example.jpg"));

        int len = toDecrypt[0] + toDecrypt[1] * 256;
        byte[] encryptedSymmetricKey = new byte[len];
        for (int i = 0; i < len; i++)
        {
            encryptedSymmetricKey[i] = toDecrypt[i + 2];
        }

        File rsaKeyValue = new File("files/privateKey.xml");
        JAXBContext jaxbContext = JAXBContext.newInstance(DotNetKeyGenerator.RSAKeyValue.class);
        Unmarshaller unMarshaller = jaxbContext.createUnmarshaller();
        DotNetKeyGenerator.RSAKeyValue result = (DotNetKeyGenerator.RSAKeyValue)unMarshaller.unmarshal(rsaKeyValue);

        BigInteger modulus = Base64.decodeInteger(result.modulus.getBytes("ASCII"));
        BigInteger d = Base64.decodeInteger(result.d.getBytes("ASCII"));
        KeyFactory factory = KeyFactory.getInstance("RSA");

        RSAPrivateKeySpec privSpec = new RSAPrivateKeySpec(modulus, d);

        PrivateKey privKey = factory.generatePrivate(privSpec);

        cipher.init(Cipher.DECRYPT_MODE, privKey);
        byte[] symmetricKey = cipher.doFinal(encryptedSymmetricKey);

        byte keyLen = symmetricKey[0];
        byte ivLen = symmetricKey[1];

        byte[] key = new byte[keyLen];
        byte[] iv = new byte[ivLen];
        for(int i = 0; i < keyLen; i++) {
            key[i] = symmetricKey[2 + i];
        }
        for(int i = 0; i < ivLen; i++) {
            iv[i] = symmetricKey[2 + i + keyLen];
        }

        int payLoadOffset = 2 + encryptedSymmetricKey.length;
        final int payLoadLen = toDecrypt.length - payLoadOffset;
        byte[] payLoad = new byte[payLoadLen];
        for (int i = 0; i < payLoadLen; i ++) {
            payLoad[i] = toDecrypt[i + payLoadOffset];
        }


        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");

        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(iv));

        byte[] decryptedPayLoad = c.doFinal(payLoad);

        assert decryptedPayLoad.length == expectedResult.length;

        for (int i = 0; i < decryptedPayLoad.length; i++) {
            assert decryptedPayLoad[i] == expectedResult[i];
        }
    }
}
