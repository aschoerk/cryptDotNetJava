package com.oneandone.test;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

import org.apache.commons.codec.binary.Base64;

public class DotNetKeyGenerator {

    @XmlRootElement(name = "RSAKeyValue")
    static class RSAKeyValue {

        @XmlElement(name = "Modulus", required = true)
        String modulus;

        @XmlElement(name = "Exponent", required = true)
        String exponent;

        @XmlElement(name = "P")
        String p;

        @XmlElement(name = "Q")
        String q;

        @XmlElement(name = "DP")
        String dp;

        @XmlElement(name = "DQ")
        String dq;

        @XmlElement(name = "InverseQ")
        String inverseQ;

        @XmlElement(name = "D")
        String d;


    }

    public void genKeys(String directory, String keyPrefix) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(4096);
        KeyPair keyPair = keyPairGen.genKeyPair();

        RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) keyPair.getPrivate();


        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAKeyValue privateRsaKeyValue = new RSAKeyValue();
        RSAKeyValue publicRsaKeyValue = new RSAKeyValue();

        publicRsaKeyValue.modulus =  encode(publicKey.getModulus());
        publicRsaKeyValue.exponent =  encode(publicKey.getPublicExponent());


        privateRsaKeyValue.modulus = encode(privKey.getModulus());
        privateRsaKeyValue.exponent = encode(privKey.getPublicExponent());
        privateRsaKeyValue.d = encode(privKey.getPrivateExponent());
        privateRsaKeyValue.p = encode(privKey.getPrimeP());
        privateRsaKeyValue.q = encode(privKey.getPrimeQ());
        privateRsaKeyValue.dp = encode(privKey.getPrimeExponentP());
        privateRsaKeyValue.dq = encode(privKey.getPrimeExponentQ());
        privateRsaKeyValue.inverseQ = encode(privKey.getCrtCoefficient());





    }

    public static void main(String[] args) throws NoSuchAlgorithmException, UnsupportedEncodingException, NoSuchPaddingException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, InvalidKeySpecException {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(4096);
        KeyPair keyPair = keyPairGen.genKeyPair();

        RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) keyPair.getPrivate();


        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

        BigInteger n = privKey.getModulus();
        BigInteger pn = publicKey.getModulus();
        BigInteger e = privKey.getPublicExponent();
        BigInteger pe = publicKey.getPublicExponent();
        BigInteger d = privKey.getPrivateExponent();
        BigInteger p = privKey.getPrimeP();
        BigInteger q = privKey.getPrimeQ();
        BigInteger dp = privKey.getPrimeExponentP();
        BigInteger dq = privKey.getPrimeExponentQ();
        BigInteger inverseQ = privKey.getCrtCoefficient();


        StringBuilder builder = new StringBuilder();
        builder.append("<RSAKeyValue>\n");
        write(builder, "Modulus", n);
        write(builder, "Exponent", e);
        write(builder, "P", p);
        write(builder, "Q", q);
        write(builder, "DP", dp);
        write(builder, "DQ", dq);
        write(builder, "InverseQ", inverseQ);
        write(builder, "D", d);
        builder.append("</RSAKeyValue>");
        System.out.println(builder.toString());

        AsymmetricCryptography ac = new AsymmetricCryptography();
        String encrypted = ac.encryptText("test", keyPair.getPublic());
        String decrypted = ac.decryptText(encrypted, keyPair.getPrivate());

        System.out.printf("org      : %s, \ndecrypted: %s\n", "test", decrypted);

        KeyFactory factory = KeyFactory.getInstance("RSA");
        Cipher cipher = Cipher.getInstance("RSA");

        RSAPrivateKeySpec privSpec = new RSAPrivateKeySpec(n, d);
        PrivateKey recreatedPrivKey = factory.generatePrivate(privSpec);
        String decrypted2 = ac.decryptText(encrypted, recreatedPrivKey);
        assert decrypted.equals(decrypted2);




    }

    private static void write(StringBuilder builder, String tag, BigInteger bigInt) throws UnsupportedEncodingException {
        builder.append("\t<");
        builder.append(tag);
        builder.append(">");
        builder.append(encode(bigInt));
        builder.append("</");
        builder.append(tag);
        builder.append(">\n");
    }

    private static String encode(BigInteger bigInt) throws UnsupportedEncodingException {
        return new String(Base64.encodeInteger(bigInt), "ASCII");
    }
}
