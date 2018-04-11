package com.oneandone.test;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.binary.Base64;

public class AsymmetricCryptography {
    private Cipher cipher;
    PublicKey publicKey;
    PrivateKey privateKey;


    public AsymmetricCryptography() throws NoSuchAlgorithmException, NoSuchPaddingException {
        this.cipher = Cipher.getInstance("RSA");

        try {

            FileInputStream is = new FileInputStream("keystore.jks");
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            String password = "pfauenauge";
            char[] passwd = password.toCharArray();
            keystore.load(is, passwd);
            String alias = "mykey";
            Key key = keystore.getKey(alias, passwd);
            if (key instanceof PrivateKey) {
                privateKey = (PrivateKey)key;
                // Get certificate of public key
                Certificate cert = keystore.getCertificate(alias);
                // Get public key
                publicKey = cert.getPublicKey();

                String publicKeyString = new String(java.util.Base64.getEncoder().encode(publicKey
                        .getEncoded()), "UTF-8");
                System.out.println(publicKeyString);


            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // https://docs.oracle.com/javase/8/docs/api/java/security/spec/PKCS8EncodedKeySpec.html
    public PrivateKey getPrivate(String filename) throws Exception {
        // byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
        // PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        // KeyFactory kf = KeyFactory.getInstance("RSA");
        // return kf.generatePrivate(spec);
        return privateKey;
    }

    // https://docs.oracle.com/javase/8/docs/api/java/security/spec/X509EncodedKeySpec.html
    public PublicKey getPublic(String filename) throws Exception {
        // byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
        // X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        // KeyFactory kf = KeyFactory.getInstance("RSA");
        // return kf.generatePublic(spec);
        return publicKey;
    }

    public void encryptFile(byte[] input, File output, PrivateKey key)
            throws IOException, GeneralSecurityException {
        this.cipher.init(Cipher.ENCRYPT_MODE, key);
        writeToFile(output, this.cipher.doFinal(input));
    }

    public void decryptFile(byte[] input, File output, PublicKey key)
            throws IOException, GeneralSecurityException {
        this.cipher.init(Cipher.DECRYPT_MODE, key);
        writeToFile(output, this.cipher.doFinal(input));
    }

    private void writeToFile(File output, byte[] toWrite)
            throws IllegalBlockSizeException, BadPaddingException, IOException {
        FileOutputStream fos = new FileOutputStream(output);
        fos.write(toWrite);
        fos.flush();
        fos.close();
    }

    public String encryptText(String msg, Key key)
            throws NoSuchAlgorithmException, NoSuchPaddingException,
            UnsupportedEncodingException, IllegalBlockSizeException,
            BadPaddingException, InvalidKeyException {
        this.cipher.init(Cipher.ENCRYPT_MODE, key);
        return Base64.encodeBase64String(cipher.doFinal(msg.getBytes("UTF-8")));
    }

    public String decryptText(String msg, Key key)
            throws InvalidKeyException, UnsupportedEncodingException,
            IllegalBlockSizeException, BadPaddingException {
        this.cipher.init(Cipher.DECRYPT_MODE, key);
        return new String(cipher.doFinal(Base64.decodeBase64(msg)), "UTF-8");
    }

    public byte[] getFileInBytes(File f) throws IOException {
        FileInputStream fis = new FileInputStream(f);
        byte[] fbytes = new byte[(int) f.length()];
        fis.read(fbytes);
        fis.close();
        return fbytes;
    }

    public static void main(String[] args) throws Exception {

        int maxKeyLen = Cipher.getMaxAllowedKeyLength("RSA");
        System.out.println(maxKeyLen);
        AsymmetricCryptography ac = new AsymmetricCryptography();
        RSAPrivateKey privateKey = (RSAPrivateKey) ac.getPrivate("KeyPair/privateKey");
        RSAPublicKey publicKey = (RSAPublicKey) ac.getPublic("KeyPair/publicKey");

        String msg = "Cryptography is fun!";
        String encrypted_msg = ac.encryptText(msg, privateKey);
        String decrypted_msg = ac.decryptText(encrypted_msg, publicKey);
        System.out.println("Original Message: " + msg +
                "\nEncrypted Message: " + encrypted_msg
                + "\nDecrypted Message: " + decrypted_msg);

        if (new File("KeyPair/text.txt").exists()) {
            ac.encryptFile(ac.getFileInBytes(new File("KeyPair/text.txt")),
                    new File("KeyPair/text_encrypted.txt"),privateKey);
            ac.decryptFile(ac.getFileInBytes(new File("KeyPair/text_encrypted.txt")),
                    new File("KeyPair/text_decrypted.txt"), publicKey);
        } else {
            System.out.println("Create a file text.txt under folder KeyPair");
        }
    }
}
