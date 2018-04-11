package com.oneandone.test;


import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Base64;

public class ReadFromKeystore {

    public static void main(String[] args) {

        try {

            FileInputStream is = new FileInputStream("keystore");
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            String password = "pfauenauge";
            char[] passwd = password.toCharArray();
            keystore.load(is, passwd);
            String alias = "mykey";
            Key key = keystore.getKey(alias, passwd);
            if (key instanceof PrivateKey) {
                // Get certificate of public key
                Certificate cert = keystore.getCertificate(alias);
                // Get public key
                PublicKey publicKey = cert.getPublicKey();

                String publicKeyString = new String(Base64.getEncoder().encode(publicKey
                        .getEncoded()), "UTF-8");
                System.out.println(publicKeyString);

            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
