package dev.arsalaan.jwtoauth2demo.security;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class KeyGeneratorUtils {

    static KeyPair generateRsaKey() {

        KeyPair keyPair;

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }

        return keyPair;
    }

}
