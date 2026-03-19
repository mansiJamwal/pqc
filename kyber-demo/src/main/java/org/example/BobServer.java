package org.example;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpExchange;

import java.io.*;
import java.net.InetSocketAddress;
import java.security.*;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.GCMParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;

import java.util.Base64;

public class BobServer {

    static KeyPair keyPair;
    static byte[] sessionKey = null;

    public static void main(String[] args) throws Exception {

        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Kyber", "BCPQC");
        kpg.initialize(KyberParameterSpec.kyber512);
        keyPair = kpg.generateKeyPair();

        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);

        // 🔹 Public Key
        server.createContext("/public-key", (exchange) -> {
            String response = Base64.getEncoder()
                    .encodeToString(keyPair.getPublic().getEncoded());
            send(exchange, response);
        });

        // 🔹 Receive Message
        server.createContext("/receive", (exchange) -> {
            try {
                String body = new String(exchange.getRequestBody().readAllBytes());

                boolean init = body.contains("\"init\":true");

                String ivB64 = extract(body, "iv");
                String ciphertextB64 = extract(body, "ciphertext");

                byte[] iv = Base64.getDecoder().decode(ivB64);

                // 🔥 First-time key setup
                if (init) {
                    String encapsulationB64 = extract(body, "encapsulation");
                    byte[] encapsulation = Base64.getDecoder().decode(encapsulationB64);

                    KeyGenerator kg = KeyGenerator.getInstance("Kyber", "BCPQC");
                    kg.init(new KEMExtractSpec(
                            keyPair.getPrivate(),
                            encapsulation,
                            "AES"
                    ));

                    SecretKeyWithEncapsulation secret =
                            (SecretKeyWithEncapsulation) kg.generateKey();

                    byte[] fullKey = secret.getEncoded();

                    sessionKey = new byte[16];
                    System.arraycopy(fullKey, 0, sessionKey, 0, 16);

                    System.out.println("🔑 Session key established");
                }

                if (sessionKey == null) {
                    send(exchange, "NO_SESSION");
                    return;
                }

                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.DECRYPT_MODE,
                        new SecretKeySpec(sessionKey, "AES"),
                        new GCMParameterSpec(128, iv));

                byte[] decrypted = cipher.doFinal(
                        Base64.getDecoder().decode(ciphertextB64)
                );

                System.out.println("📩 Bob received: " + new String(decrypted));

                send(exchange, "OK");

            } catch (Exception e) {
                e.printStackTrace();
                send(exchange, "ERROR");
            }
        });

        // 🔹 Reset Session
        server.createContext("/reset", (exchange) -> {
            sessionKey = null;
            System.out.println("♻️ Session reset");
            send(exchange, "RESET_DONE");
        });

        server.start();
        System.out.println("🚀 Bob running at http://localhost:8080");
    }

    static void send(HttpExchange ex, String response) throws IOException {
        ex.sendResponseHeaders(200, response.length());
        ex.getResponseBody().write(response.getBytes());
        ex.getResponseBody().close();
    }

    static String extract(String json, String key) {
        return json.split(key + "\":\"")[1].split("\"")[0];
    }
}