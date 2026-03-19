package org.example;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpExchange;

import java.io.*;
import java.net.*;
import java.net.http.*;
import java.security.*;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.GCMParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;

import java.util.Base64;

public class AliceServer {

    static byte[] sessionKey = null;

    public static void main(String[] args) throws Exception {

        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());

        HttpServer server = HttpServer.create(new InetSocketAddress(9000), 0);

        server.createContext("/send-to-bob", (exchange) -> {
            try {
                String body = new String(exchange.getRequestBody().readAllBytes());
                String message = extract(body, "message");

                HttpClient client = HttpClient.newHttpClient();

                String response;

                // 🔥 If no session → initialize
                if (sessionKey == null) {
                    response = initAndSend(client, message);
                } else {
                    response = sendWithSession(client, message);

                    // 🔥 Auto-recovery if Bob lost session
                    if (response.contains("NO_SESSION")) {
                        System.out.println("⚠️ Session mismatch. Reinitializing...");
                        sessionKey = null;
                        response = initAndSend(client, message);
                    }
                }

                send(exchange, "Sent! Bob says: " + response);

            } catch (Exception e) {
                e.printStackTrace();
                send(exchange, "ERROR");
            }
        });

        server.start();
        System.out.println("🚀 Alice running at http://localhost:9000");
    }

    // 🔹 First-time setup
    static String initAndSend(HttpClient client, String message) throws Exception {

        HttpRequest keyReq = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:8080/public-key"))
                .GET()
                .build();

        String pubKeyB64 = client.send(keyReq,
                HttpResponse.BodyHandlers.ofString()).body();

        byte[] pubKeyBytes = Base64.getDecoder().decode(pubKeyB64);

        KeyFactory kf = KeyFactory.getInstance("Kyber", "BCPQC");
        PublicKey pubKey = kf.generatePublic(
                new java.security.spec.X509EncodedKeySpec(pubKeyBytes));

        KeyGenerator kg = KeyGenerator.getInstance("Kyber", "BCPQC");
        kg.init(new KEMGenerateSpec(pubKey, "AES"));

        SecretKeyWithEncapsulation secret =
                (SecretKeyWithEncapsulation) kg.generateKey();

        byte[] fullKey = secret.getEncoded();

        sessionKey = new byte[16];
        System.arraycopy(fullKey, 0, sessionKey, 0, 16);

        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE,
                new SecretKeySpec(sessionKey, "AES"),
                new GCMParameterSpec(128, iv));

        byte[] encrypted = cipher.doFinal(message.getBytes());

        String json = String.format(
                "{\"init\":true,\"encapsulation\":\"%s\",\"iv\":\"%s\",\"ciphertext\":\"%s\"}",
                Base64.getEncoder().encodeToString(secret.getEncapsulation()),
                Base64.getEncoder().encodeToString(iv),
                Base64.getEncoder().encodeToString(encrypted)
        );

        return sendToBob(client, json);
    }

    // 🔹 Normal messages
    static String sendWithSession(HttpClient client, String message) throws Exception {

        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE,
                new SecretKeySpec(sessionKey, "AES"),
                new GCMParameterSpec(128, iv));

        byte[] encrypted = cipher.doFinal(message.getBytes());

        String json = String.format(
                "{\"init\":false,\"iv\":\"%s\",\"ciphertext\":\"%s\"}",
                Base64.getEncoder().encodeToString(iv),
                Base64.getEncoder().encodeToString(encrypted)
        );

        return sendToBob(client, json);
    }

    static String sendToBob(HttpClient client, String json) throws Exception {
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:8080/receive"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json))
                .build();

        return client.send(req, HttpResponse.BodyHandlers.ofString()).body();
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