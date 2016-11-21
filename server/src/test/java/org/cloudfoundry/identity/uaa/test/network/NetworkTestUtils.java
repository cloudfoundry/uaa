/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.test.network;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsExchange;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import sun.security.x509.X500Name;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import static org.cloudfoundry.identity.uaa.util.SocketUtils.getSelfCertificate;


public class NetworkTestUtils {


    static final String commonName = "localhost";
    static final String organizationalUnit = "UAA";
    static final String organization = "Pivotal Software";
    static final String city = "San Francisco";
    static final String state = "CA";
    static final String country = "UA";
    static final String alias = "uaa-test-cert";
    public static final String keyPass = "password";

    static RandomValueStringGenerator generator = new RandomValueStringGenerator();

    public static File getKeystore(Date issueDate,
                                   long validityDays) throws Exception {
        File directory = new File(System.getProperty("java.io.tmpdir"));
        String filename = generator.generate() + ".jks";
        return getKeystore(directory, filename, issueDate, validityDays);
    }


    public static File getKeystore(File directory,
                                   String filename,
                                   Date issueDate,
                                   long validityDays) throws Exception {
        return getKeystore(directory,
                           filename,
                           1024,
                           commonName,
                           organizationalUnit,
                           organization,
                           city,
                           state,
                           country,
                           issueDate,
                           validityDays,
                           alias,
                           keyPass);

    }

    public static File getKeystore(File directory,
                                   String filename,
                                   int keysize,
                                   String commonName,
                                   String organizationalUnit,
                                   String organization,
                                   String city,
                                   String state,
                                   String country,
                                   Date issueDate,
                                   long validityDays,
                                   String keyAlias,
                                   String keyPass) throws Exception {

        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, null);

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keysize);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        X509Certificate[] chain = {getSelfCertificate(new X500Name(commonName, organizationalUnit, organization, city, state, country), issueDate, validityDays * 24 * 60 * 60, keyPair, "SHA256withRSA")};
        keyStore.setKeyEntry(keyAlias, keyPair.getPrivate(), keyPass.toCharArray(), chain);

        File keystore = new File(directory, filename);
        if (!keystore.createNewFile()) {
            throw new FileNotFoundException("Unable to create file:" + keystore);
        }
        keyStore.store(new FileOutputStream(keystore, false), keyPass.toCharArray());
        return keystore;
    }

    public static HttpServer startHttpServer(int port, HttpHandler handler) throws Exception {
        //some stack overflow goodness for testing only
        InetSocketAddress address = new InetSocketAddress(port);
        HttpServer httpServer = HttpServer.create(address, 0);
        httpServer.createContext("/", handler);
        httpServer.setExecutor(new ThreadPoolExecutor(1, 1, 10, TimeUnit.SECONDS, new LinkedBlockingQueue<>()));
        httpServer.start();
        return httpServer;
    }


    public static HttpsServer startHttpsServer(int port, File keystore, String keypass, HttpHandler handler) throws Exception {
        //some stack overflow goodness for testing only
        InetSocketAddress address = new InetSocketAddress(port);
        HttpsServer httpsServer = HttpsServer.create(address, 0);
        SSLContext sslContext = SSLContext.getInstance("TLS");

        char[] password = keypass.toCharArray();
        KeyStore ks = KeyStore.getInstance("JKS");
        FileInputStream fis = new FileInputStream(keystore);
        ks.load(fis, password);

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(ks, password);

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(ks);

        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        httpsServer.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
            public void configure(HttpsParameters params) {
                try {
                    SSLContext c = SSLContext.getDefault();
                    SSLEngine engine = c.createSSLEngine();
                    params.setNeedClientAuth(false);
                    params.setCipherSuites(engine.getEnabledCipherSuites());
                    params.setProtocols(engine.getEnabledProtocols());
                    SSLParameters defaultSSLParameters = c.getDefaultSSLParameters();
                    params.setSSLParameters(defaultSSLParameters);

                } catch (Exception ex) {
                    throw new IllegalStateException(ex);
                }
            }
        });
        httpsServer.createContext("/", handler);
        httpsServer.setExecutor(new ThreadPoolExecutor(1, 1, 10, TimeUnit.SECONDS, new LinkedBlockingQueue<>()));
        httpsServer.start();
        return httpsServer;

    }

    public static class SimpleHttpResponseHandler implements HttpHandler {

        private final int status;
        private final HttpHeaders headers;
        private final String responseBody;
        private volatile boolean wasInvoked = false;

        public SimpleHttpResponseHandler(int status, HttpHeaders headers, String responseBody) {
            this.status = status;
            this.headers = headers;
            this.responseBody = responseBody;
        }

        public boolean wasInvoked() {
            return wasInvoked;
        }

        @Override
        public void handle(HttpExchange httpExchange) throws IOException {
            wasInvoked = true;
            HttpsExchange exchange = (HttpsExchange) httpExchange;
            for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
                for (String value : entry.getValue()) {
                    exchange.getResponseHeaders().add(entry.getKey(), value);
                }
            }

            exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
            exchange.sendResponseHeaders(200, responseBody.length());
            OutputStream os = exchange.getResponseBody();
            os.write(responseBody.getBytes());
            os.flush();
            os.close();
            httpExchange.close();
        }
    }
}
