/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2023 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wildfly.security.http.client;

import okhttp3.TlsVersion;
import org.junit.Assert;
import org.wildfly.security.http.client.utils.ClientCertSSLTestUtils;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Utility class for running SSLServerSocket instance for testing.
 * @author Diana Krepinska
 */
public class SSLServerSocketTestInstance {

    private int port;
    private String keystorePath;
    private String truststorePath;
    private SSLServerSocket sslServerSocket;
    private AtomicBoolean running = new AtomicBoolean(false);
    private Thread serverThread;

    public SSLServerSocketTestInstance(String pathToKeystore, String pathToTruststore, int port) {
        this.keystorePath = pathToKeystore;
        this.truststorePath = pathToTruststore;
        this.port = port;
    }

    public void run() {
        String password = "secret";
        SSLContext sslContext = ClientCertSSLTestUtils.createSSLContext(this.keystorePath, this.truststorePath, password);
        try {
            SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();
            sslServerSocket = (javax.net.ssl.SSLServerSocket) sslServerSocketFactory.createServerSocket();
            sslServerSocket.setNeedClientAuth(true);
            sslServerSocket.setUseClientMode(false);
            sslServerSocket.setWantClientAuth(true);
            sslServerSocket.setEnabledProtocols(new String[]{
                    TlsVersion.TLS_1_2.javaName(),
                    TlsVersion.TLS_1_3.javaName()
            });
            sslServerSocket.bind(new InetSocketAddress("localhost", port));
            serverThread = new Thread(() -> {
                running.set(true);
                while (running.get()) {
                    SSLSocket sslSocket;
                    try {
                        sslSocket = (SSLSocket) sslServerSocket.accept();
                        new Thread(new ServerThread(sslSocket)).start();
                    } catch (Exception e) {
                        Assert.fail();
                    }
                }
            });
            serverThread.start();
        } catch (Exception ex) {
            Assert.fail();
        } finally {
            running.set(false);
        }
    }

    public void stop() {
        running.set(false);
    }

    // Thread handling the socket from client
    public static class ServerThread implements Runnable {
        public static final String STATUS_OK = "HTTP/1.1 200 OK\r\n" +
                "Content-Type: text/plain\r\n" +
                "\r\n" +
                "ElytronHttpClient";
        private SSLSocket sslSocket;
        AtomicBoolean running = new AtomicBoolean(false);

        ServerThread(SSLSocket sslSocket) {
            this.sslSocket = sslSocket;
        }

        public void run() {
            try {
                // wait for client's message first so that the first client message will trigger handshake.
                // This way client can set its preferences in SSLParams after creation of bound createSocket(host,port) without server triggering handshake before.
                running.set(true);
                sslSocket.startHandshake();

                // if successful return 200
                PrintWriter printWriter = new PrintWriter(new OutputStreamWriter(sslSocket.getOutputStream()));
                printWriter.println(STATUS_OK );
                printWriter.flush();
                sslSocket.close();
            } catch (Exception ex) {
                Assert.fail();
            } finally {
                running.set(false);
            }
        }
    }
}