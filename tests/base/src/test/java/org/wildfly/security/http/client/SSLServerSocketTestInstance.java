package org.wildfly.security.http.client;

import okhttp3.TlsVersion;
import org.wildfly.security.http.client.utils.ClientCertSSLTestUtils;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicBoolean;

public class SSLServerSocketTestInstance {
    private int port;
    private String keystorePath;
    private String truststorePath;
    private String[] configuredEnabledCipherSuites;
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
            if (configuredEnabledCipherSuites != null) {
                sslServerSocket.setEnabledCipherSuites(configuredEnabledCipherSuites);
            }
            sslServerSocket.bind(new InetSocketAddress("localhost", port));
            serverThread = new Thread(() -> {
                running.set(true);
                while (running.get()) {
                    try {
                        SSLSocket sslSocket = (SSLSocket) sslServerSocket.accept();
                        new Thread(new ServerThread(sslSocket)).start();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            });
            serverThread.start();
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }

    public void stop() {
        running.set(false);
        try {
            serverThread.join();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    public static class ServerThread implements Runnable {
        private SSLSocket sslSocket;

        ServerThread(SSLSocket sslSocket) {
            this.sslSocket = sslSocket;
        }

        public void run() {
            try {
                sslSocket.startHandshake();

                InputStream inputStream = sslSocket.getInputStream();
                BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
                OutputStream outputStream = sslSocket.getOutputStream();

                // Read the HTTP request
                String requestLine = bufferedReader.readLine();
                if (requestLine != null) {
                    // Print the request line
                    System.out.println("Received request: " + requestLine);

                    // Read and ignore the headers
                    String headerLine;
                    while ((headerLine = bufferedReader.readLine()).length() != 0) {
                        System.out.println(headerLine);
                    }

                    // Send the HTTP response
                    String response = "HTTP/1.1 200 OK\r\n" +
                            "Content-Type: text/plain\r\n" +
                            "\r\n" +
                            "Hello, World!";
                    outputStream.write(response.getBytes(StandardCharsets.UTF_8));
                    outputStream.flush();
                }

                outputStream.close();
                inputStream.close();
                sslSocket.close();
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
    }

}
