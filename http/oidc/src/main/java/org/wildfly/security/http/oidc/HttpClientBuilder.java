/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2021 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wildfly.security.http.oidc;

import static org.wildfly.security.http.oidc.ElytronMessages.log;
import static org.wildfly.security.http.oidc.Oidc.EnvUtil;
import static org.wildfly.security.http.oidc.Oidc.PROTOCOL_CLASSPATH;

import java.io.FileInputStream;
import java.io.InputStream;
import java.net.URI;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.http.HttpHost;
import org.apache.http.client.CookieStore;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.HttpClientConnectionManager;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.DefaultHostnameVerifier;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.cookie.Cookie;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.ssl.SSLContexts;

/**
 * Abstraction for creating HttpClients. Allows SSL configuration.
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class HttpClientBuilder {

    public enum HostnameVerificationPolicy {
        /**
         * Hostname verification is not done on the server's certificate
         */
        ANY,
        /**
         * Allows wildcards in subdomain names i.e. *.foo.com
         */
        WILDCARD
    }

    private KeyStore truststore;
    private boolean disableTrustManager;
    private boolean disableCookieCache = true;
    private KeyStore clientKeyStore;
    private String clientPrivateKeyPassword;
    private int connectionPoolSize = 100;
    protected int maxPooledPerRoute = 0;
    private HostnameVerificationPolicy policy = HostnameVerificationPolicy.WILDCARD;
    private HttpHost proxyHost;
    private HostnameVerifier verifier = null;
    private SSLContext sslContext;
    private long connectionTimeToLive = -1;
    private TimeUnit connectionTimeToLiveUnit = TimeUnit.MILLISECONDS;
    private long socketTimeout = -1;
    private TimeUnit socketTimeoutUnits = TimeUnit.MILLISECONDS;
    private long establishConnectionTimeout = -1;
    private TimeUnit establishConnectionTimeoutUnits = TimeUnit.MILLISECONDS;

    /**
     * This should only be set if you cannot or do not want to verify the identity of the
     * host you are communicating with.
     *
     * @return the builder
     */
    public HttpClientBuilder setDisableTrustManager() {
        this.disableTrustManager = true;
        return this;
    }

    public HttpClientBuilder setDisableCookieCache(boolean disable) {
        this.disableCookieCache = disable;
        return this;
    }

    public HttpClientBuilder setKeyStore(KeyStore keyStore, String password) {
        this.clientKeyStore = keyStore;
        this.clientPrivateKeyPassword = password;
        return this;
    }

    public HttpClientBuilder setConnectionPoolSize(int connectionPoolSize) {
        this.connectionPoolSize = connectionPoolSize;
        return this;
    }

    public HttpClientBuilder setHostnameVerification(HostnameVerificationPolicy policy) {
        this.policy = policy;
        return this;
    }

    public HttpClientBuilder setTrustStore(KeyStore truststore) {
        this.truststore = truststore;
        return this;
    }

    public HttpClientBuilder setConnectionTimeToLive(long timeToLive, TimeUnit timeToLiveUnit) {
        this.connectionTimeToLive = timeToLive;
        this.connectionTimeToLiveUnit = timeToLiveUnit;
        return this;
    }

    public HttpClientBuilder setMaxPooledPerRoute(int maxPooledPerRoute) {
        this.maxPooledPerRoute = maxPooledPerRoute;
        return this;
    }

    public HttpClientBuilder setSocketTimeout(long timeout, TimeUnit unit) {
        this.socketTimeout = timeout;
        this.socketTimeoutUnits = unit;
        return this;
    }

    public HttpClientBuilder setEstablishConnectionTimeout(long timeout, TimeUnit unit) {
        this.establishConnectionTimeout = timeout;
        this.establishConnectionTimeoutUnits = unit;
        return this;
    }

    public HttpClient build() {
        HostnameVerifier verifier = null;
        if (this.verifier != null) verifier = new VerifierWrapper(this.verifier);
        else {
            switch (policy) {
                case ANY:
                    verifier = new NoopHostnameVerifier();
                    break;
                case WILDCARD:
                    verifier = new DefaultHostnameVerifier();
                    break;
            }
        }
        try {
            SSLConnectionSocketFactory sslSocketFactory = null;
            SSLContext theContext = sslContext;
            if (disableTrustManager) {
                theContext = SSLContext.getInstance("TLS");
                theContext.init(null, new TrustManager[]{ new PassthroughTrustManager() },
                        new SecureRandom());
                verifier = new NoopHostnameVerifier();
                sslSocketFactory = new SSLConnectionSocketFactory(theContext, verifier);
            } else if (theContext != null) {
                sslSocketFactory = new SSLConnectionSocketFactory(theContext, verifier);
            } else if (clientKeyStore != null || truststore != null) {
                sslSocketFactory = new SSLConnectionSocketFactory(SSLContexts.custom()
                        .setProtocol(SSLConnectionSocketFactory.TLS)
                        .setSecureRandom(null)
                        .loadKeyMaterial(clientKeyStore, clientPrivateKeyPassword != null ? clientPrivateKeyPassword.toCharArray() : null)
                        .loadTrustMaterial(truststore,null)
                        .build(), verifier);
            } else {
                final SSLContext tlsContext = SSLContext.getInstance(SSLConnectionSocketFactory.TLS);
                tlsContext.init(null, null, null);
                sslSocketFactory = new SSLConnectionSocketFactory(tlsContext, verifier);
            }
            Registry<ConnectionSocketFactory> registry = RegistryBuilder.<ConnectionSocketFactory>create()
                    .register("http", PlainConnectionSocketFactory.getSocketFactory())
                    .register("https", sslSocketFactory)
                    .build();
            HttpClientConnectionManager connectionManager;
            if (connectionPoolSize > 0) {
                PoolingHttpClientConnectionManager pcm = new PoolingHttpClientConnectionManager(registry, null, null, null, connectionTimeToLive, connectionTimeToLiveUnit);
                pcm.setMaxTotal(connectionPoolSize);
                if (maxPooledPerRoute == 0) maxPooledPerRoute = connectionPoolSize;
                pcm.setDefaultMaxPerRoute(maxPooledPerRoute);
                connectionManager = pcm;

            } else {
                connectionManager = new BasicHttpClientConnectionManager(registry);
            }

            org.apache.http.impl.client.HttpClientBuilder clientBuilder = org.apache.http.impl.client.HttpClientBuilder.create();
            clientBuilder.setConnectionManager(connectionManager);

            RequestConfig.Builder requestConfigBuilder = RequestConfig.custom();
            if (proxyHost != null) {
                requestConfigBuilder.setProxy(proxyHost);
            }
            if (socketTimeout > -1) {
                requestConfigBuilder.setSocketTimeout((int) socketTimeoutUnits.toMillis(socketTimeout));
            }
            if (establishConnectionTimeout > -1) {
                requestConfigBuilder.setConnectTimeout((int) establishConnectionTimeoutUnits.toMillis(establishConnectionTimeout));
            }
            clientBuilder.setDefaultRequestConfig(requestConfigBuilder.build());
            if (disableCookieCache) {
                clientBuilder.setDefaultCookieStore(new CookieStore() {
                    @Override
                    public void addCookie(Cookie cookie) {
                    }

                    @Override
                    public List<Cookie> getCookies() {
                        return Collections.emptyList();
                    }

                    @Override
                    public boolean clearExpired(Date date) {
                        return false;
                    }

                    @Override
                    public void clear() {
                    }
                });
            }
            return clientBuilder.build();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public HttpClient build(OidcJsonConfiguration oidcClientConfig) {
        setDisableCookieCache(true); // disable cookie cache as we don't want sticky sessions for load balancing

        String truststorePath = oidcClientConfig.getTruststore();
        if (truststorePath != null) {
            truststorePath = EnvUtil.replace(truststorePath);
            String truststorePassword = oidcClientConfig.getTruststorePassword();
            try {
                this.truststore = loadKeyStore(truststorePath, truststorePassword);
            } catch (Exception e) {
                throw log.unableToLoadKeyStore(e);
            }
        }
        String clientKeystore = oidcClientConfig.getClientKeystore();
        if (clientKeystore != null) {
            clientKeystore = EnvUtil.replace(clientKeystore);
            String clientKeystorePassword = oidcClientConfig.getClientKeystorePassword();
            try {
                KeyStore clientCertKeystore = loadKeyStore(clientKeystore, clientKeystorePassword);
                setKeyStore(clientCertKeystore, clientKeystorePassword);
            } catch (Exception e) {
                throw log.unableToLoadTrustStore(e);
            }
        }
        int size = 10;
        if (oidcClientConfig.getConnectionPoolSize() > 0) {
            size = oidcClientConfig.getConnectionPoolSize();
        }
        if (oidcClientConfig.getConnectionTimeoutMillis() > 0) {
            setEstablishConnectionTimeout(oidcClientConfig.getConnectionTimeoutMillis(), establishConnectionTimeoutUnits);
        }
        if (oidcClientConfig.getConnectionTtlMillis() > 0) {
            setConnectionTimeToLive(oidcClientConfig.getConnectionTtlMillis(), connectionTimeToLiveUnit);
        }
        if (oidcClientConfig.getSocketTimeoutMillis() > 0) {
            setSocketTimeout(oidcClientConfig.getSocketTimeoutMillis(), socketTimeoutUnits);
        }
        HttpClientBuilder.HostnameVerificationPolicy policy = HttpClientBuilder.HostnameVerificationPolicy.WILDCARD;
        if (oidcClientConfig.isAllowAnyHostname()) {
            policy = HttpClientBuilder.HostnameVerificationPolicy.ANY;
        }
        setConnectionPoolSize(size);
        setHostnameVerification(policy);
        if (oidcClientConfig.isDisableTrustManager()) {
            setDisableTrustManager();
        } else {
            setTrustStore(truststore);
        }

        configureProxyForAuthServerIfProvided(oidcClientConfig);
        return build();
    }

    /**
     * Configures a the proxy to use for auth-server requests if provided.
     * <p>
     * If the given {@link OidcJsonConfiguration} contains the attribute {@code proxy-url} we use the
     * given URL as a proxy server, otherwise the proxy configuration is ignored.
     * </p>
     *
     * @param adapterConfig
     */
    private void configureProxyForAuthServerIfProvided(OidcJsonConfiguration adapterConfig) {
        if (adapterConfig == null || adapterConfig.getProxyUrl() == null || adapterConfig.getProxyUrl().trim().isEmpty()) {
            return;
        }
        URI uri = URI.create(adapterConfig.getProxyUrl());
        this.proxyHost = new HttpHost(uri.getHost(), uri.getPort(), uri.getScheme());
    }

    private static KeyStore loadKeyStore(String filename, String password) throws Exception {
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        InputStream trustStream = null;
        if (filename.startsWith(PROTOCOL_CLASSPATH)) {
            String resourcePath = filename.replace(PROTOCOL_CLASSPATH, "");
            if (Thread.currentThread().getContextClassLoader() != null) {
                trustStream = Thread.currentThread().getContextClassLoader().getResourceAsStream(resourcePath);
            }
            if (trustStream == null) {
                trustStream = HttpClientBuilder.class.getResourceAsStream(resourcePath);
            }
            if (trustStream == null) {
                throw log.unableToFindTrustStoreFile(filename);
            }
        } else {
            trustStream = new FileInputStream(filename);
        }
        try (InputStream is = trustStream) {
            trustStore.load(is, password.toCharArray());
        }
        return trustStore;
    }

    static class VerifierWrapper implements HostnameVerifier {
        protected HostnameVerifier verifier;

        VerifierWrapper(HostnameVerifier verifier) {
            this.verifier = verifier;
        }

        @Override
        public boolean verify(String s, SSLSession sslSession) {
            return verifier.verify(s, sslSession);
        }
    }

    private static class PassthroughTrustManager implements X509TrustManager {
        public void checkClientTrusted(X509Certificate[] chain,
                                       String authType) throws CertificateException {
        }

        public void checkServerTrusted(X509Certificate[] chain,
                                       String authType) throws CertificateException {
        }

        public X509Certificate[] getAcceptedIssuers() {
            return null;
        }
    }
}
