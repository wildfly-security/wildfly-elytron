/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.http.util.sso;

import org.wildfly.security.http.HttpServerRequest;
import org.wildfly.security.util.ByteIterator;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import java.net.HttpURLConnection;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.util.Base64;

import static org.wildfly.common.Assert.checkNotNullParam;
import static org.wildfly.security._private.ElytronMessages.log;

/**
 * {@link SingleSignOnSessionFactory} that delegates the management of single sign-on entries to a {@link SingleSignOnManager}.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 * @author Paul Ferraro
 */
public class DefaultSingleSignOnSessionFactory implements SingleSignOnSessionFactory, SingleSignOnSessionContext {

    private static final String DEFAULT_SIGNATURE_ALGORITHM = "SHA512withRSA";
    private static final HostnameVerifier DEFAULT_HOSTNAME_VERIFIER = (s, sslSession) -> true;

    private final SingleSignOnManager manager;
    private final SSLContext sslContext;
    private final HostnameVerifier hostnameVerifier;
    private final Certificate certificate;
    private final PrivateKey privateKey;

    public DefaultSingleSignOnSessionFactory(SingleSignOnManager manager, KeyStore keyStore, String keyAlias, String keyPassword, SSLContext sslContext) {
        this(manager, keyStore, keyAlias, keyPassword, sslContext, DEFAULT_HOSTNAME_VERIFIER);
    }

    public DefaultSingleSignOnSessionFactory(SingleSignOnManager manager, KeyStore keyStore, String keyAlias, String keyPassword, SSLContext sslContext, HostnameVerifier hostnameVerifier) {
        this.manager = checkNotNullParam("manager", manager);
        checkNotNullParam("keyStore", keyStore);
        checkNotNullParam("keyAlias", keyAlias);
        checkNotNullParam("keyPassword", keyPassword);

        try {
            Key key = keyStore.getKey(keyAlias, keyPassword.toCharArray());

            if (!(key instanceof PrivateKey && "RSA".equals(key.getAlgorithm()))) {
                throw log.httpMechSsoRSAPrivateKeyExpected(keyAlias);
            }

            this.privateKey = (PrivateKey) key;

            this.certificate = keyStore.getCertificate(keyAlias);
        } catch (GeneralSecurityException cause) {
            throw log.httpMechSsoFailedObtainKeyFromKeyStore(keyAlias, cause);
        }

        if (this.certificate == null) {
            throw log.httpMechSsoCertificateExpected(keyAlias);
        }

        this.sslContext = sslContext;
        this.hostnameVerifier = hostnameVerifier;
    }

    @Override
    public SingleSignOnSession find(String id, HttpServerRequest request) {
        checkNotNullParam("id", id);
        checkNotNullParam("request", request);

        SingleSignOn sso = this.manager.find(id);
        return (sso != null) ? new DefaultSingleSignOnSession(this, request, sso) : null;
    }

    @Override
    public SingleSignOnSession create(HttpServerRequest request, String mechanismName) {
        checkNotNullParam("request", request);
        checkNotNullParam("mechanismName", mechanismName);

        return new DefaultSingleSignOnSession(this, request, mechanismName);
    }

    @Override
    public SingleSignOnManager getSingleSignOnManagerManager() {
        return this.manager;
    }

    @Override
    public String createLogoutParameter(String sessionId) {
        try {
            Signature signature = Signature.getInstance(DEFAULT_SIGNATURE_ALGORITHM);

            signature.initSign(this.privateKey);

            Base64.Encoder urlEncoder = Base64.getUrlEncoder();

            return sessionId + "." + ByteIterator.ofBytes(urlEncoder.encode(ByteIterator.ofBytes(sessionId.getBytes()).sign(signature).drain())).asUtf8String().drainToString();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public String verifyLogoutParameter(String parameter) {
        String[] parts = parameter.split("\\.");
        if (parts.length != 2) {
            throw new IllegalArgumentException(parameter);
        }
        try {
            String localSessionId = ByteIterator.ofBytes(parts[0].getBytes()).asUtf8String().drainToString();
            Signature signature = Signature.getInstance(DEFAULT_SIGNATURE_ALGORITHM);

            signature.initVerify(this.certificate);
            signature.update(localSessionId.getBytes());

            Base64.Decoder urlDecoder = Base64.getUrlDecoder();

            if (!ByteIterator.ofBytes(urlDecoder.decode(parts[1].getBytes())).verify(signature)) {
                throw log.httpMechSsoInvalidLogoutMessage(localSessionId);
            }

            return localSessionId;
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException(e);
        } catch (SignatureException e) {
            throw new IllegalArgumentException(parameter, e);
        }
    }

    @Override
    public void configureLogoutConnection(HttpURLConnection connection) {
        if (connection.getURL().getProtocol().equalsIgnoreCase("https")) {
            HttpsURLConnection https = (HttpsURLConnection) connection;
            https.setSSLSocketFactory(this.sslContext.getSocketFactory());
            https.setHostnameVerifier(this.hostnameVerifier);
        }
    }
}
