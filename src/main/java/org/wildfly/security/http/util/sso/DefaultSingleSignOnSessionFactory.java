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

import org.wildfly.common.iteration.ByteIterator;
import org.wildfly.security.http.HttpServerRequest;

import javax.net.ssl.HttpsURLConnection;
import java.net.HttpURLConnection;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;
import java.util.function.Consumer;

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

    private final SingleSignOnManager manager;
    private final KeyPair keyPair;
    private final Consumer<HttpsURLConnection> logoutConnectionConfigurator;

    public DefaultSingleSignOnSessionFactory(SingleSignOnManager manager, KeyPair keyPair) {
        this(manager, keyPair, connection -> {});
    }

    public DefaultSingleSignOnSessionFactory(SingleSignOnManager manager, KeyPair keyPair, Consumer<HttpsURLConnection> logoutConnectionConfigurator) {
        this.manager = checkNotNullParam("manager", manager);
        this.keyPair = checkNotNullParam("keyPair", keyPair);
        this.logoutConnectionConfigurator = checkNotNullParam("logoutConnectionConfigurator", logoutConnectionConfigurator);
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
    public SingleSignOnManager getSingleSignOnManager() {
        return this.manager;
    }

    @Override
    public String createLogoutParameter(String sessionId) {
        try {
            Signature signature = Signature.getInstance(DEFAULT_SIGNATURE_ALGORITHM);

            signature.initSign(this.keyPair.getPrivate());

            Base64.Encoder urlEncoder = Base64.getUrlEncoder();

            return sessionId + "." + ByteIterator.ofBytes(urlEncoder.encode(ByteIterator.ofBytes(sessionId.getBytes(StandardCharsets.UTF_8)).sign(signature).drain())).asUtf8String().drainToString();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
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
            String localSessionId = ByteIterator.ofBytes(parts[0].getBytes(StandardCharsets.UTF_8)).asUtf8String().drainToString();
            Signature signature = Signature.getInstance(DEFAULT_SIGNATURE_ALGORITHM);

            signature.initVerify(this.keyPair.getPublic());
            signature.update(localSessionId.getBytes(StandardCharsets.UTF_8));

            Base64.Decoder urlDecoder = Base64.getUrlDecoder();

            if (!ByteIterator.ofBytes(urlDecoder.decode(parts[1].getBytes(StandardCharsets.UTF_8))).verify(signature)) {
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
            HttpsURLConnection secureConnection = (HttpsURLConnection) connection;
            this.logoutConnectionConfigurator.accept(secureConnection);
        }
    }
}
