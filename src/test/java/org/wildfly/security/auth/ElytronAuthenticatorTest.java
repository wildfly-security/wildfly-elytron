/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.auth;

import static org.junit.Assert.assertEquals;
import static org.wildfly.security.password.interfaces.ClearPassword.ALGORITHM_CLEAR;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.Authenticator;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.security.PrivilegedExceptionAction;
import java.security.spec.InvalidKeySpecException;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.wildfly.common.iteration.CodePointIterator;
import org.wildfly.security.auth.client.AuthenticationConfiguration;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.AuthenticationContextConfigurationClient;
import org.wildfly.security.auth.client.MatchRule;
import org.wildfly.security.auth.util.ElytronAuthenticator;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class ElytronAuthenticatorTest {

    private static final int SERVER_PORT = 50831;

    private MockWebServer server;

    @Before
    public void onBefore() throws Exception {
        server = new MockWebServer();

        server.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest recordedRequest) throws InterruptedException {
                String authorization = recordedRequest.getHeader("Authorization");
                if (authorization == null) {
                    return new MockResponse().setResponseCode(401).addHeader("WWW-Authenticate", "Basic realm=elytron.org");
                }
                return new MockResponse().setBody(authorization);
            }
        });

        server.start(SERVER_PORT);
    }

    @After
    public void onAfter() throws Exception {
        if (server != null) {
            server.shutdown();
        }
    }

    @Test
    public void testBasicAuthentication() throws Exception {
        String userName = "elytron";
        AuthenticationConfiguration configuration = AuthenticationConfiguration.empty().useName(userName);
        String userPassword = "dont_tell_me";
        AuthenticationContext context = AuthenticationContext.captureCurrent().with(MatchRule.ALL, configuration.usePassword(createPassword(configuration, userPassword)));
        String response = context.run((PrivilegedExceptionAction<String>) () -> {
            Authenticator.setDefault(new ElytronAuthenticator());
            HttpURLConnection connection = HttpURLConnection.class.cast(new URL("http://localhost:" + SERVER_PORT).openConnection());
            try (InputStream inputStream = connection.getInputStream()) {
                return new BufferedReader(new InputStreamReader(inputStream)).lines().findFirst().orElse(null);
            }
        });
        assertEquals("Basic " + CodePointIterator.ofString(userName + ":" + userPassword).asUtf8().base64Encode().drainToString(), response);
    }

    private Password createPassword(AuthenticationConfiguration configuration, String userPassword) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PasswordFactory factory = PasswordFactory.getInstance(ALGORITHM_CLEAR, AuthenticationContextConfigurationClient.ACTION.run().getProviderSupplier(configuration));
        return factory.generatePassword(new ClearPasswordSpec(userPassword.toCharArray()));
    }
}
