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

import org.junit.Assert;
import org.junit.Test;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.AuthenticationContextConfigurationClient;
import org.wildfly.security.auth.client.ElytronXmlParser;
import org.wildfly.security.auth.client.InvalidAuthenticationConfigurationException;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;
import org.wildfly.security.http.bearer.BearerMechanismFactory;
import org.wildfly.security.http.client.mechanism.bearer.ElytronHttpClientBearerAuthMechanism;
import org.wildfly.security.http.impl.AbstractBaseHttpTest;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;

import static java.security.AccessController.doPrivileged;
import static org.wildfly.security.http.HttpConstants.FORBIDDEN;
import static org.wildfly.security.http.HttpConstants.UNAUTHORIZED;

import java.net.URI;
import java.net.URL;
import java.net.http.HttpRequest;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.util.HashMap;
import java.util.function.Supplier;

/**
 * Test for the ElytronHttpClient class
 *
 * @author <a href="mailto:kekumar@redhat.com">Keshav Kumar</a>
 */
public class ElytronHttpClientBearerTest extends AbstractBaseHttpTest {

    public static Supplier<Provider[]> ELYTRON_PASSWORD_PROVIDERS = () -> new Provider[]{
            WildFlyElytronPasswordProvider.getInstance()
    };
    protected HttpServerAuthenticationMechanismFactory bearerFactory = new BearerMechanismFactory(ELYTRON_PASSWORD_PROVIDERS.get());
    private ElytronHttpClient elytronHttpClient = new ElytronHttpClient();

    @Test
    public void testElytonHttpClientDigestAuthenticationMechanismAuthorizedUser() {
        AuthenticationContextConfigurationClient AUTH_CONTEXT_CLIENT =
                doPrivileged((PrivilegedAction<AuthenticationContextConfigurationClient>) AuthenticationContextConfigurationClient::new);

        AuthenticationContext context = doPrivileged((PrivilegedAction<AuthenticationContext>) () -> {
            try {
                URL config = getClass().getResource("wildfly-config-http-client-bearer.xml");
                return ElytronXmlParser.parseAuthenticationClientConfiguration(config.toURI()).create();
            } catch (Throwable t) {
                throw new InvalidAuthenticationConfigurationException(t);
            }
        });
        context.run(() -> {
            try {
                URI uri = new URI("http://localhost:8080/hello");
                HttpServerAuthenticationMechanism mechanism = bearerFactory.createAuthenticationMechanism("BEARER_TOKEN", new HashMap<>(),getCallbackHandler("authorizedUser", "RealmUsersRoles", "password", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaXNzIjoiYXV0aC5zZXJ2ZXIiLCJhdWQiOiJmb3JfbWUiLCJleHAiOjE3NjA5OTE2MzUsInByZWZlcnJlZF91c2VybmFtZSI6Impkb2UifQ.SoPW41_mOFnKXdkwVG63agWQ2k09dEnEtTBztnxHN64"));
                HttpRequest request = ElytronHttpClientBearerAuthMechanism.evaluateMechanism(uri);

                //Test successful authentication
                TestingHttpServerRequest testingHttpServerRequest = new TestingHttpServerRequest(new String[]{request.headers().allValues("Authorization").get(0)});
                mechanism.evaluateRequest(testingHttpServerRequest);
                Assert.assertEquals(Status.COMPLETE,testingHttpServerRequest.getResult());
            }catch (Exception e){
                throw new RuntimeException(e);
            }
        });
    }

    @Test
    public void testElytonHttpClientDigestAuthenticationMechanismUnauthorizedUser() {
        AuthenticationContextConfigurationClient AUTH_CONTEXT_CLIENT =
                doPrivileged((PrivilegedAction<AuthenticationContextConfigurationClient>) AuthenticationContextConfigurationClient::new);

        AuthenticationContext context = doPrivileged((PrivilegedAction<AuthenticationContext>) () -> {
            try {
                URL config = getClass().getResource("wildfly-config-http-client-bearer.xml");
                return ElytronXmlParser.parseAuthenticationClientConfiguration(config.toURI()).create();
            } catch (Throwable t) {
                throw new InvalidAuthenticationConfigurationException(t);
            }
        });
        context.run(() -> {
            try {
                URI uri = new URI("http://localhost:8080/hello");
                HttpServerAuthenticationMechanism mechanism = bearerFactory.createAuthenticationMechanism("BEARER_TOKEN", new HashMap<>(),getCallbackHandler("unauthorizedUser", "RealmUsersRoles", "password", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaXNzIjoiYXV0aC5zZXJ2ZXIiLCJhdWQiOiJmb3JfbWUiLCJleHAiOjE3NjA5OTE2MzUsInByZWZlcnJlZF91c2VybmFtZSI6Impkb2UifQ.SoPW41_mOFnKXdkwVG63agWQ2k09dEnEtTBztnxHN64"));
                HttpRequest request = ElytronHttpClientBearerAuthMechanism.evaluateMechanism(uri);

                //Test successful authentication
                TestingHttpServerRequest testingHttpServerRequest = new TestingHttpServerRequest(new String[]{request.headers().allValues("Authorization").get(0)});
                mechanism.evaluateRequest(testingHttpServerRequest);
                Assert.assertEquals(Status.FAILED,testingHttpServerRequest.getResult());
                Assert.assertEquals(FORBIDDEN, testingHttpServerRequest.getResponse().getStatusCode());
            }catch (Exception e){
                throw new RuntimeException(e);
            }
        });
    }

    @Test
    public void testElytonHttpClientDigestAuthenticationMechanismInvalidToken() {
        AuthenticationContextConfigurationClient AUTH_CONTEXT_CLIENT =
                doPrivileged((PrivilegedAction<AuthenticationContextConfigurationClient>) AuthenticationContextConfigurationClient::new);

        AuthenticationContext context = doPrivileged((PrivilegedAction<AuthenticationContext>) () -> {
            try {
                URL config = getClass().getResource("wildfly-config-http-client-bearer.xml");
                return ElytronXmlParser.parseAuthenticationClientConfiguration(config.toURI()).create();
            } catch (Throwable t) {
                throw new InvalidAuthenticationConfigurationException(t);
            }
        });
        context.run(() -> {
            try {
                URI uri = new URI("http://localhost:8080/hello");
                HttpServerAuthenticationMechanism mechanism = bearerFactory.createAuthenticationMechanism("BEARER_TOKEN", new HashMap<>(),getCallbackHandler("unauthorizedUser", "RealmUsersRoles", "password", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaXNzIjoiYXV0aC5zZXJ2ZXIiLCJhdWQiOiJmb3JfbWUiLCJleHAiOjE3NjA5OTE2MzUsInByZWZlcnJlZF91c2VybmFtZSI6Impkb2UifQ.SoPW41_mOFnKXdkwVG63agWQ2k09dEnEtTBzt"));
                HttpRequest request = ElytronHttpClientBearerAuthMechanism.evaluateMechanism(uri);

                //Test successful authentication
                TestingHttpServerRequest testingHttpServerRequest = new TestingHttpServerRequest(new String[]{request.headers().allValues("Authorization").get(0)});
                mechanism.evaluateRequest(testingHttpServerRequest);
                Assert.assertEquals(Status.FAILED,testingHttpServerRequest.getResult());
                Assert.assertEquals(UNAUTHORIZED, testingHttpServerRequest.getResponse().getStatusCode());
            }catch (Exception e){
                throw new RuntimeException(e);
            }
        });
    }
}