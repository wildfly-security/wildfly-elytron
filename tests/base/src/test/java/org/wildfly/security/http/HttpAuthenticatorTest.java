/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.http;

import static org.junit.Assert.assertEquals;
import static org.wildfly.security.http.HttpConstants.BASIC_NAME;
import static org.wildfly.security.http.HttpConstants.CONFIG_REALM;
import static org.wildfly.security.http.HttpConstants.DIGEST_NAME;
import static org.wildfly.security.http.HttpConstants.OK;
import static org.wildfly.security.http.HttpConstants.SHA256;
import static org.wildfly.security.http.HttpConstants.UNAUTHORIZED;

import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import javax.security.auth.callback.CallbackHandler;

import org.hamcrest.MatcherAssert;
import org.hamcrest.core.IsInstanceOf;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.security.auth.realm.SimpleMapBackedSecurityRealm;
import org.wildfly.security.auth.realm.SimpleRealmEntry;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.auth.server.event.SecurityAuthenticationFailedEvent;
import org.wildfly.security.auth.server.event.SecurityAuthenticationSuccessfulEvent;
import org.wildfly.security.auth.server.event.SecurityPermissionCheckSuccessfulEvent;
import org.wildfly.security.auth.server.event.SecurityEvent;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.http.digest.WildFlyElytronHttpDigestProvider;
import org.wildfly.security.http.impl.AbstractBaseHttpTest;
import org.wildfly.security.http.util.SecurityProviderServerMechanismFactory;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;

import mockit.integration.junit4.JMockit;

/**
 * Test of using multiple HTTP authentication mechanisms.
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
@RunWith(JMockit.class)
public class HttpAuthenticatorTest extends AbstractBaseHttpTest {

    private final TestingHttpExchangeSpi exchangeSpi = new TestingHttpExchangeSpi();
    private HttpAuthenticator authenticator;
    private final String digestHeader = "Digest username=\"Mufasa\",\n" +
            "       realm=\"http-auth@example.org\",\n" +
            "       uri=\"/dir/index.html\",\n" +
            "       algorithm=MD5,\n" +
            "       nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\",\n" +
            "       nc=00000001,\n" +
            "       cnonce=\"f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ\",\n" +
            "       qop=auth,\n" +
            "       response=\"8ca523f5e9506fed4657c9700eebdbec\",\n" +
            "       opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\"";
    private final String digestSha256Header = "Digest username=\"Mufasa\",\n"
            + "       realm=\"http-auth@example.org\",\n"
            + "       uri=\"/dir/index.html\",\n"
            + "       algorithm=SHA-256,\n"
            + "       nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\",\n"
            + "       nc=00000001,\n"
            + "       cnonce=\"f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ\",\n"
            + "       qop=auth,\n"
            + "       response=\"753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1\",\n"
            + "       opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\"";

    private static final Provider provider = WildFlyElytronPasswordProvider.getInstance();

    @BeforeClass
    public static void registerPasswordProvider() {
        Security.insertProviderAt(provider, 1);
    }

    @AfterClass
    public static void removePasswordProvider() {
        Security.removeProvider(provider.getName());
    }

    private CallbackHandler callbackHandler() {
        return getCallbackHandler("Mufasa", "http-auth@example.org", "Circle of Life");
    }

    private void testOneOfThree() throws Exception {
        mockDigestNonce("7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v");

        Map<String, Object> digestProps = new HashMap<>();
        digestProps.put(CONFIG_REALM, "http-auth@example.org");
        digestProps.put("org.wildfly.security.http.validate-digest-uri", "false");

        CallbackHandler callbackHandler = callbackHandler();

        final List<HttpServerAuthenticationMechanism> mechanisms = new LinkedList<>();
        mechanisms.add(digestFactory.createAuthenticationMechanism(DIGEST_NAME, digestProps, callbackHandler));
        mechanisms.add(basicFactory.createAuthenticationMechanism(BASIC_NAME, Collections.emptyMap(), callbackHandler));
        mechanisms.add(digestFactory.createAuthenticationMechanism(DIGEST_NAME + "-" + SHA256, digestProps, callbackHandler));

        authenticator = HttpAuthenticator.builder()
                .setMechanismSupplier(() -> mechanisms)
                .setHttpExchangeSpi(exchangeSpi)
                .setRequired(true)
                .build();
        Assert.assertFalse(authenticator.authenticate());

        List<String> responses = exchangeSpi.getResponseAuthenticateHeaders();
        assertEquals("All three mechanisms provided authenticate response", 3, responses.size());
        Assert.assertEquals(UNAUTHORIZED, exchangeSpi.getStatusCode());
        Assert.assertEquals(null, exchangeSpi.getResult());
        exchangeSpi.setStatusCode(0);
    }

    private void authenticateWithDigestMD5() throws HttpAuthenticationException {
        exchangeSpi.setRequestAuthorizationHeaders(Collections.singletonList(digestHeader));
        Assert.assertTrue("Digest-MD5 successful", authenticator.authenticate());
        Assert.assertEquals(0, exchangeSpi.getStatusCode());
        Assert.assertEquals(Status.COMPLETE, exchangeSpi.getResult());
    }

    @Test
    public void testDigestMd5() throws Exception {
        testOneOfThree();
        authenticateWithDigestMD5();
    }

    @Test
    public void testBasic() throws Exception {
        testOneOfThree();

        exchangeSpi.setRequestAuthorizationHeaders(Collections.singletonList(
                "Basic TXVmYXNhOkNpcmNsZSBvZiBMaWZl"
        ));
        Assert.assertTrue("Basic successful", authenticator.authenticate());
        Assert.assertEquals(0, exchangeSpi.getStatusCode());
        Assert.assertEquals(Status.COMPLETE, exchangeSpi.getResult());
    }

    @Test
    public void testBasicCaseInsensitive() throws Exception {
        testOneOfThree();

        exchangeSpi.setRequestAuthorizationHeaders(Collections.singletonList(
                "BASIC TXVmYXNhOkNpcmNsZSBvZiBMaWZl"
        ));
        Assert.assertTrue("Basic successful", authenticator.authenticate());
        Assert.assertEquals(0, exchangeSpi.getStatusCode());
        Assert.assertEquals(Status.COMPLETE, exchangeSpi.getResult());
    }

    @Test
    public void testDigestSha256() throws Exception {
        testOneOfThree();

        exchangeSpi.setRequestAuthorizationHeaders(Collections.singletonList(digestSha256Header));
        Assert.assertTrue("Digest-SHA-256 successful", authenticator.authenticate());
        Assert.assertEquals(0, exchangeSpi.getStatusCode());
        Assert.assertEquals(Status.COMPLETE, exchangeSpi.getResult());
    }

    @Test
    public void testDigestSha256CaseInsensitive() throws Exception {
        testOneOfThree();

        exchangeSpi.setRequestAuthorizationHeaders(Collections.singletonList("DIGEST " + digestSha256Header.substring(7)));
        Assert.assertTrue("Digest-SHA-256 successful", authenticator.authenticate());
        Assert.assertEquals(0, exchangeSpi.getStatusCode());
        Assert.assertEquals(Status.COMPLETE, exchangeSpi.getResult());
    }

    public List<HttpServerAuthenticationMechanism> prepareBasicSilentMechanisms() throws Exception {
        mockDigestNonce("7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v");

        final List<HttpServerAuthenticationMechanism> mechanisms = new LinkedList<>();
        Map<String, Object> silentProp = new HashMap<>();
        silentProp.put("silent", "true");
        mechanisms.add(basicFactory.createAuthenticationMechanism(BASIC_NAME, silentProp, callbackHandler()));
        authenticator = HttpAuthenticator.builder()
                .setMechanismSupplier(() -> mechanisms)
                .setHttpExchangeSpi(exchangeSpi)
                .setRequired(true)
                .build();

        return mechanisms;
    }

    public void prepareSilentBasicWithDigestMechanisms() throws Exception {
        List<HttpServerAuthenticationMechanism> mechanisms = prepareBasicSilentMechanisms();
        Map<String, Object> digestProps = new HashMap<>();
        digestProps.put(CONFIG_REALM, "http-auth@example.org");
        digestProps.put("org.wildfly.security.http.validate-digest-uri", "false");

        mechanisms.add(digestFactory.createAuthenticationMechanism(DIGEST_NAME, digestProps, callbackHandler()));
        authenticator = HttpAuthenticator.builder()
                .setMechanismSupplier(() -> mechanisms)
                .setHttpExchangeSpi(exchangeSpi)
                .setRequired(true)
                .build();
    }

    @Test
    public void testBasicSilent() throws Exception {
        prepareBasicSilentMechanisms();

        Assert.assertFalse(authenticator.authenticate());
        List<String> responses = exchangeSpi.getResponseAuthenticateHeaders();
        assertEquals("Basic authentication with silent mode does not send challenge if AUTHORIZATION header is not present", 0, responses.size());
        Assert.assertEquals(OK, exchangeSpi.getStatusCode());

        exchangeSpi.setRequestAuthorizationHeaders(Collections.singletonList(
                "Basic "    // empty credentials
        ));
        Assert.assertFalse(authenticator.authenticate());
        responses = exchangeSpi.getResponseAuthenticateHeaders();
        assertEquals("Basic authentication with silent mode sends challenge when AUTHORIZATION header is present", 1, responses.size());
        Assert.assertEquals(UNAUTHORIZED, exchangeSpi.getStatusCode());

        exchangeSpi.setRequestAuthorizationHeaders(Collections.singletonList(
                "Basic TXVmYXNhOkNpcmNsZSBvZiBMaWZl"
        ));
        Assert.assertTrue("Basic auth successful", authenticator.authenticate());
        Assert.assertEquals(Status.COMPLETE, exchangeSpi.getResult());
    }

    @Test
    public void testBasicSilentWithDigest() throws Exception {
        // authenticate using only DIGEST mechanism
        prepareSilentBasicWithDigestMechanisms();
        authenticateWithDigestMD5();
    }

    public void prepareSecurityProviderServerMechanismWithDigestMD5() throws Exception {
        mockDigestNonce("7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v");

        final List<HttpServerAuthenticationMechanism> mechanisms = new LinkedList<>();
        Map<String, Object> digestProps = new HashMap<>();
        digestProps.put(CONFIG_REALM, "http-auth@example.org");
        digestProps.put("org.wildfly.security.http.validate-digest-uri", "false");
        HttpServerAuthenticationMechanismFactory fact = new SecurityProviderServerMechanismFactory(WildFlyElytronHttpDigestProvider.getInstance());
        mechanisms.add(fact.createAuthenticationMechanism(DIGEST_NAME, digestProps, callbackHandler()));

        authenticator = HttpAuthenticator.builder()
                .setMechanismSupplier(() -> mechanisms)
                .setHttpExchangeSpi(exchangeSpi)
                .setRequired(true)
                .build();
    }

    @Test
    public void testUsingSecurityProviderServerMechanismWithDigestMD5() throws Exception {
        prepareSecurityProviderServerMechanismWithDigestMD5();

        Assert.assertFalse(authenticator.authenticate());
        List<String> responses = exchangeSpi.getResponseAuthenticateHeaders();
        assertEquals("DIGEST response is received", 1, responses.size());
        Assert.assertEquals(UNAUTHORIZED, exchangeSpi.getStatusCode());
        Assert.assertEquals(null, exchangeSpi.getResult());
        exchangeSpi.setStatusCode(0);

        authenticateWithDigestMD5();
    }

    @Test
    public void testLoginInSecurityDomain() throws Exception {
        SimpleMapBackedSecurityRealm usersRealm = new SimpleMapBackedSecurityRealm();
        usersRealm.setIdentityMap(Collections.singletonMap("Mufasa",
                new SimpleRealmEntry(Collections.singletonList(new PasswordCredential(
                        PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR).generatePassword(
                                new ClearPasswordSpec("Circle of Life".toCharArray())))))));
        List<SecurityEvent> events = new ArrayList<>();
        Consumer<SecurityEvent> listener = event -> events.add(event);
        SecurityDomain secDomain = SecurityDomain.builder()
                .addRealm("http-auth@example.org", usersRealm).build()
                .setDefaultRealmName("http-auth@example.org")
                .setPermissionMapper((permissionMappable, roles) -> LoginPermission.getInstance())
                .setSecurityEventListener(listener)
                .build();

        authenticator = HttpAuthenticator.builder()
                .setHttpExchangeSpi(exchangeSpi)
                .setSecurityDomain(secDomain)
                .build();

        SecurityIdentity identity = authenticator.login("Mufasa", "wrong-password");
        Assert.assertNull(identity);
        Assert.assertEquals(1, events.size());
        MatcherAssert.assertThat(events.get(0), IsInstanceOf.instanceOf(SecurityAuthenticationFailedEvent.class));
        Assert.assertEquals("Mufasa", ((SecurityAuthenticationFailedEvent) events.get(0)).getPrincipal().getName());

        events.clear();

        identity = authenticator.login("Mufasa", "Circle of Life");
        Assert.assertNotNull(identity);
        Assert.assertEquals(2, events.size());
        MatcherAssert.assertThat(events.get(0), IsInstanceOf.instanceOf(SecurityPermissionCheckSuccessfulEvent.class));
        Assert.assertEquals("Mufasa", ((SecurityPermissionCheckSuccessfulEvent) events.get(0)).getSecurityIdentity().getPrincipal().getName());
        MatcherAssert.assertThat(((SecurityPermissionCheckSuccessfulEvent) events.get(0)).getPermission(), IsInstanceOf.instanceOf(LoginPermission.class));
        MatcherAssert.assertThat(events.get(1), IsInstanceOf.instanceOf(SecurityAuthenticationSuccessfulEvent.class));
        Assert.assertEquals("Mufasa", ((SecurityAuthenticationSuccessfulEvent) events.get(1)).getSecurityIdentity().getPrincipal().getName());
    }
}
