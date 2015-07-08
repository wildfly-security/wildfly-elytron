/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.auth;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.security.Provider;
import java.security.Security;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.WildFlyElytronProvider;
import org.wildfly.security.auth.provider.JaasSecurityRealm;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.auth.server.CredentialSupport;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;

/**
 * Testsuite for the {@link org.wildfly.security.auth.provider.JaasSecurityRealm}.
 *
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class JaasSecurityRealmTest {

    private static final Provider provider = new WildFlyElytronProvider();

    @BeforeClass
    public static void init() {
        Security.addProvider(provider);
        System.setProperty("java.security.auth.login.config", JaasSecurityRealmTest.class.getResource("login.config").toString());
    }

    @AfterClass
    public static void tearDown() {
        Security.removeProvider(provider.getName());
    }

    @Test
    public void testJaasSecurityRealm() throws Exception {

        // create a JAAS security realm with the default callback handler.
        SecurityRealm realm = new JaasSecurityRealm("test");

        // test the creation of a realm identity.
        RealmIdentity realmIdentity = realm.createRealmIdentity("elytron");
        assertNotNull("Unexpected null realm identity", realmIdentity);

        // check the supported credential types (the default handler can only handle char[], String and ClearPassword credentials)..
        assertEquals("Invalid credential support", CredentialSupport.VERIFIABLE_ONLY, realmIdentity.getCredentialSupport(char[].class));
        assertEquals("Invalid credential support", CredentialSupport.VERIFIABLE_ONLY, realmIdentity.getCredentialSupport(String.class));
        assertEquals("Invalid credential support", CredentialSupport.VERIFIABLE_ONLY, realmIdentity.getCredentialSupport(ClearPassword.class));
        assertEquals("Invalid credential support", CredentialSupport.UNSUPPORTED, realmIdentity.getCredentialSupport(Object.class));

        // the JAAS realm identity cannot be used to obtain credentials, so getCredential should always return null.
        assertNull("Invalid non null credential", realmIdentity.getCredential(char[].class));
        assertNull("Invalid non null credential", realmIdentity.getCredential(String.class));

        // use the realm identity to verify all supported credentials - this will trigger a JAAS login that will use the test module.
        assertTrue(realmIdentity.verifyCredential("passwd12#$"));
        assertTrue(realmIdentity.verifyCredential("passwd12#$".toCharArray()));
        ClearPassword clearPassword = (ClearPassword) PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR).
                generatePassword(new ClearPasswordSpec("passwd12#$".toCharArray()));
        assertTrue(realmIdentity.verifyCredential(clearPassword));
        assertFalse(realmIdentity.verifyCredential("wrongpass"));
        // the default handler can't handle an object credential, so even if an object contains the correct password it won't be processed.
        assertFalse(realmIdentity.verifyCredential(new Object() {
            @Override
            public String toString() {
                return "passwd12#$";
            }
        }));

        // get the authenticated realm identity after successfully verifying the credential.
        assertTrue(realmIdentity.verifyCredential("passwd12#$"));
        AuthorizationIdentity authRealmIdentity = realmIdentity.getAuthorizationIdentity();
        assertNotNull("Unexpected null authenticated realm identity", authRealmIdentity);
        // check if the authenticated identity returns the caller principal as set by the test login module.
//        Principal authPrincipal = authRealmIdentity.getPrincipal();
//        assertNotNull("Unexpected null principal", authPrincipal);
//        assertEquals("Invalid principal name", new NamePrincipal("auth-caller"), authPrincipal);

        // dispose the auth realm identity - should trigger a JAAS logout that clears the subject.
        // TODO - some other solution is needed here!  We can no longer force JAAS logout in an authorization scenario.
        //authPrincipal = authRealmIdentity.getPrincipal();
        // after the logout, the subject no longer contains a caller principal so the identity should return the same principal as the realm identity.
        //assertNotNull("Unexpected null principal", authPrincipal);
        //assertEquals("Invalid principal name", new NamePrincipal("elytron"), authPrincipal);

    }

    @Test
    public void testJaasSecurityRealmWithCustomCallbackHandler() throws Exception {

        // create a JAAS realm that takes a custom callback handler.
        SecurityRealm realm = new JaasSecurityRealm("test", new TestCallbackHandler());

        // create a new realm identity using the realm.
        RealmIdentity realmIdentity = realm.createRealmIdentity("javajoe");

        // as the custom handler might be able to handle different credential types, we should get a POSSIBLY_VERIFIABLE support for any type.
        assertEquals("Invalid credential support", CredentialSupport.POSSIBLY_VERIFIABLE, realmIdentity.getCredentialSupport(char[].class));
        assertEquals("Invalid credential support", CredentialSupport.POSSIBLY_VERIFIABLE, realmIdentity.getCredentialSupport(String.class));
        assertEquals("Invalid credential support", CredentialSupport.POSSIBLY_VERIFIABLE, realmIdentity.getCredentialSupport(ClearPassword.class));
        assertEquals("Invalid credential support", CredentialSupport.POSSIBLY_VERIFIABLE, realmIdentity.getCredentialSupport(Object.class));

        // verify the credentials using the custom callback handler.
        assertTrue(realmIdentity.verifyCredential("$#21pass".toCharArray()));
        // the custom callback will handle an object using its toString method.
        assertTrue(realmIdentity.verifyCredential(new Object() {
            @Override
            public String toString() {
                return "$#21pass";
            }
        }));
        assertFalse(realmIdentity.verifyCredential("wrongpass"));

    }
}