/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2024 Red Hat, Inc., and individual contributors
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

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/*
    Verify that invalid logout config options values are flagged.
 */
public class LogoutConfigurationOptionsTest {
    private OidcJsonConfiguration oidcJsonConfiguration;

    @Before
    public void before() {
        oidcJsonConfiguration = new OidcJsonConfiguration();
        // minimum required options
        oidcJsonConfiguration.setRealm("realm");
        oidcJsonConfiguration.setResource("resource");
        oidcJsonConfiguration.setClientId("clientId");
        oidcJsonConfiguration.setAuthServerUrl("AuthServerUrl");
    }

    @After
    public void after() {
        System.clearProperty(Oidc.LOGOUT_PATH);
        System.clearProperty(Oidc.LOGOUT_CALLBACK_PATH);
        System.clearProperty(Oidc.POST_LOGOUT_PATH);
    }

    @Test
    public void testLogoutPath() {

        try {
            System.setProperty(Oidc.LOGOUT_PATH, " ");
             OidcClientConfigurationBuilder.build(oidcJsonConfiguration);
             fail("Empty " +Oidc.LOGOUT_PATH+ " is invalid");
        } catch (Exception e) {
            assertTrue(e.getMessage().endsWith(Oidc.LOGOUT_PATH));
        }

        try {
            System.setProperty(Oidc.LOGOUT_PATH, "/");
            OidcClientConfigurationBuilder.build(oidcJsonConfiguration);
            fail("/ in " +Oidc.LOGOUT_PATH+ " is invalid");
        } catch (Exception e) {
            assertTrue(e.getMessage().endsWith(Oidc.LOGOUT_PATH));
        }
    }

    @Test
    public void testCallbackLogoutPath() {

        try {
            System.setProperty(Oidc.LOGOUT_CALLBACK_PATH, " ");
            OidcClientConfigurationBuilder.build(oidcJsonConfiguration);
            fail("Empty " + Oidc.LOGOUT_CALLBACK_PATH + " is invalid");
        } catch (Exception e) {
            assertTrue(e.getMessage().endsWith(Oidc.LOGOUT_CALLBACK_PATH));
        }

        try {
            System.setProperty(Oidc.LOGOUT_CALLBACK_PATH, "/");
            OidcClientConfigurationBuilder.build(oidcJsonConfiguration);
            fail("/ in " + Oidc.LOGOUT_CALLBACK_PATH + " is invalid");
        } catch (Exception e) {
            assertTrue(e.getMessage().endsWith(Oidc.LOGOUT_CALLBACK_PATH));
        }

        try {
            System.setProperty(Oidc.LOGOUT_PATH, "/mylogout");
            System.setProperty(Oidc.LOGOUT_CALLBACK_PATH, "/more/mylogout");
            OidcClientConfigurationBuilder.build(oidcJsonConfiguration);
            fail("Identical paths is invalid");
        } catch (Exception e) {
            assertTrue(e.getMessage().contains("ELY23072"));
        }
    }

    @Test
    public void testPostLogoutPath() {

        try {
            System.setProperty(Oidc.POST_LOGOUT_PATH, " ");
            OidcClientConfigurationBuilder.build(oidcJsonConfiguration);
            fail("Empty " +Oidc.POST_LOGOUT_PATH+ " is invalid");
        } catch (Exception e) {
            assertTrue(e.getMessage().endsWith(Oidc.POST_LOGOUT_PATH));
        }

        try {
            System.setProperty(Oidc.POST_LOGOUT_PATH, "/");
            OidcClientConfigurationBuilder.build(oidcJsonConfiguration);
            fail("/ in " + Oidc.POST_LOGOUT_PATH + " is invalid");
        } catch (Exception e) {
            assertTrue(e.getMessage().endsWith(Oidc.POST_LOGOUT_PATH));
        }
    }
}
