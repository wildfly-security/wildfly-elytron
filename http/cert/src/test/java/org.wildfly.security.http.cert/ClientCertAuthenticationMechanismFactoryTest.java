/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2024 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.http.cert;

import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import org.junit.Assert;
import org.junit.Test;

public class ClientCertAuthenticationMechanismFactoryTest {
    private HttpServerAuthenticationMechanismFactory clientCertMechanismFactory = new ClientCertMechanismFactory();

    CallbackHandler dummyCallbackHandler = new CallbackHandler() {
        @Override
        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        }
    };

    /**
     * Tests that {@link ServerMechanismFactoryImpl#getMechanismNames(Map)} correctly
     * handles null or empty properties parameter as possible value.
     */
    @Test
    public void testGetMechanismNamesPropertiesNull() {
        clientCertMechanismFactory.getMechanismNames(null);
        clientCertMechanismFactory.getMechanismNames(new HashMap<String, String>());
    }

    /**
     * Tests that {@link ServerMechanismFactoryImpl#getMechanismNames(Map)} does not return null.
     */
    @Test
    public void testGetMechanismNamesReturnNotNull() {
        String[] mechanismNames = clientCertMechanismFactory.getMechanismNames(null);
        Assert.assertNotNull("Array of mechanism names is not null.", mechanismNames);
    }

    /**
     * Tests that {@link ServerMechanismFactoryImpl#createAuthenticationMechanism(String, Map, javax.security.auth.callback.CallbackHandler)}
     * does handle null mechanism name parameter correctly - does not allow.
     * @throws HttpAuthenticationException
     */
    @Test
    public void testCreateAuthenticationMechanismMechanismNameNull() throws HttpAuthenticationException {
        try {
            clientCertMechanismFactory.createAuthenticationMechanism(null, new HashMap<String,String>(), dummyCallbackHandler);
            Assert.fail("Mechanism name could not be null");
        } catch (IllegalArgumentException e) {
            // OK - expected exception state
        }
    }

    /**
     * Tests that {@link ServerMechanismFactoryImpl#createAuthenticationMechanism(String, Map, javax.security.auth.callback.CallbackHandler)}
     * does handle null properties parameter correctly - does not allow.
     */
    @Test
    public void testCreateAuthenticationMechanismPropertiesNull() throws HttpAuthenticationException {
        try {
            clientCertMechanismFactory.createAuthenticationMechanism("CLIENT_CERT", null, dummyCallbackHandler);
            Assert.fail("Properties could not be null");
        } catch (IllegalArgumentException e) {
            // OK - expected exception state
        }
    }

    /**
     * Tests that {@link ServerMechanismFactoryImpl#createAuthenticationMechanism(String, Map, javax.security.auth.callback.CallbackHandler)}
     * does handle wrong mechanism ("BASIC") - returns null.
     */
    @Test
    public void testCreateAuthenticationMechanismBasicMechanismName() throws HttpAuthenticationException{
        HttpServerAuthenticationMechanism httpServerAuthenticationMechanism = clientCertMechanismFactory.createAuthenticationMechanism("BASIC",new HashMap<String,String>(),dummyCallbackHandler);
        Assert.assertNull("Provided mechanism must be null.", httpServerAuthenticationMechanism);
    }

    /**
     * Tests that {@link ServerMechanismFactoryImpl#createAuthenticationMechanism(String, Map, javax.security.auth.callback.CallbackHandler)}
     * does handle null properties parameter correctly - does not allow.
     */
    @Test
    public void testCreateAuthenticationMechanismCallbackHandlerNull() throws HttpAuthenticationException {
        try {
            clientCertMechanismFactory.createAuthenticationMechanism("CLIENT_CERT", new HashMap<String,String>(), null);
            Assert.fail("CallbackHandler could not be null");
        } catch (IllegalArgumentException e) {
            // OK - expected exception state
        }
    }

    /**
     * Tests that {@link ServerMechanismFactoryImpl#createAuthenticationMechanism(String, Map, javax.security.auth.callback.CallbackHandler)}
     * does handle wrong mechanism name correctly - returns null.
     */
    @Test
    public void testCreateAuthenticationMechanismWrongMechanismName() throws HttpAuthenticationException {
        HttpServerAuthenticationMechanism httpServerAuthenticationMechanism = clientCertMechanismFactory.createAuthenticationMechanism("MECHANISM_NAME_DOES_NOT_EXISTS", new HashMap<String,String>(), dummyCallbackHandler);
        Assert.assertNull("Provided mechanism must be null.", httpServerAuthenticationMechanism);
    }
}
