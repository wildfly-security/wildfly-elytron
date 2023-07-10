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

package org.wildfly.security.http.digest;

import org.junit.Assert;
import org.junit.Test;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;
import java.util.HashMap;

/**
 * Tests of DigestMechanismFactory Class.
 *
 * @author Keshav Kumar
 */

public class DigestMechanismFactoryTest {

    private DigestMechanismFactory digestMechanismFactory = new DigestMechanismFactory();

    CallbackHandler dummyCallbackHandler = new CallbackHandler() {
        @Override
        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        }
    };

    /**
     * Tests that getMechanismNames(Map) correctly
     * handles null or empty properties parameter as possible value.
     */
    @Test
    public void testGetMechanismNamesPropertiesNull(){
        String[] mechanismNames1 = digestMechanismFactory.getMechanismNames(null);
        Assert.assertNotNull("Array of mechanism names cannot be null.",mechanismNames1);

        String[] mechanismNames2 = digestMechanismFactory.getMechanismNames(new HashMap<String,String>());
        Assert.assertNotNull("Array of mechanism names cannot be null.",mechanismNames2);
    }

    /**
     * Tests that getMechanismNames(Map) does not return null.
     */
    @Test
    public void testGetMechanismNamesReturnNotNull(){
        String[] mechanismNames = digestMechanismFactory.getMechanismNames(null);
        Assert.assertNotNull("Array of mechanism names cannot be null.", mechanismNames);
    }

    /**
     * Tests that createAuthenticationMechanism(String, Map, javax.security.auth.callback.CallbackHandler)
     * does handle null mechanism name parameter correctly - does not allow.
     * @throws HttpAuthenticationException
     */
    @Test
    public void testCreateAuthenticationMechanismMechanismNameNull() throws HttpAuthenticationException{
        try {
            digestMechanismFactory.createAuthenticationMechanism(null,new HashMap<String,String>(),dummyCallbackHandler);
            Assert.fail("Mechanism name could not be null");
        }catch (IllegalArgumentException illegalArgumentException){
            // OK - expected exception state
        }
    }

    /**
     * Tests that {createAuthenticationMechanism(String, Map, javax.security.auth.callback.CallbackHandler)
     * does handle null properties parameter correctly - does not allow.
     */
    @Test
    public void testCreateAuthenticationMechanismPropertiesNull() throws HttpAuthenticationException{
        try {
            digestMechanismFactory.createAuthenticationMechanism("DIGEST",null,dummyCallbackHandler);
            Assert.fail("Properties could not be null");
        }catch (IllegalArgumentException illegalArgumentException){
            // OK - expected exception state
        }
    }

    /**
     * Tests that createAuthenticationMechanism(String, Map, javax.security.auth.callback.CallbackHandler)
     * does handle null callbackHandler parameter correctly - does not allow.
     */
    @Test
    public void testCreateAuthenticationMechanismCallbackHandlerNull() throws HttpAuthenticationException{
        try {
            digestMechanismFactory.createAuthenticationMechanism("DIGEST",new HashMap<String,String>(),null);
            Assert.fail("CallbackHandler could not be null");
        }catch (IllegalArgumentException illegalArgumentException){
            // OK - expected exception state
        }
    }

    /**
     * Tests that createAuthenticationMechanism(String, Map, javax.security.auth.callback.CallbackHandler)
     * does handle wrong mechanism ("BASIC") - returns null.
     */
    @Test
    public void testCreateAuthenticationMechanismBasicMechanismName() throws HttpAuthenticationException{
        HttpServerAuthenticationMechanism httpServerAuthenticationMechanism = digestMechanismFactory.createAuthenticationMechanism("BASIC",new HashMap<String,String>(),dummyCallbackHandler);
        Assert.assertNull("Provided mechanism must be null.", httpServerAuthenticationMechanism);
    }

    /**
     * Tests that createAuthenticationMechanism(String, Map, javax.security.auth.callback.CallbackHandler)
     * does handle all not null parameter correctly - does not return null.
     */
    @Test
    public void testCreateAuthenticationMechanismReturnNotNull() throws HttpAuthenticationException{
        HttpServerAuthenticationMechanism httpServerAuthenticationMechanism = digestMechanismFactory.createAuthenticationMechanism("DIGEST",new HashMap<String,String>(),dummyCallbackHandler);
        Assert.assertNotNull("HttpServerAuthenticationMechanism cannot be null.",httpServerAuthenticationMechanism);
    }

    /**
     * Tests that createAuthenticationMechanism(String, Map, javax.security.auth.callback.CallbackHandler)
     * does handle wrong mechanism name correctly - returns null.
     */
    @Test
    public void testCreateAuthenticationMechanismWrongMechanismName() throws HttpAuthenticationException{
        HttpServerAuthenticationMechanism httpServerAuthenticationMechanism = digestMechanismFactory.createAuthenticationMechanism("MECHANISM_NAME_DOES_NOT_EXISTS",new HashMap<String,String>(),dummyCallbackHandler);
        Assert.assertNull("Provided mechanism must be null.", httpServerAuthenticationMechanism);
    }
}
