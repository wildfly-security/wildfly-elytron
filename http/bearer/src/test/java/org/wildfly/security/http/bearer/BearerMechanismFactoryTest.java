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

package org.wildfly.security.http.bearer;


import org.junit.Test;
import org.junit.Assert;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;

import javax.security.auth.callback.CallbackHandler;
import java.util.HashMap;

import static org.wildfly.security.http.HttpConstants.BASIC_NAME;
import static org.wildfly.security.http.HttpConstants.BEARER_TOKEN;

/**
 * This test class contains unit tests for the {@link BearerMechanismFactory}.
 *
 * @author Marek Jusko
 */
public class BearerMechanismFactoryTest {

    private final BearerMechanismFactory bearerMechanismFactory = new BearerMechanismFactory();
    private final HashMap<String,String> emptyProperties = new HashMap<>();

    CallbackHandler dummyCallbackHandler = callbacks -> {};

    /**
     * Unit test for the {@link BearerMechanismFactory#getMechanismNames} method with a {@code null} properties map.
     * Verifies that the method returns a non-null array containing the Bearer mechanism name.
     */
    @Test
    public void testGetMechanismNamesWithNullProperties() {
        BearerMechanismFactory factory = new BearerMechanismFactory();
        String[] mechanismNames = factory.getMechanismNames(null);

        Assert.assertNotNull("Array of mechanism names cannot be null.", mechanismNames);
        Assert.assertEquals(1, mechanismNames.length);
        Assert.assertEquals(BEARER_TOKEN, mechanismNames[0]);
    }

    /**
     * Unit test for the {@link BearerMechanismFactory#getMechanismNames} method with an empty properties map.
     * Verifies that the method returns a non-null array containing the Bearer mechanism name.
     */
    @Test
    public void testGetMechanismNamesWithEmptyProperties() {
        BearerMechanismFactory factory = new BearerMechanismFactory();
        String[] mechanismNames = factory.getMechanismNames(emptyProperties);

        Assert.assertNotNull("Array of mechanism names cannot be null.", mechanismNames);
        Assert.assertEquals(1, mechanismNames.length);
        Assert.assertEquals(BEARER_TOKEN, mechanismNames[0]);
    }

    /**
     * Verifies that creating an authentication mechanism with a null mechanism name results in an IllegalArgumentException.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testCreateAuthenticationMechanismMechanismNameNull() throws HttpAuthenticationException {
        bearerMechanismFactory.createAuthenticationMechanism(null, emptyProperties, dummyCallbackHandler);
        Assert.fail("IllegalArgumentException expected for null mechanismName.");
    }

    /**
     * Verifies that creating an authentication mechanism with null properties results in an IllegalArgumentException.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testCreateAuthenticationMechanismPropertiesNull() throws HttpAuthenticationException {
        bearerMechanismFactory.createAuthenticationMechanism(BEARER_TOKEN, null, dummyCallbackHandler);
        Assert.fail("IllegalArgumentException expected for null properties.");
    }

    /**
     * Verifies that creating an authentication mechanism with a null callback handler results in an IllegalArgumentException.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testCreateAuthenticationMechanismCallbackHandlerNull() throws HttpAuthenticationException {
        bearerMechanismFactory.createAuthenticationMechanism(BEARER_TOKEN, emptyProperties, null);
        Assert.fail("IllegalArgumentException expected for null callbackHandler.");
    }

    /**
     * Verifies that creating an authentication mechanism with the BASIC mechanism name returns null.
     */
    @Test
    public void testCreateAuthenticationMechanismBasicMechanismName() throws HttpAuthenticationException {
        HttpServerAuthenticationMechanism mechanism = bearerMechanismFactory.createAuthenticationMechanism(BASIC_NAME, emptyProperties, dummyCallbackHandler);
        Assert.assertNull("Expected null mechanism for the BASIC mechanism name.", mechanism);
    }

    /**
     * Verifies that creating an authentication mechanism with an incorrect mechanism name returns null.
     */
    @Test
    public void testCreateAuthenticationMechanismIncorrectMechanismName() throws HttpAuthenticationException {
        HttpServerAuthenticationMechanism mechanism = bearerMechanismFactory.createAuthenticationMechanism("INCORRECT_NAME", emptyProperties, dummyCallbackHandler);
        Assert.assertNull("Expected null mechanism for an incorrect mechanism name.", mechanism);
    }

    /**
     * Tests that creating a Bearer authentication mechanism with valid parameters returns a non-null mechanism.
     */
    @Test
    public void testCreateValidBearerAuthenticationMechanism() throws HttpAuthenticationException{
        HttpServerAuthenticationMechanism httpServerAuthenticationMechanism = bearerMechanismFactory.createAuthenticationMechanism(BEARER_TOKEN, emptyProperties, dummyCallbackHandler);
        Assert.assertNotNull("HttpServerAuthenticationMechanism cannot be null.",httpServerAuthenticationMechanism);
    }

}
