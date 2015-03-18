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
package org.wildfly.security.sasl.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.Enumeration;

import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslServerFactory;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.wildfly.security.sasl.WildFlySaslProvider;

/**
 * A base for the test cases to ensure the provider is registered before the test
 * is executed and removed after the test completes.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class BaseTestCase {

    private static final Provider wildFlySaslProvider = new WildFlySaslProvider();

    @BeforeClass
    public static void registerProvider() {
        AccessController.doPrivileged(new PrivilegedAction<Integer>() {
            public Integer run() {
                return Security.insertProviderAt(wildFlySaslProvider, 1);
            }
        });
    }

    @AfterClass
    public static void removeProvider() {
        AccessController.doPrivileged(new PrivilegedAction<Void>() {
            public Void run() {
                Security.removeProvider(wildFlySaslProvider.getName());

                return null;
            }
        });
    }

    // Utility methods for use by the Test classes.

    /**
     * Obtain the first registered SaslServerFactory of the specified class.
     * <p/>
     * Although we could obtain the server factory directly ourselves this also
     * verifies that it can be found from the registrations.
     *
     * @param requiredServerFactory - The server factory we are looking for.
     * @return the located server factory.
     */
    protected SaslServerFactory obtainSaslServerFactory(final Class requiredServerFactory) {
        Enumeration<SaslServerFactory> serverFactories = Sasl.getSaslServerFactories();
        while (serverFactories.hasMoreElements()) {
            SaslServerFactory current = serverFactories.nextElement();
            if (current.getClass().equals(requiredServerFactory)) {
                return current;
            }
        }

        return null;
    }

    /**
     * Obtain the first registered SaslClientFactory of the specified class.
     * <p/>
     * Although we could obtain the client factory directly ourselves this also
     * verifies that it can be found from the registrations.
     *
     * @param requiredClientFactory - The client factory we are looking for.
     * @return the located client factory.
     */
    protected SaslClientFactory obtainSaslClientFactory(final Class requiredClientFactory) {
        Enumeration<SaslClientFactory> clientFactories = Sasl.getSaslClientFactories();
        while (clientFactories.hasMoreElements()) {
            SaslClientFactory current = clientFactories.nextElement();
            if (current.getClass().equals(requiredClientFactory)) {
                return current;
            }
        }

        return null;
    }

    /**
     * Verify that no mechanisms have been specified in the array.
     *
     * @param mechanisms - the array of mechanisms to verify.
     */
    protected void assertNoMechanisms(final String[] mechanisms) {
        assertEquals(0, mechanisms.length);
    }

    /**
     * @param mechanismName
     * @param mechanisms
     */
    protected void assertSingleMechanism(final String mechanismName, final String[] mechanisms) {
        assertEquals(1, mechanisms.length);
        assertEquals(mechanismName, mechanisms[0]);
    }

    /**
     * Verify the array of mechanisms.
     *
     * @param expectedMechanisms the expected array of mechanisms
     * @param mechanisms the array of mechanisms to verify
     */
    protected void assertMechanisms(final String[] expectedMechanisms, final String[] mechanisms) {
        assertEquals(expectedMechanisms.length, mechanisms.length);
        assertTrue(Arrays.asList(expectedMechanisms).containsAll(Arrays.asList(mechanisms)));
    }
}
