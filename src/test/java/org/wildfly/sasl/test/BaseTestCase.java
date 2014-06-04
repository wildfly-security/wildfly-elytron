/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2011, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.wildfly.sasl.test;

import static org.junit.Assert.assertEquals;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.Security;
import java.util.Enumeration;

import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslServerFactory;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.wildfly.sasl.WildFlySaslProvider;

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


}
