/*
 * JBoss, Home of Professional Open Source
 * Copyright 2026 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.password.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.security.AlgorithmParameters;
import java.security.Provider;
import java.util.ServiceLoader;

import org.junit.Test;
import org.wildfly.security.ServiceImplementationFactory;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;

public class PasswordImplementationFactoryTest {

    private static final Provider PROVIDER = WildFlyElytronPasswordProvider.getInstance();

    @Test
    public void factoryIsRegisteredWithTheServiceLoader() {
        boolean found = false;
        for (ServiceImplementationFactory factory : ServiceLoader.load(ServiceImplementationFactory.class)) {
            found |= factory instanceof PasswordImplementationFactory;
        }
        assertTrue(found);
    }

    @Test
    public void factoryCreatesTheImplementationsOfThisModule() {
        PasswordImplementationFactory factory = new PasswordImplementationFactory();
        assertEquals(PasswordFactorySpiImpl.class, factory.newInstance(PasswordFactorySpiImpl.class.getName(), PROVIDER).getClass());
        assertEquals(DigestPasswordAlgorithmParametersSpiImpl.class, factory.newInstance(DigestPasswordAlgorithmParametersSpiImpl.class.getName(), PROVIDER).getClass());
        assertEquals(IteratedSaltedPasswordAlgorithmParametersSpiImpl.class, factory.newInstance(IteratedSaltedPasswordAlgorithmParametersSpiImpl.class.getName(), PROVIDER).getClass());
        assertEquals(MaskedPasswordAlgorithmParametersSpiImpl.class, factory.newInstance(MaskedPasswordAlgorithmParametersSpiImpl.class.getName(), PROVIDER).getClass());
        assertEquals(OneTimePasswordAlgorithmParametersSpiImpl.class, factory.newInstance(OneTimePasswordAlgorithmParametersSpiImpl.class.getName(), PROVIDER).getClass());
        assertEquals(SaltedPasswordAlgorithmParametersSpiImpl.class, factory.newInstance(SaltedPasswordAlgorithmParametersSpiImpl.class.getName(), PROVIDER).getClass());
        assertNull(factory.newInstance("org.wildfly.security.password.impl.Unknown", PROVIDER));
    }

    @Test
    public void providerServicesAreCreatedThroughTheFactory() throws Exception {
        for (Provider.Service service : PROVIDER.getServices()) {
            if (service.getClassName().startsWith("org.wildfly.security.password.impl.")) {
                assertTrue(service.getAlgorithm(), service.getClass().getName().endsWith("ProviderService"));
            }
        }
        assertEquals(PasswordFactorySpiImpl.class.getName(), PasswordFactory.getInstance("clear", PROVIDER).getProvider().getService("PasswordFactory", "clear").getClassName());
        assertEquals(PROVIDER, AlgorithmParameters.getInstance("masked-MD5-DES", PROVIDER).getProvider());
    }
}
