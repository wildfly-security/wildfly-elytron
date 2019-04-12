/*
 * JBoss, Home of Professional Open Source
 * Copyright 2015 Red Hat, Inc., and individual contributors
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

import static org.junit.Assert.*;
import static org.wildfly.security.password.interfaces.ClearPassword.ALGORITHM_CLEAR;

import java.security.Provider;
import java.security.Security;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;

/**
 * Tests for the {@link ClearPassword} implementation.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class ClearPasswordTest {

    private static final Provider provider = WildFlyElytronPasswordProvider.getInstance();

    @BeforeClass
    public static void registerProvider() {
        Security.addProvider(provider);
    }

    @AfterClass
    public static void removeProvider() {
        Security.removeProvider(provider.getName());
    }

    @Test
    public void testEmptyPassword() throws Exception {
        performTest("");
    }

    @Test
    public void testNonEmptyPassword() throws Exception {
        performTest("p4ssw0rd!");
    }

    private void performTest(final String correctPassword) throws Exception {
        PasswordFactory factory = PasswordFactory.getInstance(ALGORITHM_CLEAR);
        ClearPasswordSpec spec = new ClearPasswordSpec(correctPassword.toCharArray());

        ClearPassword password = (ClearPassword) factory.generatePassword(spec);
        assertTrue("Password validation", factory.verify(password, correctPassword.toCharArray()));
        assertFalse("Bad password rejection", factory.verify(password, "badpassword".toCharArray()));

        assertTrue("Convertible to key spec", factory.convertibleToKeySpec(password, ClearPasswordSpec.class));
        ClearPasswordSpec clearSpec = factory.getKeySpec(password, ClearPasswordSpec.class);
        assertArrayEquals(correctPassword.toCharArray(), clearSpec.getEncodedPassword());
    }
}
