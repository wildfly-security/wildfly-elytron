/*
 * JBoss, Home of Professional Open Source
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

package org.wildfly.security.ldap;

import org.junit.Test;
import org.wildfly.common.function.ExceptionSupplier;

import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import java.util.Properties;

import static org.junit.Assert.assertNotNull;

/**
 * Test case to test connectivity to the server.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class TestEnvironmentSuiteChild {
    @Test
    public void testConnection() throws NamingException {
        Properties additionalConnectionProperties = new Properties();

        // let's configure connection pooling
        additionalConnectionProperties.put("com.sun.jndi.ldap.connect.pool", "true");

        System.setProperty("com.sun.jndi.ldap.connect.pool.authentication", "simple");
        System.setProperty("com.sun.jndi.ldap.connect.pool.maxsize", "10");
        System.setProperty("com.sun.jndi.ldap.connect.pool.prefsize", "5");
        System.setProperty("com.sun.jndi.ldap.connect.pool.timeout", "300000");
        System.setProperty("com.sun.jndi.ldap.connect.pool.debug", "all");

        ExceptionSupplier<DirContext, NamingException> supplier = LdapTestSuite.dirContextFactory.create();
        DirContext context = supplier.get();
        assertNotNull(context);

        context.close();
    }
}
