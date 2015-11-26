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

import org.junit.ClassRule;
import org.junit.Test;
import org.wildfly.security.auth.provider.ldap.DirContextFactory;

import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import java.util.Properties;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

/**
 * Test case to test connectivity to the server, also verifies that the user accounts in use are all correctly registered.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class TestEnvironmentTest {

    @ClassRule
    public static DirContextFactoryRule dirContextFactory = new DirContextFactoryRule();

    @Test
    public void testPlain() throws NamingException {
        testUser("uid=plainUser,dc=elytron,dc=wildfly,dc=org", "plainPassword");
    }

    @Test
    public void testSha512() throws NamingException {
        testUser("uid=sha512User,dc=elytron,dc=wildfly,dc=org", "sha512Password");
    }

    @Test
    public void testSsha512() throws NamingException {
        testUser("uid=ssha512User,dc=elytron,dc=wildfly,dc=org", "ssha512Password");
    }

    @Test
    public void testCrypt() throws NamingException {
        testUser("uid=cryptUser,dc=elytron,dc=wildfly,dc=org", "cryptIt");
    }

    private void testUser(final String principal, final String credential) throws NamingException {
        runTest(principal, credential);
        try {
            runTest(principal, "BAD");
            fail("Expected exception not thrown");
        } catch (NamingException e) {
        }
    }

    private void runTest(final String principal, final String credential) throws NamingException {
        Properties additionalConnectionProperties = new Properties();

        // let's configure connection pooling
        additionalConnectionProperties.put("com.sun.jndi.ldap.connect.pool", "true");

        System.setProperty("com.sun.jndi.ldap.connect.pool.authentication", "simple");
        System.setProperty("com.sun.jndi.ldap.connect.pool.maxsize", "10");
        System.setProperty("com.sun.jndi.ldap.connect.pool.prefsize", "5");
        System.setProperty("com.sun.jndi.ldap.connect.pool.timeout", "300000");
        System.setProperty("com.sun.jndi.ldap.connect.pool.debug", "all");

        DirContextFactory factory = dirContextFactory.create(principal, credential);

        DirContext context = factory.obtainDirContext(null);
        assertNotNull(context);
        factory.returnContext(context);
    }

}
