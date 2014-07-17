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

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import javax.naming.NamingException;
import javax.naming.directory.DirContext;

import org.junit.Test;
import org.wildfly.security.auth.provider.ldap.DirContextFactory;
import org.wildfly.security.auth.provider.ldap.SimpleDirContextFactoryBuilder;

/**
 * Test case to test connectivity to the server, also verifies that the user accounts in use are all correctly registered.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class ConnectionTests {

    @Test
    public void testServer() throws NamingException {
        testUser(LdapTest.SERVER_DN, LdapTest.SERVER_CREDENTIAL);
    }

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
        testUser("uid=cryptUser,dc=elytron,dc=wildfly,dc=org", "cryptPassword");
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
        DirContextFactory factory = SimpleDirContextFactoryBuilder.builder()
                .setProviderUrl(String.format("ldap://localhost:%d/", LdapTest.LDAP_PORT))
                .setSecurityPrincipal(principal)
                .setSecurityCredential(credential)
                .build();

        DirContext context = factory.obtainDirContext(null);
        assertNotNull(context);
        factory.returnContext(context);
    }

}
