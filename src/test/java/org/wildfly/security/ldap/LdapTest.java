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

import java.io.File;
import java.io.IOException;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.wildfly.security.apacheds.LdapService;

/**
 * Suite for running a set of LDAP tests against a single server.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@RunWith(Suite.class)
@Suite.SuiteClasses(
    {ConnectionTests.class,
     UserPasswordTests.class})
public class LdapTest {

    static final int LDAP_PORT = 11390;

    private static LdapService ldapService;

    @BeforeClass
    public static void beforeClass() throws Exception {
        ldapService = LdapService.builder()
            .setWorkingDir(new File("./target/apache-ds/working"))
            .createDirectoryService("Test Service")
            .addPartition("Elytron", "dc=elytron,dc=wildfly,dc=org", 5, "uid")
            .importLdif(UserPasswordTests.class.getResourceAsStream("/Elytron.ldif"))
            .addTcpServer("Default TCP", "localhost", LDAP_PORT)
            .start();
    }

    @AfterClass
    public static void afterClass() throws IOException {
        if (ldapService != null) {
            ldapService.close();
        }
        ldapService = null;
    }

}
