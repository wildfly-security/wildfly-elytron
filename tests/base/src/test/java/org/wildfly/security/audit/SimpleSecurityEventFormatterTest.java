/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.audit;

import static org.junit.Assert.assertTrue;

import java.io.FilePermission;

import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.auth.realm.SimpleMapBackedSecurityRealm;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.event.SecurityAuthenticationSuccessfulEvent;
import org.wildfly.security.auth.server.event.SecurityEvent;
import org.wildfly.security.auth.server.event.SecurityEventVisitor;
import org.wildfly.security.auth.server.event.SecurityPermissionCheckFailedEvent;

/**
 * Test case to test the SimpleSecurityEventFormatter
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
//has dependency on wildfly-elytron-realm because of SimpleMapBackedSecurityRealm
public class SimpleSecurityEventFormatterTest {

    private static SecurityEventVisitor<?, String> simpleFormatter;
    private static SecurityDomain securityDomain;

    @BeforeClass
    public static void createDomain() {
        simpleFormatter = SimpleSecurityEventFormatter.builder().build();
        securityDomain = SecurityDomain.builder()
                .addRealm("Simple", new SimpleMapBackedSecurityRealm()).build()
                .setDefaultRealmName("Simple")
                .build();
    }

    private String baseTest(SecurityEvent event) {
        String formatted = event.accept(simpleFormatter, null);

        System.out.println(formatted);

        assertTrue("Event Time", formatted.contains("event-time="));
        assertTrue("Security Identity", formatted.contains("security-identity="));
        assertTrue("Identity Name", formatted.contains("name=anonymous"));
        assertTrue("Identity Creation Time", formatted.contains("creation-time="));

        return formatted;
    }

    @Test
    public void testAuthenticationSuccessful() {
        String formatted = baseTest(new SecurityAuthenticationSuccessfulEvent(securityDomain.getCurrentSecurityIdentity()));

        assertTrue("Event", formatted.contains("event=SecurityAuthenticationSuccessfulEvent"));
        assertTrue("Success", formatted.contains("success=true"));
    }

    @Test
    public void testPermissionCheckFailed() {
        String formatted = baseTest(new SecurityPermissionCheckFailedEvent(securityDomain.getCurrentSecurityIdentity(), new FilePermission("/etc", "read")));

        assertTrue("Event", formatted.contains("event=SecurityPermissionCheckFailedEvent"));
        assertTrue("Success", formatted.contains("success=false"));

        assertTrue("Permission", formatted.contains("permission="));
        assertTrue("Permission Type", formatted.contains("type=java.io.FilePermission"));
        assertTrue("Permission Actions", formatted.contains("actions=read"));
        assertTrue("Permission Name", formatted.contains("name=/etc"));
    }
}
