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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.FilePermission;
import java.io.StringReader;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;

import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.auth.realm.SimpleMapBackedSecurityRealm;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.event.Rfc3164SyslogEvent;
import org.wildfly.security.auth.server.event.Rfc5424SyslogEvent;
import org.wildfly.security.auth.server.event.SecurityAuthenticationSuccessfulEvent;
import org.wildfly.security.auth.server.event.SecurityEvent;
import org.wildfly.security.auth.server.event.SecurityEventVisitor;
import org.wildfly.security.auth.server.event.SecurityPermissionCheckFailedEvent;

/**
 * Test case to test the JsonSecurityEventFormatter
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
//has dependency on wildfly-elytron-realm because of SimpleMapBackedSecurityRealm
public class JsonSecurityEventFormatterTest {

    private static SecurityEventVisitor<?, String> jsonFormatter;
    private static SecurityDomain securityDomain;

    @BeforeClass
    public static void createDomain() {
        jsonFormatter = JsonSecurityEventFormatter.builder().build();
        securityDomain = SecurityDomain.builder()
                .addRealm("Simple", new SimpleMapBackedSecurityRealm()).build()
                .setDefaultRealmName("Simple")
                .build();
    }

    private JsonObject baseTest(SecurityEvent event) {
        String formatted = event.accept(jsonFormatter, null);

        System.out.println(formatted);

        JsonReader reader = Json.createReader(new StringReader(formatted));
        JsonObject jsonObject = reader.readObject();

        assertNotNull("Event Time", jsonObject.getString("event-time"));

        JsonObject securityIdentity = jsonObject.getJsonObject("security-identity");
        assertEquals("Name", "anonymous", securityIdentity.getString("name"));
        assertNotNull("Creation Time", securityIdentity.getString("creation-time"));

        return jsonObject;
    }

    @Test
    public void testRfc3164SyslogEvent() {
        JsonObject jsonObject = baseTest(new Rfc3164SyslogEvent(securityDomain.getCurrentSecurityIdentity()));

        assertEquals("Expected Event", "Rfc3164SyslogEvent", jsonObject.getString("event"));
        assertEquals("Expected Format", "RFC3164", jsonObject.getString("syslog-format"));
    }

    @Test
    public void testRfc5424SyslogEvent() {
        JsonObject jsonObject = baseTest(new Rfc5424SyslogEvent(securityDomain.getCurrentSecurityIdentity()));

        assertEquals("Expected Event", "Rfc5424SyslogEvent", jsonObject.getString("event"));
        assertEquals("Expected Format", "RFC5424", jsonObject.getString("syslog-format"));
    }

    @Test
    public void testAuthenticationSuccessful() {
        JsonObject jsonObject = baseTest(new SecurityAuthenticationSuccessfulEvent(securityDomain.getCurrentSecurityIdentity()));

        assertEquals("Expected Event", "SecurityAuthenticationSuccessfulEvent", jsonObject.getString("event"));
        assertEquals("Success", true, jsonObject.getBoolean("success"));
    }

    @Test
    public void testPermissionCheckFailed() {
        JsonObject jsonObject = baseTest(new SecurityPermissionCheckFailedEvent(securityDomain.getCurrentSecurityIdentity(), new FilePermission("/etc", "read")));

        assertEquals("Expected Event", "SecurityPermissionCheckFailedEvent", jsonObject.getString("event"));
        assertEquals("Success", false, jsonObject.getBoolean("success"));

        JsonObject permission = jsonObject.getJsonObject("permission");
        assertEquals("Permission Type", "java.io.FilePermission", permission.getString("type"));
        assertEquals("Permission Actions", "read", permission.getString("actions"));
        assertEquals("Permission Name", "/etc", permission.getString("name"));
    }
}
