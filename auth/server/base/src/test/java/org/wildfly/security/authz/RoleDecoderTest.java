/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2018 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.authz;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.wildfly.security.authz.RoleDecoder.KEY_SOURCE_ADDRESS;

import java.util.Arrays;
import java.util.HashSet;
import java.util.regex.Pattern;

import org.junit.Test;

/**
 * Tests for role decoders.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class RoleDecoderTest {

    @Test
    public void testSourceAddressRoleDecoderExactMatch() {
        Roles roles = getRoles("admin", "user");
        String sourceAddress = "10.12.14.16";
        SourceAddressRoleDecoder roleDecoder = new SourceAddressRoleDecoder(sourceAddress, roles);
        assertEquals(roles, roleDecoder.decodeRoles(getAuthorizationIdentity(sourceAddress)));
        assertEquals(Roles.NONE, roleDecoder.decodeRoles(getAuthorizationIdentity("10.12.16.18")));
        assertEquals(Roles.NONE, roleDecoder.decodeRoles(getAuthorizationIdentity("0:0:0:0:ffff:0:192.0.2.128")));

        // IPv6
        sourceAddress = "2001:db8:85a3:0:0:8a2e:370:7334";
        roleDecoder = new SourceAddressRoleDecoder(sourceAddress, roles);
        assertEquals(roles, roleDecoder.decodeRoles(getAuthorizationIdentity(sourceAddress)));
        assertEquals(Roles.NONE, roleDecoder.decodeRoles(getAuthorizationIdentity("0:0:0:0:ffff:0:192.0.2.128")));
        assertEquals(Roles.NONE, roleDecoder.decodeRoles(getAuthorizationIdentity("10.12.14.16")));

        assertEquals(Roles.NONE, roleDecoder.decodeRoles(getAuthorizationIdentity(null)));
    }

    @Test
    public void testSourceAddressRoleDecoderRegex() {
        Roles roles = getRoles("admin", "user");
        Pattern sourceAddressPattern = Pattern.compile("10\\.12\\.14\\.\\d+$");
        String sourceAddress = "10.12.14.16";
        SourceAddressRoleDecoder roleDecoder = new SourceAddressRoleDecoder(sourceAddressPattern, roles);
        assertEquals(roles, roleDecoder.decodeRoles(getAuthorizationIdentity(sourceAddress)));
        assertEquals(roles, roleDecoder.decodeRoles(getAuthorizationIdentity("10.12.14.18")));
        assertEquals(roles, roleDecoder.decodeRoles(getAuthorizationIdentity("10.12.14.1")));
        assertEquals(Roles.NONE, roleDecoder.decodeRoles(getAuthorizationIdentity("10.12.14.")));
        assertEquals(Roles.NONE, roleDecoder.decodeRoles(getAuthorizationIdentity("12.12.16.18")));
        assertEquals(Roles.NONE, roleDecoder.decodeRoles(getAuthorizationIdentity("10.12.14.18.20")));

        // IPv6
        sourceAddressPattern = Pattern.compile("2001\\:db8\\:85a3\\:0\\:0\\:8a2e\\:370\\:\\d+$");
        sourceAddress = "2001:db8:85a3:0:0:8a2e:370:7334";
        roleDecoder = new SourceAddressRoleDecoder(sourceAddressPattern, roles);
        assertEquals(roles, roleDecoder.decodeRoles(getAuthorizationIdentity(sourceAddress)));
        assertEquals(roles, roleDecoder.decodeRoles(getAuthorizationIdentity("2001:db8:85a3:0:0:8a2e:370:7335")));
        assertEquals(roles, roleDecoder.decodeRoles(getAuthorizationIdentity("2001:db8:85a3:0:0:8a2e:370:7000")));
        assertEquals(Roles.NONE, roleDecoder.decodeRoles(getAuthorizationIdentity("2001:db8:85a3:0:0:8a2e:370:")));
        assertEquals(Roles.NONE, roleDecoder.decodeRoles(getAuthorizationIdentity("2222:db8:85a3:0:0:8a2e:370:7335")));
        assertEquals(Roles.NONE, roleDecoder.decodeRoles(getAuthorizationIdentity("2001:db8:85a3:0:0:8a2e:370:7335:0")));

        assertEquals(Roles.NONE, roleDecoder.decodeRoles(getAuthorizationIdentity(null)));
    }

    @Test
    public void testAggregateRoleDecoder() {
        Roles roles1 = getRoles("admin", "user");
        String sourceAddress1 = "10.12.14.16";
        SourceAddressRoleDecoder roleDecoder1 = new SourceAddressRoleDecoder(sourceAddress1, roles1);

        Roles roles2 = getRoles("employee");
        String sourceAddress2 = "10.12.14.18";
        SourceAddressRoleDecoder roleDecoder2 = new SourceAddressRoleDecoder(sourceAddress2, roles2);

        Roles roles3 = getRoles("internal");
        Pattern pattern = Pattern.compile("10\\.12\\.14\\.\\d+$");
        SourceAddressRoleDecoder roleDecoder3 = new SourceAddressRoleDecoder(pattern, roles3);

        RoleDecoder aggregateRoleDecoder = RoleDecoder.aggregate(roleDecoder1, roleDecoder2, roleDecoder3);
        Roles decodedRoles = aggregateRoleDecoder.decodeRoles(getAuthorizationIdentity(sourceAddress1));
        assertTrue(decodedRoles.contains("admin"));
        assertTrue(decodedRoles.contains("user"));
        assertFalse(decodedRoles.contains("employee"));
        assertTrue(decodedRoles.contains("internal"));

        decodedRoles = aggregateRoleDecoder.decodeRoles(getAuthorizationIdentity(sourceAddress2));
        assertFalse(decodedRoles.contains("admin"));
        assertFalse(decodedRoles.contains("user"));
        assertTrue(decodedRoles.contains("employee"));
        assertTrue(decodedRoles.contains("internal"));

        decodedRoles = aggregateRoleDecoder.decodeRoles(getAuthorizationIdentity("10.12.14.20"));
        assertFalse(decodedRoles.contains("admin"));
        assertFalse(decodedRoles.contains("user"));
        assertFalse(decodedRoles.contains("employee"));
        assertTrue(decodedRoles.contains("internal"));

        decodedRoles = aggregateRoleDecoder.decodeRoles(getAuthorizationIdentity("10.10.14.20"));
        assertFalse(decodedRoles.contains("admin"));
        assertFalse(decodedRoles.contains("user"));
        assertFalse(decodedRoles.contains("employee"));
        assertFalse(decodedRoles.contains("internal"));

        assertEquals(Roles.NONE, aggregateRoleDecoder.decodeRoles(getAuthorizationIdentity("2001:db8:85a3:0:0:8a2e:370:")));
        assertEquals(Roles.NONE, aggregateRoleDecoder.decodeRoles(getAuthorizationIdentity("12.12.16.18")));
        assertEquals(Roles.NONE, aggregateRoleDecoder.decodeRoles(getAuthorizationIdentity(null)));
    }

    private Roles getRoles(String... roles) {
        return Roles.fromSet(new HashSet<>(Arrays.asList(roles)));
    }

    private AuthorizationIdentity getAuthorizationIdentity(String sourceAddress) {
        if (sourceAddress == null) {
            return AuthorizationIdentity.basicIdentity(Attributes.EMPTY);
        } else {
            MapAttributes runtimeAttributes = new MapAttributes();
            runtimeAttributes.addFirst(KEY_SOURCE_ADDRESS, sourceAddress);
            return AuthorizationIdentity.basicIdentity(AuthorizationIdentity.EMPTY, runtimeAttributes);
        }
    }
}
