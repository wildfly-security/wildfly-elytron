/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.x500;

import static org.junit.Assert.*;

import java.util.Arrays;

import javax.security.auth.x500.X500Principal;

import org.junit.Test;
import org.wildfly.security.asn1.ASN1Encodable;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public class X500PrincipalBuilderTest {

    @Test
    public void testSimple() {
        X500PrincipalBuilder builder = new X500PrincipalBuilder();
        builder.addItem(X500AttributeTypeAndValue.create(X500.OID_AT_COMMON_NAME, ASN1Encodable.ofUtf8String("testUser")));
        X500Principal principal = builder.build();
        assertEquals("CN=testUser", principal.getName());
        builder.addItem(X500AttributeTypeAndValue.create(X500.OID_AT_COMMON_NAME, ASN1Encodable.ofUtf8String("testUser2")));
        principal = builder.build();
        assertEquals("CN=testUser2,CN=testUser", principal.getName());
        builder.addItem(X500AttributeTypeAndValue.create(X500.OID_DC, ASN1Encodable.ofUtf8String("com")));
        builder.addItem(X500AttributeTypeAndValue.create(X500.OID_DC, ASN1Encodable.ofUtf8String("foo")));
        principal = builder.build();
        assertEquals("DC=foo,DC=com,CN=testUser2,CN=testUser", principal.getName());
    }

    @Test
    public void testCompound() {
        X500PrincipalBuilder builder = new X500PrincipalBuilder();
        builder.addCompoundItem(Arrays.asList(
            X500AttributeTypeAndValue.create(X500.OID_AT_COMMON_NAME, ASN1Encodable.ofUtf8String("testUser")),
            X500AttributeTypeAndValue.create(X500.OID_AT_COMMON_NAME, ASN1Encodable.ofUtf8String("testUser2"))
        ));
        X500Principal principal = builder.build();
        assertEquals("CN=testUser+CN=testUser2", principal.getName());
        builder.addItem(X500AttributeTypeAndValue.create(X500.OID_AT_COMMON_NAME, ASN1Encodable.ofUtf8String("testUser3")));
        principal = builder.build();
        assertEquals("CN=testUser3,CN=testUser+CN=testUser2", principal.getName());
        builder.addCompoundItem(Arrays.asList(
            X500AttributeTypeAndValue.create(X500.OID_DC, ASN1Encodable.ofUtf8String("com")),
            X500AttributeTypeAndValue.create(X500.OID_DC, ASN1Encodable.ofUtf8String("foo"))
        ));
        principal = builder.build();
        assertEquals("DC=com+DC=foo,CN=testUser3,CN=testUser+CN=testUser2", principal.getName());
    }
}
