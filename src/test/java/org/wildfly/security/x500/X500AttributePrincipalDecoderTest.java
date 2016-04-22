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

import static org.junit.Assert.assertEquals;

import javax.security.auth.x500.X500Principal;

import org.junit.Test;

/**
 * Tests for the X500AttributePrincipalDecoder.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class X500AttributePrincipalDecoderTest {

    @Test
    public void testDecodeInReverse() {
        X500Principal principal = new X500Principal("dc=com,dc=redhat,dc=example,ou=people,cn=bob.smith");
        X500AttributePrincipalDecoder decoder;
        decoder = new X500AttributePrincipalDecoder(X500.OID_DC, true);
        assertEquals("example.redhat.com", decoder.getName(principal));

        decoder = new X500AttributePrincipalDecoder(X500.OID_DC, 1, true);
        assertEquals("example", decoder.getName(principal)); // single attribute value
    }
}
