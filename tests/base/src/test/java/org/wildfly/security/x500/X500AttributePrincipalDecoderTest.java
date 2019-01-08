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
import org.wildfly.security.auth.server.PrincipalDecoder;
import org.wildfly.security.x500.principal.X500AttributePrincipalDecoder;

/**
 * Tests for the X500AttributePrincipalDecoder.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
//dependent on module auth server because of PrincipalDecoder
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

    @Test
    public void testDecodeAttributeWithSubrange() {
        X500Principal principal;
        X500AttributePrincipalDecoder decoder;
        principal = new X500Principal("cn=bob.smith,dc=example,dc=redhat,dc=com");
        decoder = new X500AttributePrincipalDecoder(X500.OID_DC, 1, 1); // single attribute value
        assertEquals("redhat", decoder.getName(principal));

        decoder = new X500AttributePrincipalDecoder(X500.OID_DC, 1, 2);
        assertEquals("redhat.com", decoder.getName(principal));

        principal = new X500Principal("dc=com,dc=redhat,dc=jboss,dc=example,ou=people,cn=bob.smith");
        decoder = new X500AttributePrincipalDecoder(X500.OID_DC, 1, 3, true); // reverse order
        assertEquals("jboss.redhat.com", decoder.getName(principal));
    }

    @Test
    public void testDecodeWithConcatenation() {
        X500Principal principal; new X500Principal("cn=bob.smith,cn=bob,ou=people,dc=example,dc=redhat,dc=com");
        PrincipalDecoder dcDecoder, dcDecoder1,  cnDecoder, ouDecoder, concatenatingDecoder;
        principal = new X500Principal("cn=bob.smith,cn=bob,ou=people,dc=example,dc=redhat,dc=com");
        dcDecoder = new X500AttributePrincipalDecoder(X500.OID_DC);
        cnDecoder = new X500AttributePrincipalDecoder(X500.OID_AT_COMMON_NAME, 1);
        concatenatingDecoder = PrincipalDecoder.concatenating(cnDecoder, "@", dcDecoder);
        assertEquals("bob.smith@example.redhat.com", concatenatingDecoder.getName(principal));


        principal = new X500Principal("cn=bob.smith,ou=people,dc=example,dc=redhat");
        cnDecoder = PrincipalDecoder.concatenating(PrincipalDecoder.constant("cn"), "=", new X500AttributePrincipalDecoder(X500.OID_AT_COMMON_NAME));
        ouDecoder = PrincipalDecoder.concatenating(PrincipalDecoder.constant("ou"), "=", new X500AttributePrincipalDecoder(X500.OID_AT_ORGANIZATIONAL_UNIT_NAME, 1));
        dcDecoder = PrincipalDecoder.concatenating(PrincipalDecoder.constant("dc"), "=", new X500AttributePrincipalDecoder(X500.OID_DC, 1));
        dcDecoder1 = PrincipalDecoder.concatenating(PrincipalDecoder.constant("dc"), "=", new X500AttributePrincipalDecoder(X500.OID_DC, 1, 1));
        concatenatingDecoder = PrincipalDecoder.concatenating(",", dcDecoder1, dcDecoder, ouDecoder, cnDecoder);
        assertEquals("dc=redhat,dc=example,ou=people,cn=bob.smith", concatenatingDecoder.getName(principal));
    }

    @Test
    public void testDecodeWithRequiredAttributes() {
        X500Principal principal;
        // require the principal to have both CN and OU attributes
        X500AttributePrincipalDecoder decoder = new X500AttributePrincipalDecoder(X500.OID_AT_COMMON_NAME, ",", 0, 2, false, false, X500.OID_AT_COMMON_NAME, X500.OID_AT_ORGANIZATIONAL_UNIT_NAME);

        principal = new X500Principal("cn=bob.smith,cn=bsmith,dc=example,dc=redhat,dc=com"); // missing an OU attribute
        assertEquals(null, decoder.getName(principal));

        principal = new X500Principal("cn=bob.smith,cn=bsmith,ou=people,dc=example,dc=redhat,dc=com");
        assertEquals("bob.smith,bsmith", decoder.getName(principal));
    }
}
