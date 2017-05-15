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

package org.wildfly.security.auth.client;

import static org.junit.Assert.*;

import org.junit.Test;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class AuthenticationConfigurationTest {


    @Test
    public void testBaseEquality1() {
        AuthenticationConfiguration c1;
        AuthenticationConfiguration c2;

        c1 = AuthenticationConfiguration.EMPTY.useName("name1").usePort(1234).useProtocol("abcd");
        c2 = AuthenticationConfiguration.EMPTY.useName("name1").usePort(1234).useProtocol("abcd");

        assertEquals(c1, c2);
    }

    @Test
    public void testBaseEquality2() {
        AuthenticationConfiguration c1;
        AuthenticationConfiguration c2;

        c1 = AuthenticationConfiguration.EMPTY.useName("name1").usePort(1234).useProtocol("abcd").usePassword("abcd");
        c2 = AuthenticationConfiguration.EMPTY.useName("name1").usePort(1234).useProtocol("abcd").usePassword("abcd");

        assertEquals(c1, c2);
    }


    @Test
    public void testCopying() {
        AuthenticationConfiguration c1;
        AuthenticationConfiguration c2;

        c1 = AuthenticationConfiguration.EMPTY.useName("name1").usePassword("password1").usePort(1234);
        c2 = AuthenticationConfiguration.EMPTY.useName("name2").useProtocol("abcd").usePort(1234);
        assertEquals(
            AuthenticationConfiguration.EMPTY.useName("name1").useCredentials(c1.getCredentialSource()).usePort(1234).useProtocol("abcd"),
            c2.with(c1)
        );

        c1 = AuthenticationConfiguration.EMPTY.useName("name1").usePassword("password1");
        c2 = AuthenticationConfiguration.EMPTY.usePort(1234);
        assertEquals(
                AuthenticationConfiguration.EMPTY.useName("name1").useCredentials(c1.getCredentialSource()).usePort(1234),
                c1.with(c2)
        );

    }
}
