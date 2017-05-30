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

package org.wildfly.security.util;

import org.junit.Test;

import java.net.URI;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

/**
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
public class URIUtilTest {
    @Test
    public void testUserFromURI() throws Exception {
        assertNull(URIUtil.getUserFromURI(new URI("http://example.com/test")));
        assertEquals("", URIUtil.getUserFromURI(new URI("http://@example.com/test")));
        assertEquals("", URIUtil.getUserFromURI(new URI("http://:pass@example.com/test")));
        assertEquals("user", URIUtil.getUserFromURI(new URI("http://user@example.com/test")));
        assertEquals("user", URIUtil.getUserFromURI(new URI("http://user:password@example.com/test")));
        assertEquals("a=b%c@d", URIUtil.getUserFromURI(new URI("http://a%3Db%25c%40d:password:test@example.com")));
        assertEquals("user", URIUtil.getUserFromURI(new URI("domain:user:password@example.com/test")));
    }
}
