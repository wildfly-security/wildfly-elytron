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

package org.wildfly.security.sasl.gssapi;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.security.Provider;
import java.security.Security;

import org.junit.Test;

public class MechanismSelectionTestCase {

    @Test
    public void testGetJdkOnlyGSSAPI() throws Exception {
        Provider[] providers = Security.getProviders("SaslClientFactory.DIGEST-MD5");

        assertNotNull(providers);
        assertTrue(providers.length > 0);
    }

}
