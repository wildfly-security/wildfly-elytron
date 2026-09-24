/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2026 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.auth.realm.token.validator;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.HashMap;
import java.util.Map;

import org.junit.Test;

/**
 * Tests for {@link OAuth2IntrospectValidator} parameter encoding.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class OAuth2IntrospectValidatorTest {

    @Test
    public void testBuildParametersEncodesInjectionCharacters() throws Exception {
        Map<String, String> parameters = new HashMap<>();
        parameters.put("token", "legitimate_token&injected=evil");
        parameters.put("token_type_hint", "access_token");

        byte[] result = OAuth2IntrospectValidator.buildParameters(parameters);
        String body = new String(result, "UTF-8");

        assertFalse("Token value containing '&' must be URL-encoded to prevent parameter injection, "
                        + "but the raw '&injected=evil' appeared as a separate parameter in: " + body,
                body.contains("&injected=evil"));

        assertTrue("Encoded body should contain the percent-encoded ampersand (%26)",
                body.contains("%26"));
    }

    @Test
    public void testBuildParametersEncodesEqualsInValue() throws Exception {
        Map<String, String> parameters = new HashMap<>();
        parameters.put("token", "token_value=with_equals");

        byte[] result = OAuth2IntrospectValidator.buildParameters(parameters);
        String body = new String(result, "UTF-8");

        String[] parts = body.split("&");
        for (String part : parts) {
            String[] keyValue = part.split("=", 2);
            if (keyValue[0].equals("token")) {
                assertFalse("Equals sign in token value must be encoded, but raw '=' found in value portion",
                        keyValue[1].contains("="));
                assertTrue("Encoded value should contain %3D for the equals sign",
                        keyValue[1].contains("%3D"));
            }
        }
    }
}
