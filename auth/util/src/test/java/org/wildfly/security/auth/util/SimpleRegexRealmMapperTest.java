/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2021 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.auth.util;

import java.security.Principal;
import java.util.regex.Pattern;

import org.junit.Assert;
import org.junit.Test;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.server.RealmMapper;
import org.wildfly.security.x500.X500PrincipalBuilder;

/**
 * @author <a href="mailto:pesilva@redhat.com">Pedro Silva</a>
 *
 */
public class SimpleRegexRealmMapperTest {

    @Test
    public void testReturnNullForNonNamePrincipal() {
        Pattern pattern = Pattern.compile("(REALM_[A-Z])");
        SimpleRegexRealmMapper simpleRegexRealmMapper = new SimpleRegexRealmMapper(pattern);
        Principal principal = new X500PrincipalBuilder().build();
        Assert.assertNull(simpleRegexRealmMapper.getRealmMapping(principal, null));
    }

    @Test
    public void testThrowExceptionForPatternParameterNull() {
        IllegalArgumentException exception = Assert.assertThrows(IllegalArgumentException.class, () -> {
            new SimpleRegexRealmMapper(null, RealmMapper.single("REALM_B"));
        });

        String expectedMessage = "Parameter 'realmNamePattern' may not be null";
        String actualMessage = exception.getMessage();

        Assert.assertEquals(expectedMessage, actualMessage);
    }

    @Test
    public void testThrowExceptionForRealmMapperParamenterNull() {
        IllegalArgumentException exception = Assert.assertThrows(IllegalArgumentException.class, () -> {
            new SimpleRegexRealmMapper(Pattern.compile("(REALM_[A-Z])"), null);
        });

        String expectedMessage = "Parameter 'delegate' may not be null";
        String actualMessage = exception.getMessage();

        Assert.assertEquals(expectedMessage, actualMessage);
    }

    @Test
    public void testThrowPatternRequiresCaptureGroup() {
        Pattern pattern = Pattern.compile("REALM_[A-Z]");

        IllegalArgumentException exception = Assert.assertThrows(IllegalArgumentException.class, () -> {
            new SimpleRegexRealmMapper(pattern);
        });

        String expectedMessage = "Pattern requires a capture group";
        String actualMessage = exception.getMessage();

        Assert.assertTrue(actualMessage.contains(expectedMessage));
    }

    @Test
    public void testReturnSpecificRealmMapping() {
        Pattern pattern = Pattern.compile("(REALM_[A-Z])");
        SimpleRegexRealmMapper simpleRegexRealmMapper = new SimpleRegexRealmMapper(pattern);
        Principal principal = new NamePrincipal("REALM_A");

        String expected = "REALM_A";
        String actual = simpleRegexRealmMapper.getRealmMapping(principal, null);

        Assert.assertEquals(expected, actual);
    }

    @Test
    public void testReturnSpecificRealmMappingForDelegate() {
        Pattern pattern = Pattern.compile("(REALM_[A-Z])");
        SimpleRegexRealmMapper simpleRegexRealmMapper = new SimpleRegexRealmMapper(pattern, RealmMapper.single("REALM_B"));
        Principal principal = new NamePrincipal("REALM_1");

        String expected = "REALM_B";
        String actual = simpleRegexRealmMapper.getRealmMapping(principal, null);

        Assert.assertEquals(expected, actual);
    }

}
