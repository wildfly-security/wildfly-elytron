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
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

import org.junit.Assert;
import org.junit.Test;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.server.RealmMapper;
import org.wildfly.security.x500.X500PrincipalBuilder;

/**
 * @author <a href="mailto:pesilva@redhat.com">Pedro Silva</a>
 */
public class MappedRegexRealmMapperTest {

    @Test
    public void testReturnNullForNonNamePrincipalInstance() {
        Map<String, String> realmNameMap = Collections.emptyMap();
        Pattern pattern = Pattern.compile("([A-Z]-\\d{4})");
        MappedRegexRealmMapper mappedRegexRealmMapper = new MappedRegexRealmMapper(pattern, realmNameMap);
        Principal principal = new X500PrincipalBuilder().build();
        Assert.assertNull(mappedRegexRealmMapper.getRealmMapping(principal, null));
    }

    @Test
    public void testReturnNullCantFindValueInMap() {
        Map<String, String> realmNameMap = Collections.singletonMap("A-0000", "new_realm");
        Pattern pattern = Pattern.compile("([A-Z]-\\d{4})");
        MappedRegexRealmMapper mappedRegexRealmMapper = new MappedRegexRealmMapper(pattern, realmNameMap);
        Principal principal = new NamePrincipal("A-9999");
        Assert.assertNull(mappedRegexRealmMapper.getRealmMapping(principal, null));
    }

    @Test
    public void testReturnSpecificRealmMapping() {
        String realmName = "new_realm";
        Map<String, String> realmNameMap = Collections.singletonMap("A-9999", realmName);
        Pattern pattern = Pattern.compile("([A-Z]-\\d{4})");
        MappedRegexRealmMapper mappedRegexRealmMapper = new MappedRegexRealmMapper(pattern, realmNameMap);
        Principal principal = new NamePrincipal("A-9999");
        Assert.assertEquals(realmName, mappedRegexRealmMapper.getRealmMapping(principal, null));
    }

    @Test
    public void testReturnSpecificRealmMappingForDelegate() {
        String delegateName = "delegate_realm";
        Pattern pattern = Pattern.compile("([A-Z]-\\d{4})");
        Map<String, String> realmNameMap = Collections.singletonMap("A-9999", delegateName);
        MappedRegexRealmMapper mappedRegexRealmMapper = new MappedRegexRealmMapper(pattern, RealmMapper.single("A-9999"), realmNameMap);
        Principal principal = new NamePrincipal("A-1");
        Assert.assertEquals(delegateName, mappedRegexRealmMapper.getRealmMapping(principal, null));
    }

    @Test
    public void testReturnCorrectRealmMappingWithPrincipalAndDelegateMatchingPattern() {
        String realmName = "realm";
        Pattern pattern = Pattern.compile("([A-Z]-\\d{4})");
        Map<String, String> realmNameMap = new HashMap<>();
        realmNameMap.put("A-9999", realmName);
        realmNameMap.put("A-1111", "delegateRealm");
        MappedRegexRealmMapper mappedRegexRealmMapper = new MappedRegexRealmMapper(pattern, RealmMapper.single("A-1111"), realmNameMap);
        Principal principal = new NamePrincipal("A-9999");
        Assert.assertEquals(realmName, mappedRegexRealmMapper.getRealmMapping(principal, null));
    }
}
