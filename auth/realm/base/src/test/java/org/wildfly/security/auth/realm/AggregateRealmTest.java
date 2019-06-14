/*
 * Copyright 2019 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.auth.realm;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;

import java.security.Principal;
import java.util.Collections;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.function.Function;

import org.junit.Test;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.server.NameRewriter;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.authz.MapAttributes;

/**
 * Test case testing the {@link AggregateSecurityRealm} implementation.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class AggregateRealmTest {

    private static final String IDENTITY_NAME = "TestIdentity";
    private static final String IDENTITY_NAME_TRANSFORMED = "TESTIDENTITY";
    private static final Principal IDENTITY_PRINCIPAL = new NamePrincipal(IDENTITY_NAME);

    /*
     * The intent of this test case is to focus on the realm aggregation aspect, the AggregateAttributesTest focuses
     * on different permutations of actual attribute aggregation.
     */

    @Test
    public void testAuthenticationOnly() throws Exception {
        Attributes authenticationAttributes = new MapAttributes();
        authenticationAttributes.add("team", 0, "One");

        SecurityRealm testRealm = createSecurityRealm(false, authenticationAttributes, null, new Attributes[] { null });
        RealmIdentity identity = testRealm.getRealmIdentity(IDENTITY_PRINCIPAL);

        assertTrue("Identity exists", identity.exists());

        Attributes identityAttributes = identity.getAuthorizationIdentity().getAttributes();
        assertEquals("Expected attribute count.", 0, identityAttributes.size());
    }

    @Test
    public void testAuthorizationOnly() throws Exception {
        Attributes authorizationAttributes = new MapAttributes();
        authorizationAttributes.add("team", 0, "One");

        SecurityRealm testRealm = createSecurityRealm(false, null, null, authorizationAttributes);
        RealmIdentity identity = testRealm.getRealmIdentity(IDENTITY_PRINCIPAL);

        assertFalse("Identity does not exist", identity.exists());

        Attributes identityAttributes = identity.getAttributes();
        assertNull("No attributes expected", identityAttributes);
    }

    @Test
    public void testSingleAuthorization() throws Exception {
        Attributes authenticationAttributes = new MapAttributes();
        authenticationAttributes.add("team", 0, "One");
        authenticationAttributes.add("office", 0, "A");

        Attributes authorizationAttributes = new MapAttributes();
        authorizationAttributes.add("team", 0, "Two");

        SecurityRealm testRealm = createSecurityRealm(false, authenticationAttributes,null, authorizationAttributes);
        RealmIdentity identity = testRealm.getRealmIdentity(IDENTITY_PRINCIPAL);

        assertTrue("Identity exists", identity.exists());

        Attributes identityAttributes = identity.getAuthorizationIdentity().getAttributes();
        assertEquals("Expected attribute count.", 1, identityAttributes.size());
        assertEquals("Expected team", "Two", identityAttributes.get("team", 0));
    }

    @Test
    public void testFirstAuthorizationOfTwo() throws Exception {
        Attributes authenticationAttributes = new MapAttributes();
        authenticationAttributes.add("team", 0, "One");
        authenticationAttributes.add("office", 0, "A");

        Attributes authorizationAttributes = new MapAttributes();
        authorizationAttributes.add("team", 0, "Two");

        SecurityRealm testRealm = createSecurityRealm(false, authenticationAttributes, null, authorizationAttributes, null);
        RealmIdentity identity = testRealm.getRealmIdentity(IDENTITY_PRINCIPAL);

        assertTrue("Identity exists", identity.exists());

        Attributes identityAttributes = identity.getAuthorizationIdentity().getAttributes();
        assertEquals("Expected attribute count.", 1, identityAttributes.size());
        assertEquals("Expected team", "Two", identityAttributes.get("team", 0));
    }

    @Test
    public void testSecondAuthorizationOfTwo() throws Exception {
        Attributes authenticationAttributes = new MapAttributes();
        authenticationAttributes.add("team", 0, "One");
        authenticationAttributes.add("office", 0, "A");

        Attributes authorizationAttributes = new MapAttributes();
        authorizationAttributes.add("team", 0, "Two");

        SecurityRealm testRealm = createSecurityRealm(false, authenticationAttributes, null,null, authorizationAttributes);
        RealmIdentity identity = testRealm.getRealmIdentity(IDENTITY_PRINCIPAL);

        assertTrue("Identity exists", identity.exists());

        Attributes identityAttributes = identity.getAuthorizationIdentity().getAttributes();
        assertEquals("Expected attribute count.", 1, identityAttributes.size());
        assertEquals("Expected team", "Two", identityAttributes.get("team", 0));
    }

    @Test
    public void testTwoAuthorizationRealms() throws Exception {
        Attributes authenticationAttributes = new MapAttributes();
        authenticationAttributes.add("team", 0, "One");
        authenticationAttributes.add("office", 0, "A");

        Attributes authorizationOne = new MapAttributes();
        authorizationOne.add("team", 0, "Two");

        Attributes authorizationTwo = new MapAttributes();
        authorizationTwo.add("team", 0, "Three");
        authorizationTwo.add("office", 0, "B");

        SecurityRealm testRealm = createSecurityRealm(false, authenticationAttributes, null, authorizationOne, authorizationTwo);
        RealmIdentity identity = testRealm.getRealmIdentity(IDENTITY_PRINCIPAL);

        assertTrue("Identity exists", identity.exists());

        Attributes identityAttributes = identity.getAuthorizationIdentity().getAttributes();
        assertEquals("Expected attribute count.", 2, identityAttributes.size());
        assertEquals("Expected team", "Two", identityAttributes.get("team", 0));
        assertEquals("Expected office", "B", identityAttributes.get("office", 0));
    }

    @Test
    public void testCommonRealm() throws Exception {
        Attributes authenticationAttributes = new MapAttributes();
        authenticationAttributes.add("team", 0, "One");
        authenticationAttributes.add("office", 0, "A");

        Attributes authorizationOne = new MapAttributes();
        authorizationOne.add("team", 0, "Two");

        Attributes authorizationTwo = new MapAttributes();
        authorizationTwo.add("team", 0, "Three");
        authorizationTwo.add("office", 0, "B");

        SecurityRealm testRealm = createSecurityRealm(false, authenticationAttributes, null, authorizationOne, authenticationAttributes, authorizationTwo);
        RealmIdentity identity = testRealm.getRealmIdentity(IDENTITY_PRINCIPAL);

        assertTrue("Identity exists", identity.exists());

        Attributes identityAttributes = identity.getAuthorizationIdentity().getAttributes();
        assertEquals("Expected attribute count.", 2, identityAttributes.size());
        assertEquals("Expected team", "Two", identityAttributes.get("team", 0));
        assertEquals("Expected office", "A", identityAttributes.get("office", 0));
    }

    @Test
    public void testAuthenticationOnlyWithPrincipalTransformer() throws Exception {
        Attributes authenticationAttributes = new MapAttributes();
        authenticationAttributes.add("team", 0, "One");

        Function<Principal, Principal> principalTransformer = new CaseRewriter().asPrincipalRewriter();

        SecurityRealm testRealm = createSecurityRealm(true, authenticationAttributes, principalTransformer, new Attributes[] { null });
        RealmIdentity identity = testRealm.getRealmIdentity(IDENTITY_PRINCIPAL);

        assertTrue("Identity exists", identity.exists());

        Attributes identityAttributes = identity.getAuthorizationIdentity().getAttributes();
        assertEquals("Expected attribute count.", 0, identityAttributes.size());
    }

    @Test
    public void testAuthorizationOnlyWithPrincipalTransformer() throws Exception {
        Attributes authorizationAttributes = new MapAttributes();
        authorizationAttributes.add("team", 0, "One");

        Function<Principal, Principal> principalTransformer = new CaseRewriter().asPrincipalRewriter();

        SecurityRealm testRealm = createSecurityRealm(true, null, principalTransformer, authorizationAttributes);
        RealmIdentity identity = testRealm.getRealmIdentity(IDENTITY_PRINCIPAL);

        assertFalse("Identity does not exist", identity.exists());

        Attributes identityAttributes = identity.getAttributes();
        assertNull("No attributes expected", identityAttributes);
    }

    @Test
    public void testSingleAuthorizationWithPrincipalTransformer() throws Exception {
        Attributes authenticationAttributes = new MapAttributes();
        authenticationAttributes.add("team", 0, "One");
        authenticationAttributes.add("office", 0, "A");

        Attributes authorizationAttributes = new MapAttributes();
        authorizationAttributes.add("team", 0, "Two");

        Function<Principal, Principal> principalTransformer = new CaseRewriter().asPrincipalRewriter();

        SecurityRealm testRealm = createSecurityRealm(true, authenticationAttributes, principalTransformer, authorizationAttributes);
        RealmIdentity identity = testRealm.getRealmIdentity(IDENTITY_PRINCIPAL);

        assertTrue("Identity exists", identity.exists());

        Attributes identityAttributes = identity.getAuthorizationIdentity().getAttributes();
        assertEquals("Expected attribute count.", 1, identityAttributes.size());
        assertEquals("Expected team", "Two", identityAttributes.get("team", 0));
    }

    private static SecurityRealm createSecurityRealm(boolean applyPrincipalTransformer, Attributes authentication, Function<Principal, Principal> principalTransformer, Attributes... authorization) {
        SecurityRealm authenticationRealm = toSecurityRealm(authentication);
        SecurityRealm[] authorizationRealms = new SecurityRealm[authorization.length];
        for (int i = 0; i < authorizationRealms.length; i++) {
            if (authentication == authorization[i]) {
                authorizationRealms[i] = authenticationRealm;
            } else {
                authorizationRealms[i] = applyPrincipalTransformer ? toSecurityRealmWithTransform(authorization[i]) : toSecurityRealm(authorization[i]);
            }
        }

        return new AggregateSecurityRealm(authenticationRealm, principalTransformer, authorizationRealms);
    }

    private static SecurityRealm toSecurityRealm(Attributes attributes) {
        SimpleMapBackedSecurityRealm securityRealm = new SimpleMapBackedSecurityRealm();
        if (attributes != null) {
            Map<String, SimpleRealmEntry> identityMap = new HashMap<>();
            identityMap.put(IDENTITY_NAME, new SimpleRealmEntry(Collections.emptyList(), attributes));
            securityRealm.setIdentityMap(identityMap);
        }

        return securityRealm;
    }

    private static SecurityRealm toSecurityRealmWithTransform(Attributes attributes) {
        SimpleMapBackedSecurityRealm securityRealm = new SimpleMapBackedSecurityRealm();
        if (attributes != null) {
            Map<String, SimpleRealmEntry> identityMap = new HashMap<>();
            identityMap.put(IDENTITY_NAME_TRANSFORMED, new SimpleRealmEntry(Collections.emptyList(), attributes));
            securityRealm.setIdentityMap(identityMap);
        }

        return securityRealm;
    }

    /*
     * Function to convert string to all caps
     */
    static class CaseRewriter implements NameRewriter {
        public String rewriteName(String original) {
            return (original == null) ? null : original.toUpperCase(Locale.ROOT);
        }
    }

}
