/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2015 Red Hat, Inc. and/or its affiliates.
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
package org.wildfly.security.authz.jacc;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;
import org.wildfly.security.auth.permission.RunAsPrincipalPermission;
import org.wildfly.security.auth.realm.SimpleMapBackedSecurityRealm;
import org.wildfly.security.auth.realm.SimpleRealmEntry;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.authz.MapAttributes;
import org.wildfly.security.authz.RoleDecoder;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.permission.PermissionUtil;
import org.wildfly.security.permission.PermissionVerifier;

import javax.security.jacc.PolicyConfiguration;
import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;
import javax.security.jacc.WebResourcePermission;

import java.security.PermissionCollection;
import java.security.Policy;
import java.security.Provider;
import java.security.Security;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * <p>This test case provides policy enforcement tests based on the JACC specification as well relying on Elytron's Permission
 * Mapping API in order to define and enforce additional permissions.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
// has dependency on wildfly-elytron-realm
public class ElytronPolicyEnforcementTest extends AbstractAuthorizationTestCase {

    private static final Provider provider = WildFlyElytronPasswordProvider.getInstance();

    @BeforeClass
    public static void onBeforeClass() {
        System.setProperty("javax.security.jacc.PolicyConfigurationFactory.provider", ElytronPolicyConfigurationFactory.class.getName());
        Policy.setPolicy(new JaccDelegatingPolicy());
        Security.addProvider(provider);
    }

    @AfterClass
    public static void onAfter() throws Exception {
        Security.removeProvider(provider.getName());
    }

    private static final String CONTEXT_ID = "third-party-app";

    @Override
    protected SecurityDomain createSecurityDomain() {
        SecurityDomain.Builder builder = SecurityDomain.builder();
        SimpleMapBackedSecurityRealm securityRealm = new SimpleMapBackedSecurityRealm();
        Map<String, SimpleRealmEntry> users = new HashMap<>();

        addUser(users, "user-admin", "Administrator");
        addUser(users, "user-manager", "Manager");
        addUser(users, "user-user", "User");

        securityRealm.setIdentityMap(users);

        builder.addRealm("default", securityRealm).build();
        builder.setDefaultRealmName("default");

        builder.setPermissionMapper((permissionMappable, roles) -> {
            PermissionCollection collection;
            if (roles.contains("Administrator")) {
                collection = PermissionUtil.readOnlyCollectionOf(
                    new WebResourcePermission("/webResource", "GET"),
                    new WebResourcePermission("/webResource", "PUT"),
                    new WebResourcePermission("/webResource", "POST"),
                    new RunAsPrincipalPermission("*")
                );
            } else if (roles.contains("Manager")) {
                collection = PermissionUtil.readOnlyCollectionOf(
                    new WebResourcePermission("/webResource", "GET"),
                    new WebResourcePermission("/webResource", "POST"),
                    new RunAsPrincipalPermission("*")
                );
            } else if (roles.contains("User")) {
                collection = PermissionUtil.readOnlyCollectionOf(
                    new WebResourcePermission("/webResource", "GET"),
                    new RunAsPrincipalPermission("*")
                );
            } else {
                collection = PermissionUtil.readOnlyCollectionOf(new RunAsPrincipalPermission("*"));
            }
            return PermissionVerifier.from(collection);
        });

        SecurityDomain securityDomain = builder.build();
        ClassLoader classLoader = ElytronPolicyEnforcementTest.class.getClassLoader();
        SecurityDomain.unregisterClassLoader(classLoader);
        securityDomain.registerWithClassLoader(classLoader);

        try {
            PolicyContext.registerHandler(SecurityIdentityHandler.KEY, new SecurityIdentityHandler(), true);
        } catch (PolicyContextException e) {
            e.printStackTrace();
            fail("Could not register [" + SecurityIdentityHandler.class + "].");
        }

        return securityDomain;
    }

    @Test
    @SecurityIdentityRule.RunAs("user-admin")
    public void testAdministratorRoleBasedPolicy() throws Exception {
        String contextID = "third-party-app";

        PolicyConfiguration policyConfiguration = createPolicyConfiguration(contextID, toConfigure -> {
            toConfigure.addToRole("Administrator", new WebResourcePermission("/webResource", "HEAD"));
        });

        policyConfiguration.commit();

        PolicyContext.setContextID(contextID);
        Policy policy = Policy.getPolicy();

        // this permission was defined using a PermissionMapper and it should be granted for user-admin
        assertTrue(policy.implies(createProtectionDomain(), new WebResourcePermission("/webResource", "POST")));
        // however, this one was set using JACC API, via PolicyConfiguration. It should be valid as well.
        assertTrue(policy.implies(createProtectionDomain(), new WebResourcePermission("/webResource", "HEAD")));
        // this one was not granted for user-admin
        assertFalse(policy.implies(createProtectionDomain(), new WebResourcePermission("/webResource", "OPTIONS")));

        policyConfiguration.delete();
    }

    @Test
    @SecurityIdentityRule.RunAs("user-manager")
    public void testManagerRoleBasedPolicy() throws Exception {
        String contextID = "third-party-app";

        PolicyConfiguration policyConfiguration = createPolicyConfiguration(contextID, toConfigure -> {});

        policyConfiguration.commit();

        PolicyContext.setContextID(contextID);
        Policy policy = Policy.getPolicy();

        // these permissions were defined using a PermissionMapper and they should be granted for user-manager
        assertTrue(policy.implies(createProtectionDomain(), new WebResourcePermission("/webResource", "POST")));
        assertTrue(policy.implies(createProtectionDomain(), new WebResourcePermission("/webResource", "GET")));
        // this one was not granted for user-manager
        assertFalse(policy.implies(createProtectionDomain(), new WebResourcePermission("/webResource", "PUT")));

        policyConfiguration.delete();
    }

    @Test
    @SecurityIdentityRule.RunAs("user-user")
    public void testUserRoleBasedPolicy() throws Exception {
        String contextID = "third-party-app";

        PolicyConfiguration policyConfiguration = createPolicyConfiguration(contextID, toConfigure -> {});

        policyConfiguration.commit();

        PolicyContext.setContextID(contextID);
        Policy policy = Policy.getPolicy();

        // this permissions was defined using a PermissionMapper and they should be granted for user-user
        assertTrue(policy.implies(createProtectionDomain(), new WebResourcePermission("/webResource", "GET")));
        // this one was not granted for user-manager
        assertFalse(policy.implies(createProtectionDomain(), new WebResourcePermission("/webResource", "PUT")));
        assertFalse(policy.implies(createProtectionDomain(), new WebResourcePermission("/webResource", "POST")));

        policyConfiguration.delete();
    }

    private void addUser(Map<String, SimpleRealmEntry> securityRealm, String userName, String roles) {
        List<Credential> defaultInsecurePasswords;

        try {
            defaultInsecurePasswords = Collections.singletonList(
                new PasswordCredential(
                    PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR).generatePassword(
                        new ClearPasswordSpec("password".toCharArray()))));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        MapAttributes attributes = new MapAttributes();

        attributes.addAll(RoleDecoder.KEY_ROLES, Collections.singletonList(roles));

        securityRealm.put(userName, new SimpleRealmEntry(defaultInsecurePasswords, attributes));
    }
}
