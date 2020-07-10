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

import org.hamcrest.core.IsInstanceOf;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.realm.SimpleMapBackedSecurityRealm;
import org.wildfly.security.auth.realm.SimpleRealmEntry;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.auth.server.ServerAuthenticationContext;
import org.wildfly.security.authz.MapAttributes;
import org.wildfly.security.authz.RoleDecoder;
import org.wildfly.security.authz.RoleMapper;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;

import javax.security.jacc.PolicyConfiguration;
import javax.security.jacc.PolicyConfigurationFactory;
import javax.security.jacc.PolicyContext;
import javax.security.jacc.WebResourcePermission;
import java.security.Policy;
import java.security.Principal;
import java.security.ProtectionDomain;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.Collections;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
// has dependency on wildfly-elytron-realm
@Ignore
public class LinkPolicyConfigurationTest {

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

    @Test
    public void testLinkPolicyConfigurationSharingRoleMapping() throws Exception {
        ElytronPolicyConfigurationFactory policyConfigurationFactory = (ElytronPolicyConfigurationFactory) PolicyConfigurationFactory.getPolicyConfigurationFactory();
        // let's create the parent module policy
        final WebResourcePermission parentPermission = new WebResourcePermission("/webResource", "PUT");
        String parentContextID = "parent-module";

        SecurityDomain parentSecurityDomain = createSecurityDomain("mary", "Administrator");
        PolicyConfiguration parentPolicyConfiguration = policyConfigurationFactory.getPolicyConfiguration(parentContextID, false);

        parentPolicyConfiguration.addToRole("Administrator", parentPermission);
        parentPolicyConfiguration.addToRole("User", parentPermission);

        // let's create the first child module
        final WebResourcePermission child1Permission = new WebResourcePermission("/webResource", "POST");
        String child1ContextID = "child-module-1";
        SecurityDomain child1SecurityDomain = createSecurityDomain("john", "User");
        PolicyConfiguration child1PolicyConfiguration = policyConfigurationFactory.getPolicyConfiguration(child1ContextID, false);

        child1PolicyConfiguration.addToRole("Administrator", child1Permission);
        child1PolicyConfiguration.addToRole("User", child1Permission);
        child1PolicyConfiguration.addToRole("Manager", child1Permission);

        // let's create the second child module
        final WebResourcePermission child2Permission = new WebResourcePermission("/webResource", "GET");
        String child2ContextID = "child-module-2";
        SecurityDomain child2SecurityDomain = createSecurityDomain("smith", "Manager");
        PolicyConfiguration child2PolicyConfiguration = policyConfigurationFactory.getPolicyConfiguration(child2ContextID, false);

        child2PolicyConfiguration.addToRole("User", child2Permission);
        child2PolicyConfiguration.addToRole("Manager", child2Permission);

        // link first child module with parent
        parentPolicyConfiguration.linkConfiguration(child1PolicyConfiguration);

        // link second child module with parent
        parentPolicyConfiguration.linkConfiguration(child2PolicyConfiguration);

        parentPolicyConfiguration.commit();
        child1PolicyConfiguration.commit();
        child2PolicyConfiguration.commit();

        // let's check now permissions for first child module
        PolicyContext.setContextID(child1ContextID);
        Policy policy = Policy.getPolicy();

        ServerAuthenticationContext authenticationContext = child1SecurityDomain.createNewAuthenticationContext();
        authenticationContext.setAuthenticationName("john");
        authenticationContext.succeed();
        SecurityIdentity johnIdentity = authenticationContext.getAuthorizedIdentity();

        // john is known by first child module, it should pass
        johnIdentity.runAs(() -> {
            assertTrue(policy.implies(createProtectionDomain(), child1Permission));
        });

        authenticationContext = child2SecurityDomain.createNewAuthenticationContext();
        authenticationContext.setAuthenticationName("smith");
        authenticationContext.succeed();
        SecurityIdentity smithIdentity = authenticationContext.getAuthorizedIdentity();
        PolicyContext.setContextID(child2ContextID);

        // smith is not know by first module, but by second module. As they share the same role mapping, smith should be known by first module as well
        smithIdentity.runAs(() -> {
            assertTrue(policy.implies(createProtectionDomain(), child1Permission));
        });

        // same thing above, but using mary which is known only by parent module
        assertTrue(policy.implies(createProtectionDomain(), child1Permission));

        PolicyContext.setContextID(child2ContextID);

        // smith is known by first child module, it should pass
        assertTrue(policy.implies(createProtectionDomain(), child2Permission));

        // john is not know by first module, but by first module. As they share the same role mapping, john should be known by second module as well
        assertTrue(policy.implies(createProtectionDomain(), child2Permission));

        // same thing above, but using mary which is known only by parent module. However, in this case we don't have a permission for mary/Administrator in the second module
        assertFalse(policy.implies(createProtectionDomain(), child2Permission));

        PolicyContext.setContextID(parentContextID);

        assertTrue(policy.implies(createProtectionDomain(), parentPermission));
        assertFalse(policy.implies(createProtectionDomain(), parentPermission));

        parentPolicyConfiguration.delete();

        PolicyContext.setContextID(child1ContextID);

        // parent module was deleted, mary is longer resolvable
        assertFalse(policy.implies(createProtectionDomain(), child1Permission));
    }

    private SecurityDomain createSecurityDomain(String userName, String... roles) throws Exception {
        SecurityDomain.Builder builder = SecurityDomain.builder();
        SimpleMapBackedSecurityRealm realm = new SimpleMapBackedSecurityRealm();

        Password password = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR).generatePassword(new ClearPasswordSpec(userName.toCharArray()));

        MapAttributes attributes = new MapAttributes();
        attributes.addAll(RoleDecoder.KEY_ROLES, Arrays.asList(roles));


        realm.setIdentityMap(Collections.singletonMap(userName, new SimpleRealmEntry(
                Collections.singletonList(new PasswordCredential(password)),
                attributes
        )));

        builder.setDefaultRealmName("default");

        builder.addRealm("default",realm).setRoleMapper(RoleMapper.IDENTITY_ROLE_MAPPER).build();

        return builder.build();
    }

    @Test
    public void testFailLinkSamePolicyConfiguration() throws Exception {
        ElytronPolicyConfigurationFactory policyConfigurationFactory = (ElytronPolicyConfigurationFactory) PolicyConfigurationFactory.getPolicyConfigurationFactory();
        String parentContextID = "parent-module";
        PolicyConfiguration parentPolicyConfiguration = policyConfigurationFactory.getPolicyConfiguration(parentContextID, false);

        try {
            parentPolicyConfiguration.linkConfiguration(parentPolicyConfiguration);
            fail("Should not be possible to link the same policy with itself");
        } catch (Exception e) {
            assertThat(e, new IsInstanceOf(IllegalArgumentException.class));
        }

        parentPolicyConfiguration.commit();
    }

    private Principal createPrincipal(final String name) {
        return new NamePrincipal(name);
    }

    private ProtectionDomain createProtectionDomain(Principal... principals) {
        return new ProtectionDomain(null, getClass().getProtectionDomain().getPermissions(), null, principals);
    }
}
