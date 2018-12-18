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
import org.hamcrest.core.IsSame;
import org.junit.Assert;
import org.junit.Test;
import org.wildfly.security.auth.principal.NamePrincipal;

import javax.security.jacc.PolicyConfiguration;
import javax.security.jacc.PolicyConfigurationFactory;
import javax.security.jacc.PolicyContext;
import javax.security.jacc.WebResourcePermission;
import java.security.PermissionCollection;
import java.security.Policy;
import java.security.PrivilegedAction;

import static java.security.AccessController.doPrivileged;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
// has dependency on wildfly-elytron-realm
@SecurityIdentityRule.RunAs("elytron")
public class PolicyConfigurationTest extends AbstractAuthorizationTestCase {

    @Test
    public void testCreateElytronPolicyConfigurationFactory() throws Exception {
        PolicyConfigurationFactory policyConfigurationFactory = PolicyConfigurationFactory.getPolicyConfigurationFactory();

        Assert.assertThat(policyConfigurationFactory, new IsInstanceOf(ElytronPolicyConfigurationFactory.class));

        PolicyConfigurationFactory sameInstance = PolicyConfigurationFactory.getPolicyConfigurationFactory();

        Assert.assertThat(policyConfigurationFactory, new IsSame<>(sameInstance));
    }

    @Test
    public void testCreateAndInstallDelegatingPolicy() throws Exception {
        Policy policy = Policy.getPolicy();

        assertThat(policy, new IsSame<>(doPrivileged((PrivilegedAction<Policy>) Policy::getPolicy)));

        Policy mustBeTheSame = Policy.getPolicy();

        assertThat(mustBeTheSame, new IsSame<>(doPrivileged((PrivilegedAction<Policy>) Policy::getPolicy)));
    }

    @Test
    public void testCreatePolicyConfiguration() throws Exception {
        final WebResourcePermission dynamicPermission1 = new WebResourcePermission("/webResource", "GET,PUT");
        final WebResourcePermission dynamicPermission2 = new WebResourcePermission("/webResource", "PUT");
        final WebResourcePermission dynamicPermission3 = new WebResourcePermission("/webResource", "HEAD");
        String contextID = "third-party-app";
        ElytronPolicyConfiguration policyConfiguration = createPolicyConfiguration(contextID, toConfigure -> {
                    toConfigure.addToUncheckedPolicy(dynamicPermission1);
                    toConfigure.addToRole("Administrator", dynamicPermission2);
                    toConfigure.addToExcludedPolicy(dynamicPermission3);
                }
        );

        PolicyConfigurationFactory policyConfigurationFactory = PolicyConfigurationFactory.getPolicyConfigurationFactory();

        // must be in open state
        assertFalse(policyConfigurationFactory.inService(contextID));
        assertFalse(policyConfiguration.inService());

        // we now set the context id
        PolicyContext.setContextID(contextID);

        Policy policy = doPrivileged((PrivilegedAction<Policy>) Policy::getPolicy);

        PermissionCollection permissions = policy.getPermissions(createProtectionDomain(new NamePrincipal("Administrator")));

        policyConfiguration.commit();

        assertTrue(policyConfiguration.inService());
        assertTrue(policyConfigurationFactory.inService(contextID));

        permissions = policy.getPermissions(createProtectionDomain(new NamePrincipal("Administrator")));

        assertTrue(permissions.implies(dynamicPermission1));
        assertTrue(permissions.implies(dynamicPermission2));

        // excluded permissions are never returned
        assertFalse(permissions.implies(dynamicPermission3));

        policyConfiguration.delete();
    }

    @Test
    public void testRemovePolicyConfiguration() throws Exception {
        final WebResourcePermission dynamicPermission1 = new WebResourcePermission("/webResource", "GET,PUT");
        final WebResourcePermission dynamicPermission2 = new WebResourcePermission("/webResource", "PUT");
        final WebResourcePermission dynamicPermission3 = new WebResourcePermission("/webResource", "HEAD");
        String contextID = "third-party-app";
        ElytronPolicyConfiguration policyConfiguration = createPolicyConfiguration(contextID, toConfigure -> {
                    toConfigure.addToUncheckedPolicy(dynamicPermission1);
                    toConfigure.addToRole("Administrator", dynamicPermission2);
                    toConfigure.addToExcludedPolicy(dynamicPermission3);
                }
        );

        assertFalse(policyConfiguration.inService());

        policyConfiguration.commit();

        assertTrue(policyConfiguration.inService());

        PolicyConfiguration removedPolicyConfiguration = createPolicyConfiguration("third-party-app", true);

        assertFalse(policyConfiguration.inService());
        assertThat(policyConfiguration, new IsSame<>(removedPolicyConfiguration));

        Policy policy = doPrivileged((PrivilegedAction<Policy>) Policy::getPolicy);

        PolicyContext.setContextID(contextID);

        PermissionCollection permissions = policy.getPermissions(createProtectionDomain(new NamePrincipal("Administrator")));

        assertFalse(permissions.implies(dynamicPermission1));
        assertFalse(permissions.implies(dynamicPermission2));
        assertFalse(permissions.implies(dynamicPermission3));
    }

    @Test
    public void testInServiceToOpenState() throws Exception {
        PolicyConfiguration policyConfiguration = createPolicyConfiguration("third-party-app");

        policyConfiguration.commit();

        PolicyConfiguration openPolicyConfiguration = createPolicyConfiguration("third-party-app");

        assertThat(policyConfiguration, new IsSame<>(openPolicyConfiguration));

        assertFalse(openPolicyConfiguration.inService());

        WebResourcePermission dynamicPermission = new WebResourcePermission("/webResource", "PUT");

        openPolicyConfiguration.addToUncheckedPolicy(dynamicPermission);
    }

    @Test
    public void testDeletedToOpenState() throws Exception {
        PolicyConfiguration policyConfiguration = createPolicyConfiguration("third-party-app");

        policyConfiguration.commit();

        PolicyConfiguration openPolicyConfiguration = createPolicyConfiguration("third-party-app", true);

        assertThat(policyConfiguration, new IsSame<>(openPolicyConfiguration));

        assertFalse(openPolicyConfiguration.inService());

        WebResourcePermission dynamicPermission = new WebResourcePermission("/webResource", "PUT");

        openPolicyConfiguration.addToUncheckedPolicy(dynamicPermission);
    }

    @Test
    public void testFailToAddUncheckedPermissionInServiceState() throws Exception {
        PolicyConfiguration policyConfiguration = createPolicyConfiguration("third-party-app");

        policyConfiguration.commit();

        WebResourcePermission dynamicPermission = new WebResourcePermission("/webResource", "PUT");

        try {
            policyConfiguration.addToUncheckedPolicy(dynamicPermission);
            fail("Permissions can not be added when policy configuration is inService state.");
        } catch (Exception e) {
            e.printStackTrace();
            assertThat(e, new IsInstanceOf(UnsupportedOperationException.class));
        }
    }

    @Test
    public void testFailToAddExcludedPermissionInServiceState() throws Exception {
        PolicyConfiguration policyConfiguration = createPolicyConfiguration("third-party-app");

        policyConfiguration.commit();

        WebResourcePermission dynamicPermission = new WebResourcePermission("/webResource", "PUT");

        try {
            policyConfiguration.addToExcludedPolicy(dynamicPermission);
            fail("Permissions can not be added when policy configuration is inService state.");
        } catch (Exception e) {
            e.printStackTrace();
            assertThat(e, new IsInstanceOf(UnsupportedOperationException.class));
        }
    }

    @Test
    public void testFailToAddRolePermissionInServiceState() throws Exception {
        PolicyConfiguration policyConfiguration = createPolicyConfiguration("third-party-app");

        policyConfiguration.commit();

        WebResourcePermission dynamicPermission = new WebResourcePermission("/webResource", "PUT");

        try {
            policyConfiguration.addToRole("Administrator", dynamicPermission);
            fail("Permissions can not be added when policy configuration is inService state.");
        } catch (Exception e) {
            e.printStackTrace();
            assertThat(e, new IsInstanceOf(UnsupportedOperationException.class));
        }
    }

    @Test
    public void testFailToRemoveUncheckedPermissionInServiceState() throws Exception {
        PolicyConfiguration policyConfiguration = createPolicyConfiguration("third-party-app");

        policyConfiguration.commit();

        try {
            policyConfiguration.removeUncheckedPolicy();
            fail("Permissions can not be removed when policy configuration is inService state.");
        } catch (Exception e) {
            e.printStackTrace();
            assertThat(e, new IsInstanceOf(UnsupportedOperationException.class));
        }
    }

    @Test
    public void testFailToRemoveExcludedPermissionInServiceState() throws Exception {
        PolicyConfiguration policyConfiguration = createPolicyConfiguration("third-party-app");

        policyConfiguration.commit();

        try {
            policyConfiguration.removeExcludedPolicy();
            fail("Permissions can not be removed when policy configuration is inService state.");
        } catch (Exception e) {
            e.printStackTrace();
            assertThat(e, new IsInstanceOf(UnsupportedOperationException.class));
        }
    }

    @Test
    public void testFailToRemoveRolePermissionInServiceState() throws Exception {
        PolicyConfiguration policyConfiguration = createPolicyConfiguration("third-party-app");

        policyConfiguration.commit();

        try {
            policyConfiguration.removeRole("Administrator");
            fail("Permissions can not be removed when policy configuration is inService state.");
        } catch (Exception e) {
            e.printStackTrace();
            assertThat(e, new IsInstanceOf(UnsupportedOperationException.class));
        }
    }

    @Test
    public void testFailToLinkInServiceState() throws Exception {
        PolicyConfiguration policyConfiguration = createPolicyConfiguration("third-party-app");

        policyConfiguration.commit();

        try {
            PolicyConfiguration linkedPolicyConfiguration = createPolicyConfiguration("third-pary-app/ejb", false);

            policyConfiguration.linkConfiguration(linkedPolicyConfiguration);

            fail("Links can not be added when policy configuration is inService state.");
        } catch (Exception e) {
            e.printStackTrace();
            assertThat(e, new IsInstanceOf(UnsupportedOperationException.class));
        }
    }

    @Test
    public void testFailToAddUncheckedPermissionInDeletedState() throws Exception {
        PolicyConfiguration policyConfiguration = createPolicyConfiguration("third-party-app");

        policyConfiguration.delete();

        WebResourcePermission dynamicPermission = new WebResourcePermission("/webResource", "PUT");

        try {
            policyConfiguration.addToUncheckedPolicy(dynamicPermission);
            fail("Permissions can not be added when policy configuration is in deleted state.");
        } catch (Exception e) {
            e.printStackTrace();
            assertThat(e, new IsInstanceOf(UnsupportedOperationException.class));
        }
    }

    @Test
    public void testFailToAddExcludedPermissionInDeletedState() throws Exception {
        PolicyConfiguration policyConfiguration = createPolicyConfiguration("third-party-app");

        policyConfiguration.delete();

        WebResourcePermission dynamicPermission = new WebResourcePermission("/webResource", "PUT");

        try {
            policyConfiguration.addToExcludedPolicy(dynamicPermission);
            fail("Permissions can not be added when policy configuration is in deleted state.");
        } catch (Exception e) {
            e.printStackTrace();
            assertThat(e, new IsInstanceOf(UnsupportedOperationException.class));
        }
    }

    @Test
    public void testFailToAddRolePermissionInDeletedState() throws Exception {
        PolicyConfiguration policyConfiguration = createPolicyConfiguration("third-party-app");

        policyConfiguration.delete();

        WebResourcePermission dynamicPermission = new WebResourcePermission("/webResource", "PUT");

        try {
            policyConfiguration.addToRole("Administrator", dynamicPermission);
            fail("Permissions can not be added when policy configuration is in deleted state.");
        } catch (Exception e) {
            e.printStackTrace();
            assertThat(e, new IsInstanceOf(UnsupportedOperationException.class));
        }
    }

    @Test
    public void testFailToRemoveUncheckedPermissionInDeletedState() throws Exception {
        PolicyConfiguration policyConfiguration = createPolicyConfiguration("third-party-app");

        policyConfiguration.delete();

        try {
            policyConfiguration.removeUncheckedPolicy();
            fail("Permissions can not be removed when policy configuration is in deleted state.");
        } catch (Exception e) {
            e.printStackTrace();
            assertThat(e, new IsInstanceOf(UnsupportedOperationException.class));
        }
    }

    @Test
    public void testFailToRemoveExcludedPermissionInDeletedState() throws Exception {
        PolicyConfiguration policyConfiguration = createPolicyConfiguration("third-party-app");

        policyConfiguration.delete();

        try {
            policyConfiguration.removeExcludedPolicy();
            fail("Permissions can not be removed when policy configuration is in deleted state.");
        } catch (Exception e) {
            e.printStackTrace();
            assertThat(e, new IsInstanceOf(UnsupportedOperationException.class));
        }
    }

    @Test
    public void testFailToRemoveRolePermissionInDeletedState() throws Exception {
        PolicyConfiguration policyConfiguration = createPolicyConfiguration("third-party-app");

        policyConfiguration.delete();

        try {
            policyConfiguration.removeRole("Administrator");
            fail("Permissions can not be removed when policy configuration is in deleted state.");
        } catch (Exception e) {
            e.printStackTrace();
            assertThat(e, new IsInstanceOf(UnsupportedOperationException.class));
        }
    }

    @Test
    public void testFailToLinkInDeletedState() throws Exception {
        PolicyConfiguration policyConfiguration = createPolicyConfiguration("third-party-app");

        policyConfiguration.delete();

        try {
            PolicyConfiguration linkedPolicyConfiguration = createPolicyConfiguration("third-pary-app/ejb", false);

            policyConfiguration.linkConfiguration(linkedPolicyConfiguration);

            fail("Links can not be added when policy configuration is in deleted state.");
        } catch (Exception e) {
            e.printStackTrace();
            assertThat(e, new IsInstanceOf(UnsupportedOperationException.class));
        }
    }

    @Test
    public void testFailToCommitDeletedState() throws Exception {
        PolicyConfiguration policyConfiguration = createPolicyConfiguration("third-party-app");

        policyConfiguration.delete();

        try {
            policyConfiguration.commit();
            fail("Commit can not be called when policy configuration is in deleted state.");
        } catch (Exception e) {
            e.printStackTrace();
            assertThat(e, new IsInstanceOf(UnsupportedOperationException.class));
        }
    }
}
