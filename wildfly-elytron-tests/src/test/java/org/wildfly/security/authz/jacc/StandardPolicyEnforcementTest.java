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

import org.junit.Test;
import org.wildfly.security.auth.principal.NamePrincipal;

import javax.security.jacc.PolicyConfiguration;
import javax.security.jacc.PolicyContext;
import javax.security.jacc.WebResourcePermission;
import java.security.Policy;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * <p>This test case provides policy enforcement tests solely based on the JACC specification.
 *
 * <p>In this case, all the permissions being evaluated are defined using JACC API without necessarily using any
 * additional permission mapping provided by Elytron. For instance, when configuring a {@link org.wildfly.security.authz.PermissionMapper} for a {@link org.wildfly.security.auth.server.SecurityDomain}.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
// has dependency on wildfly-elytron-realm
@SecurityIdentityRule.RunAs("elytron")
public class StandardPolicyEnforcementTest extends AbstractAuthorizationTestCase {

    @Test
    public void testUncheckedPolicy() throws Exception {
        String contextID = "third-party-app";
        PolicyConfiguration policyConfiguration = createPolicyConfiguration(contextID, toConfigure -> toConfigure.addToUncheckedPolicy(new WebResourcePermission("/webResource", "GET")));

        policyConfiguration.commit();

        PolicyContext.setContextID(contextID);
        Policy policy = Policy.getPolicy();

        assertTrue(policy.implies(createProtectionDomain(), new WebResourcePermission("/webResource", "GET")));
        assertFalse(policy.implies(createProtectionDomain(), new WebResourcePermission("/webResource", "HEAD")));

        policyConfiguration.delete();
    }

    @Test
    public void testExcludedPolicy() throws Exception {
        String contextID = "third-party-app";

        PolicyConfiguration policyConfiguration = createPolicyConfiguration(contextID, toConfigure -> {
                    toConfigure.addToUncheckedPolicy(new WebResourcePermission("/webResource", "GET,PUT"));
                    toConfigure.addToExcludedPolicy(new WebResourcePermission("/webResource", "PUT"));
            }
        );

        policyConfiguration.commit();

        PolicyContext.setContextID(contextID);
        Policy policy = Policy.getPolicy();

        // excluded policies have precedence over any other
        assertFalse(policy.implies(createProtectionDomain(), new WebResourcePermission("/webResource", "PUT")));

        policyConfiguration.delete();
    }

    @Test
    public void testRoleBasedPolicy() throws Exception {
        String contextID = "third-party-app";

        PolicyConfiguration policyConfiguration = createPolicyConfiguration(contextID, toConfigure -> {
            toConfigure.addToRole("Administrator", new WebResourcePermission("/webResource", "POST"));
        });

        policyConfiguration.commit();

        PolicyContext.setContextID(contextID);
        Policy policy = Policy.getPolicy();

        // as defined by JACC specification, roles are specified as principals within a ProtectionDomain and evaluated accordingly.
        assertTrue(policy.implies(createProtectionDomain(new NamePrincipal("Administrator")), new WebResourcePermission("/webResource", "POST")));
        assertFalse(policy.implies(createProtectionDomain(new NamePrincipal("Manager")), new WebResourcePermission("/webResource", "OPTIONS")));

        policyConfiguration.delete();
    }

    @Test
    public void testMultipleRolesBasedPolicy() throws Exception {
        String contextID = "third-party-app";

        PolicyConfiguration policyConfiguration = createPolicyConfiguration(contextID, toConfigure -> {
            toConfigure.addToRole("Administrator", new WebResourcePermission("/webResource", "POST"));
            toConfigure.addToRole("Administrator", new WebResourcePermission("/webResource", "PUT"));
            toConfigure.addToRole("Manager", new WebResourcePermission("/webResource", "PUT"));
        });

        policyConfiguration.commit();

        PolicyContext.setContextID(contextID);
        Policy policy = Policy.getPolicy();

        // as defined by JACC specification, roles are specified as principals within a ProtectionDomain and evaluated accordingly.
        assertTrue(policy.implies(createProtectionDomain(new NamePrincipal("Administrator")), new WebResourcePermission("/webResource", "POST")));
        assertTrue(policy.implies(createProtectionDomain(new NamePrincipal("Administrator")), new WebResourcePermission("/webResource", "PUT")));
        assertTrue(policy.implies(createProtectionDomain(new NamePrincipal("Manager")), new WebResourcePermission("/webResource", "PUT")));
        assertFalse(policy.implies(createProtectionDomain(new NamePrincipal("Administrator")), new WebResourcePermission("/webResource", "GET")));

        policyConfiguration.delete();
    }
}
