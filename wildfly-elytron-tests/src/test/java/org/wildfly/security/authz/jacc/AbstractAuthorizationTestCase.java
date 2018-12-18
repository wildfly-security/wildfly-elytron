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

import org.junit.BeforeClass;
import org.junit.Rule;
import org.wildfly.security.auth.permission.RunAsPrincipalPermission;
import org.wildfly.security.auth.realm.LegacyPropertiesSecurityRealm;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.authz.Roles;
import org.wildfly.security.permission.PermissionVerifier;

import javax.security.jacc.PolicyConfiguration;
import javax.security.jacc.PolicyConfigurationFactory;
import javax.security.jacc.PolicyContextException;
import java.io.IOException;
import java.security.Policy;
import java.security.Principal;
import java.security.ProtectionDomain;
import java.util.HashSet;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
// has dependency on wildfly-elytron-realm
public abstract class AbstractAuthorizationTestCase {

    @BeforeClass
    public static void onBeforeClass() {
        System.setProperty("javax.security.jacc.PolicyConfigurationFactory.provider", ElytronPolicyConfigurationFactory.class.getName());
        Policy.setPolicy(new JaccDelegatingPolicy());
    }

    @Rule
    public SecurityIdentityRule securityIdentityRule;
    private final SecurityDomain securityDomain;

    public AbstractAuthorizationTestCase() {
        this.securityDomain = createSecurityDomain();
        this.securityIdentityRule = new SecurityIdentityRule(securityDomain);
    }

    protected SecurityDomain createSecurityDomain() {
        SecurityDomain.Builder builder = SecurityDomain.builder();
        SecurityRealm realm;

        try {
            realm = LegacyPropertiesSecurityRealm.builder()
                    .setUsersStream(getClass().getResourceAsStream("clear.properties"))
                    .setPlainText(true)
                    .build();
        } catch (IOException e) {
            throw new RuntimeException("Error creating security realm.", e);
        }

        builder.setDefaultRealmName("default");

        builder.setPermissionMapper((permissionMappable, roles) -> PermissionVerifier.from(new RunAsPrincipalPermission("*")));

        builder.addRealm("default",realm).setRoleMapper(rolesToMap -> {
            HashSet<String> roles = new HashSet<>();

            roles.add("Administrator");
            roles.add("Manager");

            return Roles.fromSet(roles);
        }).build();

        return builder.build();
    }

    protected ElytronPolicyConfiguration createPolicyConfiguration(String contextID, ConfigurePoliciesAction configurationAction) throws ClassNotFoundException, PolicyContextException {
        ElytronPolicyConfiguration policyConfiguration = createPolicyConfiguration(contextID);

        configurationAction.configure(policyConfiguration);

        return policyConfiguration;
    }

    protected ElytronPolicyConfiguration createPolicyConfiguration(String contextID) throws ClassNotFoundException, PolicyContextException {
        ElytronPolicyConfigurationFactory policyConfigurationFactory = (ElytronPolicyConfigurationFactory) PolicyConfigurationFactory.getPolicyConfigurationFactory();

        return (ElytronPolicyConfiguration) policyConfigurationFactory.getPolicyConfiguration(contextID, false);
    }

    protected ElytronPolicyConfiguration createPolicyConfiguration(String contextID, boolean create) throws ClassNotFoundException, PolicyContextException {
        ElytronPolicyConfigurationFactory policyConfigurationFactory = (ElytronPolicyConfigurationFactory) PolicyConfigurationFactory.getPolicyConfigurationFactory();

        return (ElytronPolicyConfiguration) policyConfigurationFactory.getPolicyConfiguration(contextID, create);
    }

    protected ProtectionDomain createProtectionDomain(Principal... principals) {
        return new ProtectionDomain(null, getClass().getProtectionDomain().getPermissions(), null, principals);
    }

    protected interface ConfigurePoliciesAction {
        void configure(PolicyConfiguration toConfigure) throws PolicyContextException;
    }
}
