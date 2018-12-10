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

import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;

import javax.security.jacc.PolicyConfiguration;
import javax.security.jacc.PolicyContextException;
import javax.security.jacc.PolicyContextHandler;
import java.util.Map;

import static org.wildfly.common.Assert.checkNotNullParam;

/**
 * <p>A {@link PolicyContextHandler} that holds the relationship between a {@link SecurityDomain} and its corresponding
 * context identifier in JACC.
 *
 * <p>This handler should be installed wherever is necessary to perform permission checks based on the permissions associated
 * with the {@link SecurityIdentity} instances obtained and associated with a given {@link SecurityDomain}. In this case,
 * permission checks will be done based on the permissions managed by JACC and also on those associated with an authorized identity in Elytron.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class SecurityIdentityHandler implements PolicyContextHandler {

    static final String KEY = SecurityIdentity.class.getName();

    private final Map<String, SecurityDomain> securityDomains;

    public SecurityIdentityHandler(Map<String, SecurityDomain> securityDomains) {
        checkNotNullParam("securityDomains", securityDomains);
        this.securityDomains = securityDomains;
    }

    @Override
    public Object getContext(String key, Object data) throws PolicyContextException {
        if (supports(key)) {
            PolicyConfiguration policyConfiguration = ElytronPolicyConfigurationFactory.getCurrentPolicyConfiguration();
            SecurityDomain securityDomain = this.securityDomains.get(policyConfiguration.getContextID());

            if (securityDomain != null) {
                return securityDomain.getCurrentSecurityIdentity();
            }
        }

        return null;
    }

    @Override
    public String[] getKeys() throws PolicyContextException {
        return new String[] {KEY};
    }

    @Override
    public boolean supports(String key) throws PolicyContextException {
        return KEY.equalsIgnoreCase(key);
    }
}
