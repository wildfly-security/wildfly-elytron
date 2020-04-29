/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2019 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.authz;

import static org.wildfly.common.Assert.checkNotNullParam;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A decoder to obtain role information using the source IP address runtime attribute from the identity.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class SourceAddressRoleDecoder implements RoleDecoder {

    private String sourceAddress;
    private Pattern sourceAddressPattern;
    private Roles roles;

    /**
     * Construct a new instance.
     *
     * @param sourceAddress the source IP address to match (cannot be {@code null})
     * @param roles the roles to associate with the identity if the actual source IP address matches
     *              the given source IP address
     */
    public SourceAddressRoleDecoder(String sourceAddress, Roles roles) {
        checkNotNullParam("sourceAddress", sourceAddress);
        checkNotNullParam("roles", roles);
        this.sourceAddress = sourceAddress;
        this.roles = roles;
    }

    /**
     * Construct a new instance.
     *
     * @param sourceAddressPattern the source IP address pattern to match (cannot be {@code null})
     * @param roles the roles to associate with the identity if the actual source IP address matches
     *              the given pattern
     */
    public SourceAddressRoleDecoder(Pattern sourceAddressPattern, Roles roles) {
        checkNotNullParam("sourceAddressPattern", sourceAddressPattern);
        checkNotNullParam("roles", roles);
        this.sourceAddressPattern = sourceAddressPattern;
        this.roles = roles;
    }

    /**
     * Decode the role set using the source IP address runtime attribute from the given authorization identity.
     *
     * @param authorizationIdentity the authorization identity (not {@code null})
     * @return the role set (must not be {@code null})
     */
    public Roles decodeRoles(AuthorizationIdentity authorizationIdentity) {
        Attributes runtimeAttributes = authorizationIdentity.getRuntimeAttributes();
        if (runtimeAttributes.containsKey(KEY_SOURCE_ADDRESS)) {
            String actualSourceAddress = runtimeAttributes.getFirst(KEY_SOURCE_ADDRESS);
            if (actualSourceAddress != null) {
                if (sourceAddress != null) {
                    if (sourceAddress.equals(actualSourceAddress)) {
                        return roles;
                    }
                } else {
                    final Matcher matcher = sourceAddressPattern.matcher(actualSourceAddress);
                    if (matcher.matches()) {
                        return roles;
                    }
                }
            }
        }
        return Roles.NONE;
    }
}
