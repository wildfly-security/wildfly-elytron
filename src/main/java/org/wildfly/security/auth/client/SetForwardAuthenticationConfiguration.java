/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.auth.client;

import static java.security.AccessController.doPrivileged;
import static org.wildfly.common.math.HashMath.multiHashUnordered;

import java.security.AccessControlContext;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.util.Objects;

import org.wildfly.security.auth.client.AuthenticationConfiguration.CredentialSetting;
import org.wildfly.security.auth.client.AuthenticationConfiguration.UserSetting;
import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.credential.source.CredentialSource;
import org.wildfly.security.sasl.util.SaslMechanismInformation;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class SetForwardAuthenticationConfiguration extends AuthenticationConfiguration implements UserSetting, CredentialSetting{

    private final SecurityDomain sourceDomain;
    private final AccessControlContext context;

    SetForwardAuthenticationConfiguration(final AuthenticationConfiguration parent, final SecurityDomain sourceDomain, final AccessControlContext context) {
        super(parent.without(UserSetting.class, CredentialSetting.class, SetCallbackHandlerAuthenticationConfiguration.class));
        this.sourceDomain = sourceDomain;
        this.context = context;
    }

    private IdentityCredentials getPrivateCredentials(SecurityIdentity identity, AccessControlContext context) {
        return doPrivileged((PrivilegedAction<IdentityCredentials>) identity::getPrivateCredentials, context);
    }

    boolean saslSupportedByConfiguration(final String mechanismName) {
        return sourceDomain.getCurrentSecurityIdentity().isAnonymous() && SaslMechanismInformation.Names.ANONYMOUS.equals(mechanismName) || super.saslSupportedByConfiguration(mechanismName);
    }

    Principal getPrincipal() {
        return sourceDomain.getCurrentSecurityIdentity().getPrincipal();
    }

    CredentialSource getCredentialSource() {
        return getPrivateCredentials(sourceDomain.getCurrentSecurityIdentity(), context);
    }

    AuthenticationConfiguration reparent(final AuthenticationConfiguration newParent) {
        return new SetForwardAuthenticationConfiguration(newParent, sourceDomain, context);
    }

    boolean halfEqual(final AuthenticationConfiguration other) {
        return Objects.equals(sourceDomain, other.getForwardSecurityDomain()) && Objects.equals(context, other.getForwardAccessControlContext()) && parentHalfEqual(other);
    }

    SecurityDomain getForwardSecurityDomain() {
        return sourceDomain;
    }

    AccessControlContext getForwardAccessControlContext() {
        return context;
    }

    int calcHashCode() {
        return multiHashUnordered(multiHashUnordered(parentHashCode(), 2551, Objects.hashCode(sourceDomain)), 2113, Objects.hashCode(context));
    }

    @Override
    StringBuilder asString(StringBuilder sb) {
        return parentAsString(sb).append("ForwardAuthentication,");
    }

}
