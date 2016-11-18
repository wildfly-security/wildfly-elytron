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

import java.io.IOException;
import java.security.AccessControlContext;
import java.security.Principal;
import java.security.PrivilegedAction;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.auth.client.AuthenticationConfiguration.CredentialSetting;
import org.wildfly.security.auth.client.AuthenticationConfiguration.UserSetting;
import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.sasl.util.SaslMechanismInformation;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class SetForwardAuthenticationConfiguration extends AuthenticationConfiguration implements UserSetting, CredentialSetting{

    private final SecurityDomain sourceDomain;
    private final AccessControlContext context;

    SetForwardAuthenticationConfiguration(final AuthenticationConfiguration parent, final SecurityDomain sourceDomain, final AccessControlContext context) {
        super(parent.without(UserSetting.class, CredentialSetting.class));
        this.sourceDomain = sourceDomain;
        this.context = context;
    }

    void handleCallback(final Callback[] callbacks, final int index) throws UnsupportedCallbackException, IOException {
        Callback callback = callbacks[index];
        final SecurityIdentity identity = sourceDomain.getCurrentSecurityIdentity();
        if (! identity.isAnonymous()) {
            if (callback instanceof NameCallback) {
                ((NameCallback) callback).setName(doRewriteUser(identity.getPrincipal().getName()));
            } else if (callback instanceof CredentialCallback) {
                final CredentialCallback credentialCallback = (CredentialCallback) callback;
                final Class<? extends Credential> credentialType = credentialCallback.getCredentialType();
                final String algorithm = credentialCallback.getAlgorithm();
                final IdentityCredentials privateCredentials = getPrivateCredentials(identity, context);
                final Credential credential = privateCredentials.getCredential(credentialType, algorithm);
                if (credential != null) {
                    credentialCallback.setCredential(credential);
                }
            } else if (callback instanceof PasswordCallback) {
                final IdentityCredentials privateCredentials = getPrivateCredentials(identity, context);
                final PasswordCredential credential = privateCredentials.getCredential(PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR);
                if (credential != null) {
                    final ClearPassword clearPassword = credential.getPassword(ClearPassword.class);
                    if (clearPassword != null) {
                        // likely always true, but just to be safe...
                        ((PasswordCallback) callback).setPassword(clearPassword.getPassword());
                    }
                }
            } else {
                super.handleCallback(callbacks, index);
            }
        }
    }

    private IdentityCredentials getPrivateCredentials(SecurityIdentity identity, AccessControlContext context) {
        return doPrivileged((PrivilegedAction<IdentityCredentials>) identity::getPrivateCredentials, context);
    }

    boolean filterOneSaslMechanism(final String mechanismName) {
        return sourceDomain.getCurrentSecurityIdentity().isAnonymous() ? SaslMechanismInformation.Names.ANONYMOUS.equals(mechanismName) : super.filterOneSaslMechanism(mechanismName);
    }

    Principal getPrincipal() {
        return sourceDomain.getCurrentSecurityIdentity().getPrincipal();
    }

    AuthenticationConfiguration reparent(final AuthenticationConfiguration newParent) {
        return new SetForwardAuthenticationConfiguration(newParent, sourceDomain, context);
    }

    @Override
    StringBuilder asString(StringBuilder sb) {
        return parentAsString(sb).append("ForwardAuthentication,");
    }

}
