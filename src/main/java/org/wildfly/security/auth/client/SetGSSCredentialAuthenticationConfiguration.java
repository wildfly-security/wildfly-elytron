/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
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

import java.io.IOException;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.Sasl;

import org.ietf.jgss.GSSCredential;
import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.auth.client.AuthenticationConfiguration.CredentialSetting;
import org.wildfly.security.credential.GSSCredentialCredential;
import org.wildfly.security.sasl.util.SaslMechanismInformation;

/**
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
class SetGSSCredentialAuthenticationConfiguration extends AuthenticationConfiguration implements CredentialSetting {

    private final GSSCredential credential;

    SetGSSCredentialAuthenticationConfiguration(final AuthenticationConfiguration parent, final GSSCredential credential) {
        super(parent.without(CredentialSetting.class));
        this.credential = credential;
    }

    void handleCallback(final Callback[] callbacks, final int index) throws IOException, UnsupportedCallbackException {
        Callback callback = callbacks[index];
        if (callback instanceof CredentialCallback) {
            CredentialCallback credentialCallback = (CredentialCallback) callback;
            if (credentialCallback.isCredentialTypeSupported(GSSCredentialCredential.class, null)) {
                credentialCallback.setCredential(new GSSCredentialCredential(credential));
                return;
            }
        }
        super.handleCallback(callbacks, index);
    }

    void configureSaslProperties(final Map<String, Object> properties) {
        properties.put(Sasl.CREDENTIALS, credential);
        super.configureSaslProperties(properties);
    }

    boolean filterOneSaslMechanism(final String mechanismName) {
        // not a sure thing but we have to try
        return SaslMechanismInformation.GS2.test(mechanismName) || mechanismName.equals(SaslMechanismInformation.Names.GSSAPI) || super.filterOneSaslMechanism(mechanismName);
    }

    AuthenticationConfiguration reparent(final AuthenticationConfiguration newParent) {
        return new SetGSSCredentialAuthenticationConfiguration(newParent, credential);
    }
}
