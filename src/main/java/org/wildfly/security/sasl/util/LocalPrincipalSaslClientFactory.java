/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.sasl.util;

import java.io.IOException;
import java.security.Principal;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import javax.net.ssl.SSLSession;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.x500.X500Principal;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;

import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.auth.callback.SSLCallback;
import org.wildfly.security.auth.principal.AnonymousPrincipal;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.X509CertificateChainCredential;
import org.wildfly.security.sasl.WildFlySasl;

/**
 * A delegating SASL client factory whose instances can track and return the assumed principal used for authentication.  Use
 * the {@link WildFlySasl#PRINCIPAL} negotiated property to retrieve the principal.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class LocalPrincipalSaslClientFactory extends AbstractDelegatingSaslClientFactory {

    /**
     * Construct a new instance.
     *
     * @param delegate the delegate client factory (must not be {@code null})
     */
    public LocalPrincipalSaslClientFactory(final SaslClientFactory delegate) {
        super(delegate);
    }

    public SaslClient createSaslClient(final String[] mechanisms, final String authorizationId, final String protocol, final String serverName, final Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
        Supplier<Principal> principalSupplier;
        CallbackHandler realCallbackHandler;
        if (authorizationId != null) {
            Principal principal = new NamePrincipal(authorizationId);
            principalSupplier = () -> principal;
            realCallbackHandler = cbh;
        } else {
            final ClientPrincipalQueryCallbackHandler handler = new ClientPrincipalQueryCallbackHandler(cbh);
            principalSupplier = handler::getPrincipal;
            realCallbackHandler = handler;
        }
        final SaslClient delegate = super.createSaslClient(mechanisms, authorizationId, protocol, serverName, props, realCallbackHandler);
        if (delegate == null) {
            return null;
        }
        return new LocalPrincipalSaslClient(delegate, principalSupplier);
    }

    static final class ClientPrincipalQueryCallbackHandler implements CallbackHandler {
        private final CallbackHandler delegate;
        private final AtomicReference<Principal> principalRef = new AtomicReference<>(AnonymousPrincipal.getInstance());

        ClientPrincipalQueryCallbackHandler(final CallbackHandler delegate) {
            this.delegate = delegate;
        }

        public void handle(final Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            try {
                delegate.handle(callbacks);
            } finally {
                // try to determine the used principal
                for (Callback callback : callbacks) {
                    if (callback instanceof NameCallback) {
                        final String name = ((NameCallback) callback).getName();
                        if (name != null) {
                            principalRef.set(new NamePrincipal(name));
                        }
                    } else if (callback instanceof CredentialCallback) {
                        final Credential credential = ((CredentialCallback) callback).getCredential();
                        if (credential instanceof X509CertificateChainCredential) {
                            final X500Principal principal = ((X509CertificateChainCredential) credential).getFirstCertificate().getSubjectX500Principal();
                            if (principal != null) {
                                principalRef.set(principal);
                            }
                        }
                    } else if (callback instanceof SSLCallback) {
                        // SSL callback always comes before name callback
                        final SSLSession sslSession = ((SSLCallback) callback).getSslConnection().getSession();
                        if (sslSession != null) {
                            final Principal localPrincipal = sslSession.getLocalPrincipal();
                            if (localPrincipal != null) {
                                principalRef.set(localPrincipal);
                            }
                        }
                    }
                }
            }
        }

        public Principal getPrincipal() {
            return principalRef.get();
        }
    }

    final class LocalPrincipalSaslClient extends AbstractDelegatingSaslClient {
        private final Supplier<Principal> principalSupplier;

        LocalPrincipalSaslClient(final SaslClient delegate, final Supplier<Principal> principalSupplier) {
            super(delegate);
            this.principalSupplier = principalSupplier;
        }

        @Override
        public Object getNegotiatedProperty(final String propName) {
            // The mechanism might be smart enough to know its principal; if so, use their value instead of our guess.
            final Object value = super.getNegotiatedProperty(propName);
            return value == null && WildFlySasl.PRINCIPAL.equals(propName) ? principalSupplier.get() : value;
        }
    }
}
