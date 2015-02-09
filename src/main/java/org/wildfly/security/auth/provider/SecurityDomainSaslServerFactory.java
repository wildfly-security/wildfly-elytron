/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.auth.provider;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

import org.wildfly.security.auth.AuthenticationConfiguration;
import org.wildfly.security.auth.AuthenticationContext;
import org.wildfly.security.auth.MatchRule;
import org.wildfly.security.auth.callback.AuthenticationCompleteCallback;
import org.wildfly.security.auth.callback.CallbackUtil;
import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.auth.callback.CredentialParameterCallback;
import org.wildfly.security.auth.callback.FastUnsupportedCallbackException;
import org.wildfly.security.auth.callback.PeerPrincipalCallback;
import org.wildfly.security.auth.callback.SecurityLayerDisposedCallback;
import org.wildfly.security.auth.callback.SocketAddressCallback;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.TwoWayPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.sasl.util.AbstractDelegatingSaslServer;
import org.wildfly.security.sasl.util.AbstractDelegatingSaslServerFactory;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class SecurityDomainSaslServerFactory extends AbstractDelegatingSaslServerFactory {

    private final SecurityDomain domain;

    SecurityDomainSaslServerFactory(final SaslServerFactory delegateFactory, final SecurityDomain domain) {
        super(delegateFactory);
        this.domain = domain;
    }

    public SaslServer createSaslServer(final String mechanism, final String protocol, final String serverName, final Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
        final DomainCallbackHandler callbackHandler = new DomainCallbackHandler();
        final SaslServer saslServer = delegate.createSaslServer(mechanism, protocol, serverName, props, callbackHandler);
        if (saslServer == null) {
            return null;
        }
        return new AbstractDelegatingSaslServer(saslServer) {
            public Object getNegotiatedProperty(final String propName) {
                switch (propName) {
                    case "org.wildfly.auth-context": return callbackHandler.context;
                    case "org.wildfly.realm-identity": return callbackHandler.identity;
                    default: return delegate.getNegotiatedProperty(propName);
                }
            }
        };
    }

    class DomainCallbackHandler implements CallbackHandler {
        RealmIdentity identity;
        AuthenticationContext context;

        public RealmIdentity getIdentity() {
            return identity;
        }

        public void handle(final Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            try {
                innerHandle(callbacks);
            } catch (RealmUnavailableException e) {
                throw new IOException(e);
            }
        }

        private void innerHandle(final Callback[] callbacks) throws IOException, UnsupportedCallbackException, RealmUnavailableException {
            for (Callback callback : callbacks) {
                if (callback instanceof NameCallback) {
                    // login name
                    if (identity != null) {
                        throw new SaslException("Mechanism supplied multiple login names");
                    }
                    final String name = ((NameCallback) callback).getName();
                    final RealmIdentity realmIdentity = domain.mapName(name);
                    if (realmIdentity == null) {
                        throw new SaslException("Unknown user name");
                    }
                    identity = realmIdentity;
                } else if (callback instanceof PeerPrincipalCallback) {
                    // login name
                    if (identity != null) {
                        throw new SaslException("Mechanism supplied multiple login names");
                    }
                    final Principal principal = ((PeerPrincipalCallback) callback).getPrincipal();
                    // todo: handle X500 properly
                    final RealmIdentity realmIdentity = domain.mapName(principal.getName());
                    if (realmIdentity == null) {
                        throw new SaslException("Unknown user name");
                    }
                    identity = realmIdentity;
                } else if (callback instanceof PasswordCallback) {
                    final PasswordCallback passwordCallback = (PasswordCallback) callback;
                    // need a plain password
                    if (identity == null) {
                        throw new SaslException("No user identity loaded for credential verification");
                    }
                    final TwoWayPassword credential = identity.getCredential(TwoWayPassword.class);
                    if (credential == null) {
                        // there's a slight hope that we could get a proper credential callback
                        throw new FastUnsupportedCallbackException(callback);
                    }
                    final ClearPasswordSpec clearPasswordSpec;
                    try {
                        final PasswordFactory passwordFactory = PasswordFactory.getInstance(credential.getAlgorithm());
                        clearPasswordSpec = passwordFactory.getKeySpec(credential, ClearPasswordSpec.class);
                    } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
                        // try to fall back to another credential type
                        throw new FastUnsupportedCallbackException(callback);
                    }
                    passwordCallback.setPassword(clearPasswordSpec.getEncodedPassword());
                } else if (callback instanceof CredentialCallback) {
                    final CredentialCallback credentialCallback = (CredentialCallback) callback;
                    if (identity == null) {
                        throw new SaslException("No user identity loaded for credential verification");
                    }
                    for (Class<?> allowedType : credentialCallback.getAllowedTypes()) {
                        if (identity.getCredentialSupport(allowedType).mayBeObtainable()) {
                            final Object credential = identity.getCredential(allowedType);
                            if (credential != null) {
                                credentialCallback.setCredential(credential);
                                break;
                            }
                        }
                    }
                    // otherwise just fall out; some mechanisms will try again with different credentials
                } else if (callback instanceof CredentialParameterCallback) {
                    // ignore for now
                } else if (callback instanceof AuthenticationCompleteCallback) {
                    // todo: this should be streamlined
                    if (identity != null) {
                        final AuthenticationConfiguration conf = AuthenticationConfiguration.EMPTY.usePrincipal((NamePrincipal) identity.getPrincipal());
                        final MatchRule matchRule = MatchRule.ALL.matchLocalSecurityDomain("TODO: security domain name");
                        context = AuthenticationContext.empty().with(matchRule, conf);
                    }
                    // todo: clean up authentication-time resources
                    identity = null;
                } else if (callback instanceof SecurityLayerDisposedCallback) {
                    context = null;
                } else if (callback instanceof SocketAddressCallback) {
                    final SocketAddressCallback socketAddressCallback = (SocketAddressCallback) callback;
                    if (socketAddressCallback.getKind() == SocketAddressCallback.Kind.PEER) {
                        // todo: filter by IP address
                    }
                } else {
                    CallbackUtil.unsupported(callback);
                }
            }
        }
    }
}
