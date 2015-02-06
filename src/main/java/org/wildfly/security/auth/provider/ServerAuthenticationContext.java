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
import java.util.Collections;
import java.util.Map;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocket;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

import org.wildfly.security.auth.callback.AnonymousAuthorizationCallback;
import org.wildfly.security.auth.callback.AuthenticationCompleteCallback;
import org.wildfly.security.auth.callback.CallbackUtil;
import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.auth.callback.CredentialParameterCallback;
import org.wildfly.security.auth.callback.FastUnsupportedCallbackException;
import org.wildfly.security.auth.callback.PeerPrincipalCallback;
import org.wildfly.security.auth.callback.RealmIdentityCallback;
import org.wildfly.security.auth.callback.SocketAddressCallback;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.TwoWayPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.sasl.WildFlySasl;
import org.wildfly.security.sasl.util.AuthenticationCompleteCallbackSaslServerFactory;

/**
 * Server-side authentication context.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public final class ServerAuthenticationContext {

    private static final Map<String, String> QUERY_ALL = Collections.singletonMap(WildFlySasl.MECHANISM_QUERY_ALL, "true");

    private final SecurityDomain domain;

    private boolean done = false;

    ServerAuthenticationContext(final SecurityDomain domain) {
        this.domain = domain;
    }

    /**
     * Create a SASL server that will authenticate against this security domain.  The selected mechanism name should
     * be one of the names returned by {@link SecurityDomain#getSaslServerMechanismNames(SaslServerFactory)} for the given factory.
     * If the SASL server failed to be constructed for some reason, a {@code SaslException} is thrown.
     *
     * @param saslServerFactory the SASL server factory
     * @param serverName the server name, or {@code null} to create an unbound SASL server (if allowed by the mechanism)
     * @param mechanismName the selected mechanism name
     * @param protocol the protocol which is currently in use
     * @return the SASL server
     * @throws SaslException if creating the SASL server failed for some reason
     */
    public SaslServer createSaslServer(SaslServerFactory saslServerFactory, String serverName, String mechanismName, String protocol) throws SaslException {
        if (done) {
            throw new SaslException("Authentication already performed");
        }
        return new AuthenticationCompleteCallbackSaslServerFactory(saslServerFactory).createSaslServer(mechanismName, protocol, serverName, QUERY_ALL, createCallbackHandler());
    }

    /**
     * Create a server-side SSL engine that authenticates using this authentication context.
     *
     * @return the SSL engine
     */
    public SSLEngine createServerSslEngine() {
        throw new UnsupportedOperationException();
    }

    /**
     * Create a server-side SSL socket that authenticates using this authentication context.
     *
     * @return the SSL socket
     */
    public SSLSocket createServerSslSocket() {
        throw new UnsupportedOperationException();
    }

    CallbackHandler createCallbackHandler() {
        return new CallbackHandler() {
            RealmIdentity identity;

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
                        final char[] providedPassword = passwordCallback.getPassword();
                        if (providedPassword != null) {
                            // todo: verification API, fall back to acquiring any Password
                            throw new IllegalStateException("At this point we would verify the password instead of acquiring it");
                        } else {
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
                        }
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
                    } else if (callback instanceof AnonymousAuthorizationCallback) {
                        // todo: check configuration to see if anonymous login is allowed
                        ((AnonymousAuthorizationCallback) callback).setAuthorized(domain.isAnonymousAllowed());
                    } else if (callback instanceof AuthenticationCompleteCallback) {
                        // todo: clean up authentication-time resources
                        identity = null;
                        done = true;
                    } else if (callback instanceof SocketAddressCallback) {
                        final SocketAddressCallback socketAddressCallback = (SocketAddressCallback) callback;
                        if (socketAddressCallback.getKind() == SocketAddressCallback.Kind.PEER) {
                            // todo: filter by IP address
                        }
                    } else if (callback instanceof RealmIdentityCallback) {
                        ((RealmIdentityCallback) callback).setRealmIdentity(identity);
                    } else {
                        CallbackUtil.unsupported(callback);
                    }
                }
            }
        };
    }
}
