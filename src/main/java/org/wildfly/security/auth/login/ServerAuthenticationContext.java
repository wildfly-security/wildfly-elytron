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

package org.wildfly.security.auth.login;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.spec.InvalidKeySpecException;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

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

import org.wildfly.common.Assert;
import org.wildfly.security._private.ElytronMessages;
import org.wildfly.security.auth.callback.AnonymousAuthorizationCallback;
import org.wildfly.security.auth.callback.AuthenticationCompleteCallback;
import org.wildfly.security.auth.callback.CallbackUtil;
import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.auth.callback.CredentialParameterCallback;
import org.wildfly.security.auth.callback.FastUnsupportedCallbackException;
import org.wildfly.security.auth.callback.PeerPrincipalCallback;
import org.wildfly.security.auth.callback.RealmIdentityCallback;
import org.wildfly.security.auth.callback.SocketAddressCallback;
import org.wildfly.security.auth.spi.RealmIdentity;
import org.wildfly.security.auth.spi.RealmUnavailableException;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.TwoWayPassword;
import org.wildfly.security.password.interfaces.ClearPassword;
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
    private final AtomicReference<State> stateRef = new AtomicReference<>(INITIAL);

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
     * @throws IllegalStateException if authentication was already initiated on this context
     */
    public SaslServer createSaslServer(SaslServerFactory saslServerFactory, String serverName, String mechanismName, String protocol) throws SaslException, IllegalStateException {
        Assert.checkNotNullParam("saslServerFactory", saslServerFactory);
        Assert.checkNotNullParam("mechanismName", mechanismName);
        Assert.checkNotNullParam("protocol", protocol);
        State oldState;
        do {
            oldState = stateRef.get();
            if (oldState != INITIAL) {
                throw ElytronMessages.log.alreadyInitiated();
            }
        } while (! stateRef.compareAndSet(INITIAL, IN_PROGRESS));
        return new AuthenticationCompleteCallbackSaslServerFactory(saslServerFactory).createSaslServer(mechanismName, protocol, serverName, QUERY_ALL, createCallbackHandler());
    }

    /**
     * Create a server-side SSL engine that authenticates using this authentication context.
     *
     * @return the SSL engine
     * @throws IllegalStateException if authentication was already initiated on this context
     */
    public SSLEngine createServerSslEngine() throws IllegalStateException {
        State oldState;
        do {
            oldState = stateRef.get();
            if (oldState != INITIAL) {
                throw ElytronMessages.log.alreadyInitiated();
            }
        } while (! stateRef.compareAndSet(INITIAL, IN_PROGRESS));
        throw new UnsupportedOperationException();
    }

    /**
     * Create a server-side SSL socket that authenticates using this authentication context.
     *
     * @return the SSL socket
     * @throws IllegalStateException if authentication was already initiated on this context
     */
    public SSLSocket createServerSslSocket() throws IllegalStateException {
        State oldState;
        do {
            oldState = stateRef.get();
            if (oldState != INITIAL) {
                throw ElytronMessages.log.alreadyInitiated();
            }
        } while (! stateRef.compareAndSet(INITIAL, IN_PROGRESS));
        throw new UnsupportedOperationException();
    }

    /**
     * Get the authorized identity result of this authentication.
     *
     * @return the authorized identity
     * @throws IllegalStateException if the authentication is incomplete
     */
    public SecurityIdentity getAuthorizedIdentity() throws IllegalStateException {
        return stateRef.get().getAuthorizedIdentity();
    }

    CallbackHandler createCallbackHandler() {
        return new CallbackHandler() {
            RealmIdentity identity;

            public void handle(final Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                try {
                    handleOne(callbacks, 0);
                } catch (RealmUnavailableException e) {
                    throw new IOException(e);
                }
            }

            private void handleOne(final Callback[] callbacks, final int idx) throws IOException, UnsupportedCallbackException, RealmUnavailableException {
                if (idx == callbacks.length) {
                    return;
                }
                Callback callback = callbacks[idx];
                if (callback instanceof NameCallback) {
                    // login name
                    if (identity != null) {
                        identity.dispose();
                        identity = null;
                    }
                    final String name = ((NameCallback) callback).getName();
                    final RealmIdentity realmIdentity = domain.mapName(name);
                    if (realmIdentity == null) {
                        throw new SaslException("Unknown user name");
                    }
                    identity = realmIdentity;
                    try {
                        handleOne(callbacks, idx + 1);
                    } catch (Throwable t) {
                        identity = null;
                        throw t;
                    }
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
                    try {
                        handleOne(callbacks, idx + 1);
                    } catch (Throwable t) {
                        identity = null;
                        throw t;
                    }
                } else if (callback instanceof PasswordCallback) {
                    final PasswordCallback passwordCallback = (PasswordCallback) callback;
                    // need a plain password
                    RealmIdentity identity = this.identity;
                    if (identity == null) {
                        throw new SaslException("No user identity loaded for credential verification");
                    }
                    final char[] providedPassword = passwordCallback.getPassword();
                    if (providedPassword != null) {
                        if (identity.getCredentialSupport(char[].class).isDefinitelyVerifiable() && ! identity.verifyCredential(providedPassword)) {
                            throw new SaslException("Invalid password");
                        } else if (identity.getCredentialSupport(TwoWayPassword.class).isDefinitelyVerifiable()) {
                            try {
                                final PasswordFactory passwordFactory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR);
                                final Password password = passwordFactory.generatePassword(new ClearPasswordSpec(providedPassword));
                                if (! identity.verifyCredential(password)) {
                                    throw new SaslException("Invalid password");
                                }
                            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                                throw new SaslException("Password verification not supported", e);
                            }
                        } else {
                            throw new SaslException("Password verification not supported");
                        }
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
                    handleOne(callbacks, idx + 1);
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
                    handleOne(callbacks, idx + 1);
                } else if (callback instanceof CredentialParameterCallback) {
                    // ignore for now
                    handleOne(callbacks, idx + 1);
                } else if (callback instanceof AnonymousAuthorizationCallback) {
                    ((AnonymousAuthorizationCallback) callback).setAuthorized(domain.isAnonymousAllowed());
                    handleOne(callbacks, idx + 1);
                } else if (callback instanceof AuthenticationCompleteCallback) {
                    if (((AuthenticationCompleteCallback) callback).succeeded()) {
                        stateRef.set(new CompleteState(new SecurityIdentity(domain, identity.getAuthorizationIdentity())));
                    } else {
                        stateRef.set(FAILED);
                    }
                    identity = null;
                    handleOne(callbacks, idx + 1);
                } else if (callback instanceof SocketAddressCallback) {
                    final SocketAddressCallback socketAddressCallback = (SocketAddressCallback) callback;
                    if (socketAddressCallback.getKind() == SocketAddressCallback.Kind.PEER) {
                        // todo: filter by IP address
                    }
                    handleOne(callbacks, idx + 1);
                } else if (callback instanceof RealmIdentityCallback) {
                    ((RealmIdentityCallback) callback).setRealmIdentity(identity);
                    handleOne(callbacks, idx + 1);
                } else {
                    CallbackUtil.unsupported(callback);
                }
            }
        };
    }

    abstract static class State {
        abstract int getId();

        abstract SecurityIdentity getAuthorizedIdentity();
    }

    static final class SimpleState extends State {
        private final int id;

        SimpleState(final int id) {
            this.id = id;
        }

        public int getId() {
            return id;
        }

        SecurityIdentity getAuthorizedIdentity() {
            throw ElytronMessages.log.noSuccessfulAuthentication();
        }
    }

    static final class CompleteState extends State {
        private final SecurityIdentity identity;

        public CompleteState(final SecurityIdentity identity) {
            this.identity = identity;
        }

        int getId() {
            return 3;
        }

        SecurityIdentity getAuthorizedIdentity() {
            return identity;
        }
    }

    private static final SimpleState INITIAL = new SimpleState(0);
    private static final SimpleState IN_PROGRESS = new SimpleState(1);
    private static final SimpleState FAILED = new SimpleState(2);
}
