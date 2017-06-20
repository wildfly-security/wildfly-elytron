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
package org.wildfly.security.http.impl;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.wildfly.common.Assert.checkNotNullParam;
import static org.wildfly.security._private.ElytronMessages.log;
import static org.wildfly.security.http.HttpConstants.AUTHORIZATION;
import static org.wildfly.security.http.HttpConstants.CONFIG_GSS_MANAGER;
import static org.wildfly.security.http.HttpConstants.FORBIDDEN;
import static org.wildfly.security.http.HttpConstants.NEGOTIATE;
import static org.wildfly.security.http.HttpConstants.SPNEGO_NAME;
import static org.wildfly.security.http.HttpConstants.UNAUTHORIZED;
import static org.wildfly.security.http.HttpConstants.WWW_AUTHENTICATE;

import java.io.IOException;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.kerberos.KerberosTicket;
import javax.security.sasl.AuthorizeCallback;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.wildfly.security.auth.callback.AuthenticationCompleteCallback;
import org.wildfly.security.auth.callback.IdentityCredentialCallback;
import org.wildfly.security.auth.callback.ServerCredentialCallback;
import org.wildfly.security.credential.GSSKerberosCredential;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpScope;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerRequest;
import org.wildfly.security.http.HttpServerResponse;
import org.wildfly.security.http.Scope;
import org.wildfly.security.mechanism.AuthenticationMechanismException;
import org.wildfly.security.mechanism.MechanismUtil;
import org.wildfly.security.util.ByteIterator;
import org.wildfly.security.util._private.Arrays2;

/**
 * A {@link HttpServerAuthenticationMechanism} implementation to support SPNEGO.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class SpnegoAuthenticationMechanism implements HttpServerAuthenticationMechanism {

    private static final String CHALLENGE_PREFIX = NEGOTIATE + " ";

    private static final String GSS_CONTEXT_KEY = SpnegoAuthenticationMechanism.class.getName() + ".GSSContext";
    private static final String KERBEROS_TICKET = SpnegoAuthenticationMechanism.class.getName() + ".KerberosTicket";

    private final CallbackHandler callbackHandler;
    private final GSSManager gssManager;

    SpnegoAuthenticationMechanism(final CallbackHandler callbackHandler, final Map<String, ?> properties) {
        checkNotNullParam("callbackHandler", callbackHandler);
        checkNotNullParam("properties", properties);

        this.callbackHandler = callbackHandler;
        this.gssManager = properties.containsKey(CONFIG_GSS_MANAGER) ? (GSSManager) properties.get(CONFIG_GSS_MANAGER) : GSSManager.getInstance();
    }

    @Override
    public String getMechanismName() {
        return SPNEGO_NAME;
    }

    @Override
    public void evaluateRequest(HttpServerRequest request) throws HttpAuthenticationException {
        HttpScope connectionScope = request.getScope(Scope.CONNECTION);
        GSSContext gssContext = connectionScope != null ? connectionScope.getAttachment(GSS_CONTEXT_KEY, GSSContext.class) : null;
        KerberosTicket kerberosTicket = connectionScope != null ? connectionScope.getAttachment(KERBEROS_TICKET, KerberosTicket.class) : null;
        log.tracef("Evaluating SPNEGO request: cached GSSContext = %s", gssContext);

        // Do we already have a cached identity? If so use it.
        if (gssContext != null && gssContext.isEstablished() && authorizeCachedGSSContext(gssContext)) {
            log.trace("Successfully authorized using cached identity");
            request.authenticationComplete();
            return;
        }

        if (gssContext == null) { // init GSSContext
            ServerCredentialCallback gssCredentialCallback = new ServerCredentialCallback(GSSKerberosCredential.class);
            final GSSCredential serviceGssCredential;

            try {
                log.trace("Obtaining GSSCredential for the service from callback handler...");
                callbackHandler.handle(new Callback[] { gssCredentialCallback });
                serviceGssCredential = gssCredentialCallback.applyToCredential(GSSKerberosCredential.class, GSSKerberosCredential::getGssCredential);
                kerberosTicket = gssCredentialCallback.applyToCredential(GSSKerberosCredential.class, GSSKerberosCredential::getKerberosTicket);
            } catch (IOException | UnsupportedCallbackException e) {
                throw log.mechCallbackHandlerFailedForUnknownReason(SPNEGO_NAME, e).toHttpAuthenticationException();
            }

            if (serviceGssCredential == null) {
                throw log.unableToObtainServerCredential(SPNEGO_NAME).toHttpAuthenticationException();
            }

            try {
                gssContext = gssManager.createContext(serviceGssCredential);

                if (log.isTraceEnabled()) {
                    log.tracef("Using SpnegoAuthenticationMechanism to authenticate %s using the following mechanisms: [%s]",
                            serviceGssCredential.getName(), Arrays2.objectToString(serviceGssCredential.getMechs()));
                }

                if (connectionScope != null) {
                    connectionScope.setAttachment(GSS_CONTEXT_KEY, gssContext);
                    log.tracef("Caching GSSContext %s", gssContext);
                    connectionScope.setAttachment(KERBEROS_TICKET, kerberosTicket);
                    log.tracef("Caching KerberosTicket %s", kerberosTicket);
                }
            } catch (GSSException e) {
                throw log.mechUnableToCreateGssContext(SPNEGO_NAME, e).toHttpAuthenticationException();
            }
        }

        // authentication exchange
        List<String> authorizationValues = request.getRequestHeaderValues(AUTHORIZATION);
        Optional<String> challenge = authorizationValues != null ? authorizationValues.stream()
                .filter(s -> s.startsWith(CHALLENGE_PREFIX)).limit(1).map(s -> s.substring(CHALLENGE_PREFIX.length()))
                .findFirst() : Optional.empty();

        if (log.isTraceEnabled()) {
            log.tracef("Sent HTTP authorizations: [%s]", Arrays2.objectToString(authorizationValues));
        }

        // Do we have an incoming response to a challenge? If so, process it.
        if (challenge.isPresent()) {
            log.trace("Processing incoming response to a challenge...");

            byte[] decodedValue = ByteIterator.ofBytes(challenge.get().getBytes(UTF_8)).base64Decode().drain();

            Subject subject = new Subject(true, Collections.emptySet(), Collections.emptySet(), kerberosTicket != null ? Collections.singleton(kerberosTicket) : Collections.emptySet());

            byte[] responseToken;
            try {
                final GSSContext finalGssContext = gssContext;
                responseToken = Subject.doAs(subject, (PrivilegedExceptionAction<byte[]>) () -> finalGssContext.acceptSecContext(decodedValue, 0, decodedValue.length));
            } catch (PrivilegedActionException e) {
                Exception cause = e.getCause() instanceof Exception ? (Exception) e.getCause() : e;
                log.trace("Call to acceptSecContext failed.");
                handleCallback(AuthenticationCompleteCallback.FAILED);
                throw log.mechServerSideAuthenticationFailed(SPNEGO_NAME, cause).toHttpAuthenticationException();
            }

            if (gssContext.isEstablished()) {
                final GSSCredential gssCredential;

                try {
                    gssCredential = gssContext.getCredDelegState() ? gssContext.getDelegCred() : null;
                } catch (GSSException e) {
                    log.trace("Unable to access delegated credential despite being delegated.");
                    handleCallback(AuthenticationCompleteCallback.FAILED);

                    throw log.mechServerSideAuthenticationFailed(SPNEGO_NAME, e).toHttpAuthenticationException();
                }

                if (gssCredential != null) {
                    log.trace("Associating delegated GSSCredential with identity.");
                    handleCallback(new IdentityCredentialCallback(new GSSKerberosCredential(gssCredential), true));
                } else {
                    log.trace("No GSSCredential delegated from client.");
                }

                log.trace("GSSContext established, authorizing...");

                final GSSName srcName;
                try {
                    srcName = gssContext.getSrcName();
                    if (srcName == null) {
                        log.trace("Authorization failed - srcName of GSSContext (name of initiator) is null - wrong realm or kdc?");
                        if (connectionScope != null) {
                            connectionScope.setAttachment(GSS_CONTEXT_KEY, null); // clear cache
                        }

                        handleCallback(AuthenticationCompleteCallback.FAILED);
                        throw log.noSrcNameFromGssContext(SPNEGO_NAME).toHttpAuthenticationException();
                    }
                } catch (GSSException e) {
                    log.trace("Unable to obtain srcName from established GSSContext.");
                    if (connectionScope != null) {
                        connectionScope.setAttachment(GSS_CONTEXT_KEY, null); // clear cache
                    }
                    handleCallback(AuthenticationCompleteCallback.FAILED);

                    throw log.mechServerSideAuthenticationFailed(SPNEGO_NAME, e).toHttpAuthenticationException();
                }

                if (authorizeSrcName(srcName, gssContext)) {
                    log.trace("GSSContext established and authorized - authentication complete");
                    request.authenticationComplete(response -> sendChallenge(responseToken, response, 0));

                    return;
                } else {
                    log.trace("Authorization of established GSSContext failed");
                    handleCallback(AuthenticationCompleteCallback.FAILED);
                    request.authenticationFailed(log.authenticationFailed(SPNEGO_NAME), response -> sendChallenge(responseToken, response, FORBIDDEN));
                    return;
                }
            } else if (responseToken != null) {
                log.trace("GSSContext establishing - sending negotiation token to the peer");
                request.authenticationInProgress(response -> sendChallenge(responseToken, response, UNAUTHORIZED));
                return;
            }
        }

        log.trace("Request lacks valid authentication credentials");
        if (connectionScope != null) {
            connectionScope.setAttachment(GSS_CONTEXT_KEY, null); // clear cache
            connectionScope.setAttachment(KERBEROS_TICKET, null); // clear cache
        }
        request.noAuthenticationInProgress(this::sendBareChallenge);
    }

    private void sendBareChallenge(HttpServerResponse response) {
        response.addResponseHeader(WWW_AUTHENTICATE, NEGOTIATE);
        response.setStatusCode(UNAUTHORIZED);
    }

    private void sendChallenge(byte[] responseToken, HttpServerResponse response, int statusCode) {
        if (log.isTraceEnabled()) {
            log.tracef("Sending intermediate challenge: %s", Arrays2.objectToString(responseToken));
        }
        if (responseToken == null) {
            response.addResponseHeader(WWW_AUTHENTICATE, NEGOTIATE);
        } else {
            String responseConverted = ByteIterator.ofBytes(responseToken).base64Encode().drainToString();
            response.addResponseHeader(WWW_AUTHENTICATE, CHALLENGE_PREFIX + responseConverted);
        }
        if (statusCode != 0) {
            response.setStatusCode(statusCode);
        }
    }

    private boolean authorizeCachedGSSContext(GSSContext gssContext) throws HttpAuthenticationException {
        try {
            GSSName srcName = gssContext.getSrcName();
            boolean authorized = srcName != null && authorizeSrcName(srcName, gssContext);
            if (authorized && gssContext.getCredDelegState()) {
                GSSCredential gssCredential = gssContext.getDelegCred();
                if (gssCredential != null) {
                    log.trace("Associating delegated GSSCredential with identity.");
                    handleCallback(new IdentityCredentialCallback(new GSSKerberosCredential(gssCredential), true));
                } else {
                    log.trace("No GSSCredential delegated from client.");
                }
            }
            return authorized;
        } catch (GSSException e) {
            log.trace("GSSException while obtaining srcName of GSSContext (name of initiator)");
            handleCallback(AuthenticationCompleteCallback.FAILED);
            throw log.mechServerSideAuthenticationFailed(SPNEGO_NAME, e).toHttpAuthenticationException();
        }
    }

    private boolean authorizeSrcName(GSSName srcName, GSSContext gssContext) throws HttpAuthenticationException {
        boolean authorized = false;
        try {
            String clientName = srcName.toString();
            AuthorizeCallback authorize = new AuthorizeCallback(clientName, clientName);
            callbackHandler.handle(new Callback[] {authorize});

            authorized = authorize.isAuthorized();
            log.tracef("Authorized by callback handler = %b  clientName = [%s]", authorized, clientName);
        } catch (IOException e) {
            log.trace("IOException during AuthorizeCallback handling", e);
            throw log.mechServerSideAuthenticationFailed(SPNEGO_NAME, e).toHttpAuthenticationException();
        } catch (UnsupportedCallbackException ignored) {
        }

        if (authorized) { // credential delegation
            if (gssContext.getCredDelegState()) {
                try {
                    GSSCredential credential = gssContext.getDelegCred();
                    log.tracef("Credential delegation enabled, delegated credential = %s", credential);
                    MechanismUtil.handleCallbacks(SPNEGO_NAME, callbackHandler, new IdentityCredentialCallback(new GSSKerberosCredential(credential), true));
                } catch (UnsupportedCallbackException ignored) {
                    // ignored
                } catch (AuthenticationMechanismException e) {
                    throw e.toHttpAuthenticationException();
                } catch (GSSException e) {
                    throw new HttpAuthenticationException(e);
                }
            } else {
                log.trace("Credential delegation not enabled");
            }
        }

        handleCallback(authorized ? AuthenticationCompleteCallback.SUCCEEDED : AuthenticationCompleteCallback.FAILED);
        return authorized;
    }

    private void handleCallback(Callback callback) throws HttpAuthenticationException {
        try {
            MechanismUtil.handleCallbacks(SPNEGO_NAME, callbackHandler, callback);
        } catch (AuthenticationMechanismException e) {
            throw e.toHttpAuthenticationException();
        } catch (UnsupportedCallbackException ignored) {
        }
    }

}
