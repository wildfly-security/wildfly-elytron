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

package org.wildfly.security.sasl.gssapi;

import static org.wildfly.security.sasl.util.SaslMechanismInformation.Names.GSSAPI;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.MessageProp;
import org.ietf.jgss.Oid;
import org.jboss.logging.Logger;
import org.wildfly.common.Assert;
import org.wildfly.security._private.ElytronMessages;
import org.wildfly.security.auth.callback.IdentityCredentialCallback;
import org.wildfly.security.auth.callback.ServerCredentialCallback;
import org.wildfly.security.credential.GSSKerberosCredential;

/**
 * SaslServer for the GSSAPI mechanism as defined by RFC 4752
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
final class GssapiServer extends AbstractGssapiMechanism implements SaslServer {

    private static final ElytronMessages log = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security.sasl.gssapi.server");

    private static final int ACCEPTOR_STATE = 1;
    private static final int SECURITY_LAYER_ADVERTISER = 2;
    private static final int SECURITY_LAYER_RECEIVER = 3;

    private String authorizationId;

    private byte offeredSecurityLayer;

    GssapiServer(final String protocol, final String serverName, final Map<String, ?> props,
            final CallbackHandler callbackHandler) throws SaslException {
        super(GSSAPI, protocol, serverName, props, callbackHandler, log);

        // Initialise our GSSContext
        GSSManager manager = GSSManager.getInstance();

        GSSContext gssContext = null;

        GSSCredential ourCredential = null;

        ServerCredentialCallback gssCredentialCallback = new ServerCredentialCallback(GSSKerberosCredential.class);
        try {
            log.trace("Obtaining GSSCredential for the service from callback handler...");
            callbackHandler.handle(new Callback[] { gssCredentialCallback });
            ourCredential = gssCredentialCallback.applyToCredential(GSSKerberosCredential.class, GSSKerberosCredential::getGssCredential);
        } catch (IOException e) {
            throw log.mechCallbackHandlerFailedForUnknownReason(GSSAPI, e).toSaslException();
        } catch (UnsupportedCallbackException e) {
            log.trace("Unable to obtain GSSCredential from CallbackHandler", e);
        }

        try {
            if (ourCredential == null) {
                // According to the Javadoc we will have a protocol and server name.
                String localName = protocol + "@" + serverName;
                log.tracef("Our name '%s'", localName);

                GSSName ourName = manager.createName(localName, GSSName.NT_HOSTBASED_SERVICE, KERBEROS_V5);
                ourCredential = manager.createCredential(ourName, GSSContext.INDEFINITE_LIFETIME, KERBEROS_V5,
                        GSSCredential.ACCEPT_ONLY);
            }

            gssContext = manager.createContext(ourCredential);
        } catch (GSSException e) {
            throw log.mechUnableToCreateGssContext(getMechanismName(), e).toSaslException();
        }
        // We don't request integrity or confidentiality as that is only
        // supported on the client side.

        this.gssContext = gssContext;
    }

    @Override
    public void init() {
        setNegotiationState(ACCEPTOR_STATE);
    }

    @Override
    public String getAuthorizationID() {
        assertComplete();

        return authorizationId;
    }

    @Override
    public byte[] evaluateResponse(byte[] response) throws SaslException {
        return evaluateMessage(response);
    }

    @Override
    protected byte[] evaluateMessage(int state, final byte[] message) throws SaslException {
        switch (state) {
            case ACCEPTOR_STATE:
                assert gssContext.isEstablished() == false;

                try {
                    byte[] response = gssContext.acceptSecContext(message, 0, message.length);

                    if (gssContext.isEstablished()) {
                        Oid actualMech = gssContext.getMech();
                        log.tracef("Negotiated mechanism %s", actualMech);
                        if (KERBEROS_V5.equals(actualMech) == false) {
                            throw log.mechNegotiatedMechanismWasNotKerberosV5(getMechanismName()).toSaslException();
                        }

                        setNegotiationState(SECURITY_LAYER_ADVERTISER);

                        if (response == null || response.length == 0) {
                            log.trace("No response so triggering next state immediately.");
                            return evaluateMessage(null);
                        }
                    } else {
                        log.trace("GSSContext not established, expecting subsequent exchange.");
                    }

                    return response;
                } catch (GSSException e) {
                    throw log.mechUnableToAcceptClientMessage(getMechanismName(), e).toSaslException();
                }

            case SECURITY_LAYER_ADVERTISER:
                // This state expects at most to be called with an empty message, it will then advertise
                // the currently support security layer and transition to the next state to await a response
                if (message != null && message.length > 0) {
                    throw log.mechInitialChallengeMustBeEmpty(getMechanismName()).toSaslException();
                }

                byte[] response = new byte[4];

                byte supportedSecurityLayers = 0x00;

                boolean offeringSecurityLayer = false;
                for (QOP current : orderedQops) {
                    switch (current) {
                        case AUTH_INT:
                            if (gssContext.getIntegState()) {
                                supportedSecurityLayers |= current.getValue();
                                offeringSecurityLayer = true;
                                log.trace("Offering AUTH_INT");
                            } else {
                                log.trace("No integrity protection so unable to offer AUTH_INT");
                            }
                            break;
                        case AUTH_CONF:
                            if (gssContext.getConfState()) {
                                supportedSecurityLayers |= current.getValue();
                                offeringSecurityLayer = true;
                                log.trace("Offering AUTH_CONF");
                            } else {
                                log.trace("No confidentiality available so unable to offer AUTH_CONF");
                            }
                            break;
                        default:
                            supportedSecurityLayers |= current.getValue();
                    }
                }

                if (supportedSecurityLayers == 0x00) {
                    throw log.mechInsufficientQopsAvailable(getMechanismName()).toSaslException();
                }

                response[0] = supportedSecurityLayers;
                try {
                    byte[] length;

                    if (offeringSecurityLayer) {
                        log.tracef("Our max buffer size %d", configuredMaxReceiveBuffer);
                        length = intToNetworkOrderBytes(configuredMaxReceiveBuffer);
                    } else {
                        log.trace("Not offering a security layer so zero length.");
                        length = new byte[] { 0x00, 0x00, 0x00 };
                    }
                    System.arraycopy(length, 0, response, 1, 3);

                    MessageProp msgProp = new MessageProp(0, false);
                    response = gssContext.wrap(response, 0, 4, msgProp);
                } catch (GSSException e) {
                    throw log.mechUnableToGenerateChallenge(getMechanismName(), e).toSaslException();
                }

                log.trace("Transitioning to receive chosen security layer from client");
                offeredSecurityLayer = supportedSecurityLayers;
                setNegotiationState(SECURITY_LAYER_RECEIVER);

                return response;
            case SECURITY_LAYER_RECEIVER:
                MessageProp msgProp = new MessageProp(0, false);
                byte[] unwrapped;
                try {
                    unwrapped = gssContext.unwrap(message, 0, message.length, msgProp);
                } catch (GSSException e) {
                    throw log.mechUnableToUnwrapMessage(getMechanismName(), e).toSaslException();
                }

                if (unwrapped.length < 4) {
                    throw log.mechInvalidMessageOnUnwrapping(getMechanismName(), unwrapped.length).toSaslException();
                }

                // What we offered and our own list of QOP could be different so we compare against what we offered as we know we
                // only offered it if the underlying GssContext also supports it.
                if ((offeredSecurityLayer & unwrapped[0]) == 0x00) {
                    throw log.mechSelectedUnofferedQop(getMechanismName()).toSaslException();
                }

                QOP selectedQop = QOP.mapFromValue(unwrapped[0]);
                assert selectedQop != null;

                maxBuffer = networkOrderBytesToInt(unwrapped, 1, 3);
                log.tracef("Client selected security layer %s, with maxBuffer of %d", selectedQop, maxBuffer);
                if (relaxComplianceChecks == false && selectedQop == QOP.AUTH && maxBuffer != 0) {
                    throw log.mechNoSecurityLayerButLengthReceived(getMechanismName()).toSaslException();
                }
                try {
                    maxBuffer = gssContext.getWrapSizeLimit(0, selectedQop == QOP.AUTH_CONF, maxBuffer);
                } catch (GSSException e) {
                    throw log.mechUnableToGetMaximumSizeOfMessage(getMechanismName(), e).toSaslException();
                }

                this.selectedQop = selectedQop;

                final String authenticationId;
                try {
                    authenticationId = gssContext.getSrcName().toString();
                } catch (GSSException e) {
                    throw log.mechUnableToDeterminePeerName(getMechanismName(), e).toSaslException();
                }
                final String authorizationId;
                if (unwrapped.length > 4) {
                    authorizationId = new String(unwrapped, 4, unwrapped.length - 4, StandardCharsets.UTF_8);
                } else {
                    authorizationId = authenticationId;
                }
                log.tracef("Authentication ID=%s,  Authorization ID=%s", authenticationId, authorizationId);

                AuthorizeCallback cb = new AuthorizeCallback(authenticationId, authorizationId);
                handleCallbacks(new Callback[] {cb});

                if (cb.isAuthorized() == false) {
                    throw log.mechAuthorizationFailed(getMechanismName(), authenticationId, authorizationId).toSaslException();
                }
                this.authorizationId = authorizationId;

                if (selectedQop != QOP.AUTH) {
                    log.trace("Setting message wrapper.");
                    setWrapper(new GssapiWrapper(selectedQop == QOP.AUTH_CONF));
                }

                try {
                    GSSCredential gssCredential = gssContext.getDelegCred();
                    if (gssCredential != null) {
                        tryHandleCallbacks(new IdentityCredentialCallback(new GSSKerberosCredential(gssCredential), true));
                    } else {
                        log.trace("No GSSCredential delegated during authentication.");
                    }
                } catch (UnsupportedCallbackException | GSSException e) {
                    // ignored
                } catch (SaslException e) {
                    throw e;
                }
                log.trace("Negotiation complete.");
                negotiationComplete();
                // By now this is the end.
                return null;
        }
        throw Assert.impossibleSwitchCase(state);
    }
}
