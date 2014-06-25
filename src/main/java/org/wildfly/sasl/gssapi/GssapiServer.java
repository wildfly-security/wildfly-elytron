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

package org.wildfly.sasl.gssapi;

import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
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
import org.wildfly.sasl.gssapi.AbstractGssapiMechanism.GssapiWrapper;
import org.wildfly.sasl.gssapi.AbstractGssapiMechanism.QOP;
import org.wildfly.sasl.util.Charsets;
import org.wildfly.sasl.util.SaslState;
import org.wildfly.sasl.util.SaslStateContext;

/**
 * SaslServer for the GSSAPI mechanism as defined by RFC 4752
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class GssapiServer extends AbstractGssapiMechanism implements SaslServer {

    private String authroizationId;

    GssapiServer(final String protocol, final String serverName, final Map<String, ?> props,
            final CallbackHandler callbackHandler) throws SaslException {
        super(AbstractGssapiFactory.GSSAPI, protocol, serverName, props, callbackHandler);

        // Initialise our GSSContext
        GSSManager manager = GSSManager.getInstance();

        // According to the Javadoc we will have a protocol and server name.
        String localName = protocol + "@" + serverName;
        GSSContext gssContext = null;
        try {
            GSSName ourName = manager.createName(localName, GSSName.NT_HOSTBASED_SERVICE, KERBEROS_V5);
            GSSCredential ourCredential = manager.createCredential(ourName, GSSContext.INDEFINITE_LIFETIME, KERBEROS_V5,
                    GSSCredential.ACCEPT_ONLY);

            gssContext = manager.createContext(ourCredential);
        } catch (GSSException e) {
            throw new SaslException("Unable to create GSSContext", e);
        }
        // We don't request integrity or confidentiality as that is only
        // supported on the client side.

        this.gssContext = gssContext;
    }

    @Override
    public void init() {
        getContext().setNegotiationState(new AcceptorState());
    }

    @Override
    public String getAuthorizationID() {
        assertComplete();

        return authroizationId;
    }

    @Override
    public byte[] evaluateResponse(byte[] response) throws SaslException {
        return evaluateMessage(response);
    }

    // States

    // 1 - Acceptor State

    private class AcceptorState implements SaslState {

        @Override
        public byte[] evaluateMessage(SaslStateContext context, byte[] message) throws SaslException {
            assert gssContext.isEstablished() == false;

            try {
                byte[] response = gssContext.acceptSecContext(message, 0, message.length);

                if (gssContext.isEstablished()) {
                    Oid actualMech = gssContext.getMech();
                    if (KERBEROS_V5.equals(actualMech) == false) {
                        throw new SaslException("Negotiated mechanism was not Kerberos V5");
                    }

                    SaslState nextState = new SecurityLayerAdvertiser();
                    context.setNegotiationState(nextState);

                    if (response == null || response.length == 0) {
                        return nextState.evaluateMessage(context, null);
                    }
                }

                return response;
            } catch (GSSException e) {
                throw new SaslException("Unable to accept message from client.", e);
            }

        }

    }

    // 2 - Security Layer Advertiser

    private class SecurityLayerAdvertiser implements SaslState {

        /**
         * This state expects at most to be called with an empty message, it will then advertise the currently support security
         * layer and transition to the next state to await a response.
         */
        @Override
        public byte[] evaluateMessage(SaslStateContext context, byte[] message) throws SaslException {
            if (message != null && message.length > 0) {
                throw new SaslException("Only expecting an empty message, received a full message.");
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
                        }
                        break;
                    case AUTH_CONF:
                        if (gssContext.getConfState()) {
                            supportedSecurityLayers |= current.getValue();
                            offeringSecurityLayer = true;
                        }
                        break;
                    default:
                        supportedSecurityLayers |= current.getValue();
                }
            }

            if (supportedSecurityLayers == 0x00) {
                throw new SaslException("Insufficient levels of protection available for supported security layers.");
            }

            response[0] = supportedSecurityLayers;
            try {
                byte[] length;

                if (offeringSecurityLayer) {
                    actualMaxReceiveBuffer = gssContext.getWrapSizeLimit(0,
                            (supportedSecurityLayers & QOP.AUTH_CONF.getValue()) != 0, configuredMaxReceiveBuffer);
                    length = intToNetworkOrderBytes(actualMaxReceiveBuffer);
                } else {
                    length = new byte[] { 0x00, 0x00, 0x00 };
                }
                System.arraycopy(length, 0, response, 1, 3);

                MessageProp msgProp = new MessageProp(0, false);
                response = gssContext.wrap(response, 0, 4, msgProp);
            } catch (GSSException e) {
                throw new SaslException("Unable to generate security layer challenge.", e);
            }

            context.setNegotiationState(new SecurityLayerReceiver(supportedSecurityLayers));

            return response;
        }

    }

    // 3 - Security Layer Receiver

    private class SecurityLayerReceiver implements SaslState {

        private final byte offeredSecurityLayer;

        private SecurityLayerReceiver(final byte offeredSecurityLayer) {
            this.offeredSecurityLayer = offeredSecurityLayer;
        }

        @Override
        public byte[] evaluateMessage(SaslStateContext context, byte[] message) throws SaslException {
            MessageProp msgProp = new MessageProp(0, false);
            byte[] unwrapped;
            try {
                unwrapped = gssContext.unwrap(message, 0, message.length, msgProp);
            } catch (GSSException e) {
                throw new SaslException("Unable to unwrap security layer response.", e);
            }

            if (unwrapped.length < 4) {
                throw new SaslException(String.format("Invalid message of length %d on unwrapping.", unwrapped.length));
            }

            // What we offered and our own list of QOP could be different so we compare against what we offered as we know we
            // only offered it if the underlying GssContext also supports it.
            if ((offeredSecurityLayer & unwrapped[0]) == 0x00) {
                throw new SaslException("Client selected a security layer that was not offered.");
            }

            QOP selectedQop = QOP.mapFromValue(unwrapped[0]);
            assert selectedQop != null;

            maxBuffer = networkOrderBytesToInt(unwrapped, 1, 3);
            if (relaxComplianceChecks == false && selectedQop == QOP.AUTH && maxBuffer != 0) {
                throw new SaslException("No security layer selected but message length received.");
            }
            GssapiServer.this.selectedQop = selectedQop;

            final String authenticationId;
            try {
                authenticationId = gssContext.getSrcName().toString();
            } catch (GSSException e) {
                throw new SaslException("Unable to determine name of peer.", e);
            }
            final String authorizationId;
            if (unwrapped.length > 4) {
                authorizationId = new String(unwrapped, 4, unwrapped.length - 4, Charsets.UTF_8);
            } else {
                authorizationId = authenticationId;
            }

            AuthorizeCallback cb = new AuthorizeCallback(authenticationId, authorizationId);
            handleCallbacks(new Callback[] {cb});

            if (cb.isAuthorized() == false) {
                throw new SaslException(String.format("User %s is not authorized to act as %s", authenticationId, authorizationId));
            }
            GssapiServer.this.authroizationId = authorizationId;

            if (selectedQop != QOP.AUTH) {
                setWrapper(new GssapiWrapper(selectedQop == QOP.AUTH_CONF));
            }

            context.negotiationComplete();
            // By now this is the end.
            return null;
        }

    }
}
