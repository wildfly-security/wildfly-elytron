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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.MessageProp;
import org.wildfly.sasl.WildFlySasl;
import org.wildfly.sasl.util.Charsets;
import org.wildfly.sasl.util.SaslState;
import org.wildfly.sasl.util.SaslStateContext;

/**
 * SaslClient for the GSSAPI mechanism as defined by RFC 4752
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class GssapiClient extends AbstractGssapiMechanism implements SaslClient {

    private final String authorizationId;

    GssapiClient(final String protocol, final String serverName, final Map<String, ?> props,
            final CallbackHandler callbackHandler, final String authorizationId) throws SaslException {
        super(AbstractGssapiFactory.GSSAPI, protocol, serverName, props, callbackHandler);

        this.authorizationId = authorizationId;

        // Initialise our GSSContext
        GSSManager manager = GSSManager.getInstance();

        String acceptorNameString = protocol + "@" + serverName;
        final GSSName acceptorName;
        try {
            // The client can use other name types but this should be added to the config.
            acceptorName = manager.createName(acceptorNameString, GSSName.NT_HOSTBASED_SERVICE, KERBEROS_V5);
        } catch (GSSException e) {
            throw new SaslException("Unable to create name for acceptor.", e);
        }

        boolean mayRequireSecurityLayer = mayRequireSecurityLater(orderedQops);

        // Pull the credential if we have it.
        GSSCredential credential = null;

        Object credObj = props.get(Sasl.CREDENTIALS);
        if (credObj != null && credObj instanceof GSSCredential) {
            credential = (GSSCredential) credObj;
        }

        // Better way to obtain the credential if we don't have one?

        final GSSContext gssContext;
        try {
            gssContext = manager.createContext(acceptorName, KERBEROS_V5, credential, GSSContext.INDEFINITE_LIFETIME);
        } catch (GSSException e) {
            throw new SaslException("Unable to crate GSSContexr", e);
        }

        try {
            // JDK only sets this if a credential was supplied, we should support a config override.
            // i.e. we may have a credential because it was delegated to us - doesn't mean we want
            // to delegate it further - at same point we may have a Subject on ACC and still want to delegate.
            boolean delegate = credential != null;
            if (props.containsKey(WildFlySasl.GSSAPI_DELEGATE_CREDENTIAL)) {
                delegate = Boolean.parseBoolean((String) props.get(WildFlySasl.GSSAPI_DELEGATE_CREDENTIAL));
            }
            if (delegate) {
                gssContext.requestCredDeleg(true);
            }

            // The client must pass the integ_req_flag of true.
            gssContext.requestInteg(true);
            // This was requested so that integrity protection can be used to negotiate the security layer,
            // further integrity protection will be based on the negotiated security layer.

            // requestMutualAuth if: -
            // 1 - The client requests it.
            // 2 - The client will be requesting a security layer. Will interpret as may be requesting as
            // client and server could agree auth only.
            boolean serverAuth = false;
            if (props.containsKey(Sasl.SERVER_AUTH)) {
                serverAuth = Boolean.parseBoolean((String) props.get(Sasl.SERVER_AUTH));
            }

            if (serverAuth || mayRequireSecurityLayer) {
                gssContext.requestMutualAuth(true);
            }

            // Request sequence detection if a security layer could be requested.
            if (mayRequireSecurityLayer) {
                gssContext.requestSequenceDet(true);
            }

            // Need to set this is we may want confidentiality, integrity is always requested.
            for (QOP current : orderedQops) {
                if (current == QOP.AUTH_CONF) {
                    gssContext.requestConf(true);
                    break;
                }
            }

        } catch (GSSException e) {
            throw new SaslException("Unable to set request flags.", e);
        }

        // Channel Binding Is Not Supported

        this.gssContext = gssContext;
    }

    private boolean mayRequireSecurityLater(final QOP[] preferredQop) {
        for (QOP current : preferredQop) {
            if (current == QOP.AUTH_INT || current == QOP.AUTH_CONF) {
                return true;
            }
        }
        return false;
    }

    private QOP findAgreeableQop(final byte securityLayer) throws SaslException {
        for (QOP current : orderedQops) {
            if (current.includedBy(securityLayer) && isCompatibleWithGssContext(current)) {
                return current;
            }
        }

        throw new SaslException("No mutually agreeable security layer found.");
    }

    private boolean isCompatibleWithGssContext(final QOP qop) {
        switch (qop) {
            case AUTH_INT:
                return gssContext.getIntegState();
            case AUTH_CONF:
                return gssContext.getIntegState() && gssContext.getConfState();
            default:
                return true;
        }
    }

    @Override
    public void init() {
        getContext().setNegotiationState(new InitialChallengeState());
    }

    @Override
    public boolean hasInitialResponse() {
        return true;
    }

    @Override
    public byte[] evaluateChallenge(byte[] challenge) throws SaslException {
        return evaluateMessage(challenge);
    }

    /**
     * GSSAPI is a client first mechanism, this state both verifies that requirement is met and provides the first token from
     * the client.
     *
     */
    private class InitialChallengeState implements SaslState {

        @Override
        public byte[] evaluateMessage(SaslStateContext context, byte[] message) throws SaslException {
            assert gssContext.isEstablished() == false;
            if (message.length > 0) {
                throw new SaslException("GSSAPI is a client first mechanism, unexpected server challenge received.");
            }

            try {
                byte[] response = gssContext.initSecContext(NO_BYTES, 0, 0);
                context.setNegotiationState(gssContext.isEstablished() ? new SecurityLayerNegotiationState()
                        : new ChallengeResponseState());
                return response;
            } catch (GSSException e) {
                throw new SaslException("Unable to create output token.", e);
            }
        }

    }

    /**
     * This state is to handle the subsequent exchange of tokens up until the point the GSSContext is established.
     *
     */
    private class ChallengeResponseState implements SaslState {

        @Override
        public byte[] evaluateMessage(SaslStateContext context, byte[] message) throws SaslException {
            assert gssContext.isEstablished() == false;

            try {
                byte[] response = gssContext.initSecContext(message, 0, message.length);

                if (gssContext.isEstablished()) {
                    context.setNegotiationState(new SecurityLayerNegotiationState());
                }
                return response;
            } catch (GSSException e) {
                throw new SaslException("Unable to handle response from server.", e);
            }
        }

    }

    private class SecurityLayerNegotiationState implements SaslState {

        @Override
        public byte[] evaluateMessage(SaslStateContext context, byte[] message) throws SaslException {
            assert gssContext.isEstablished();

            MessageProp msgProp = new MessageProp(0, false);
            try {
                byte[] unwrapped = gssContext.unwrap(message, 0, message.length, msgProp);
                if (unwrapped.length != 4) {
                    throw new SaslException("Bad length of message for negotiating security layer.");
                }

                byte qopByte = unwrapped[0];
                selectedQop = findAgreeableQop(qopByte);
                maxBuffer = networkOrderBytesToInt(unwrapped, 1, 3);
                if (relaxComplianceChecks == false && maxBuffer > 0 && (qopByte & QOP.AUTH_INT.getValue()) == 0
                        && (qopByte & QOP.AUTH_CONF.getValue()) == 0) {
                    throw new SaslException(String.format(
                            "Invalid message size received when no security layer supported by server '%d'",
                            maxBuffer));
                }

                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                baos.write(selectedQop.getValue());
                if (selectedQop == QOP.AUTH) {
                    // No security layer selected to must set response to 000.
                    baos.write(new byte[] { 0x00, 0x00, 0x00 });
                } else {
                    actualMaxReceiveBuffer = gssContext.getWrapSizeLimit(0, selectedQop == QOP.AUTH_CONF,
                            configuredMaxReceiveBuffer);
                    baos.write(intToNetworkOrderBytes(actualMaxReceiveBuffer));
                }

                if (authorizationId != null) {
                    baos.write(authorizationId.getBytes(Charsets.UTF_8));
                }

                byte[] response = baos.toByteArray();
                msgProp = new MessageProp(0, false);
                response = gssContext.wrap(response, 0, response.length, msgProp);

                if (selectedQop != QOP.AUTH) {
                    setWrapper(new GssapiWrapper(selectedQop == QOP.AUTH_CONF));
                }

                context.negotiationComplete();
                return response;
            } catch (IOException e) {
                throw new SaslException("Unable to construct response for server.", e);
            } catch (GSSException e) {
                throw new SaslException("Unable to unwrap security layer negotiation message.", e);
            }
        }
    }

}
