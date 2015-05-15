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

package org.wildfly.security.sasl.gs2;

import static org.wildfly.security._private.ElytronMessages.log;
import static org.wildfly.security.asn1.ASN1.*;
import static org.wildfly.security.sasl.gs2.Gs2.*;

import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.SaslException;

import org.ietf.jgss.ChannelBinding;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import org.wildfly.security.asn1.ASN1Exception;
import org.wildfly.security.asn1.DEREncoder;
import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.sasl.util.AbstractSaslServer;
import org.wildfly.security.util.ByteIterator;
import org.wildfly.security.util.ByteStringBuilder;
import org.wildfly.security.util.CodePointIterator;

/**
 * SaslServer for the GS2 mechanism family as defined by
 * <a href="https://tools.ietf.org/html/rfc5801">RFC 5801</a>.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
final class Gs2SaslServer extends AbstractSaslServer {

    private static final int ST_NO_MESSAGE = 1;
    private static final int ST_FIRST_MESSAGE = 2;
    private static final int ST_ACCEPTOR = 3;

    private final boolean plus;
    private final String bindingType;
    private final byte[] bindingData;
    private final Oid mechanism;
    private final GSSManager gssManager;
    private GSSContext gssContext;
    private String authorizationID;

    Gs2SaslServer(final String mechanismName, final String protocol, final String serverName, final CallbackHandler callbackHandler,
            final Map<String, ?> props, final GSSManager gssManager, final boolean plus, final String bindingType, final byte[] bindingData) throws SaslException {
        super(mechanismName, protocol, serverName, callbackHandler);
        this.plus = plus;
        this.bindingType = bindingType;
        this.bindingData = bindingData;
        this.gssManager = gssManager;

        try {
            mechanism = Gs2.getMechanismForSaslName(mechanismName);
        } catch (GSSException e) {
            throw log.saslMechanismToOidMappingFailed(e);
        }

        // Attempt to obtain a credential
        GSSCredential credential = null;
        CredentialCallback credentialCallback = new CredentialCallback(GSSCredential.class);
        try {
            tryHandleCallbacks(credentialCallback);
            credential = (GSSCredential) credentialCallback.getCredential();
        } catch (UnsupportedCallbackException e) {
            try {
                String localNameStr = protocol + "@" + serverName;
                GSSName localName = gssManager.createName(localNameStr, GSSName.NT_HOSTBASED_SERVICE, mechanism);
                credential = gssManager.createCredential(localName, GSSContext.INDEFINITE_LIFETIME, mechanism, GSSCredential.ACCEPT_ONLY);
            } catch (GSSException e1) {
                throw log.saslUnableToCreateGssContext(e1);
            }
        }
        try {
            gssContext = gssManager.createContext(credential);
        } catch (GSSException e) {
            throw log.saslUnableToCreateGssContext(e);
        }
    }

    public void init() {
        setNegotiationState(ST_NO_MESSAGE);
    }

    public String getAuthorizationID() {
        return authorizationID;
    }

    protected byte[] evaluateMessage(final int state, final byte[] message) throws SaslException {
        switch (state) {
            case ST_NO_MESSAGE: {
                if (message == null || message.length == 0) {
                    setNegotiationState(ST_ACCEPTOR);
                    // Initial challenge
                    return NO_BYTES;
                }
                // Fall through
            }
            case ST_FIRST_MESSAGE: {
                assert gssContext.isEstablished() == false;
                if (message == null || message.length == 0) {
                    throw log.saslClientRefusesToInitiateAuthentication();
                }
                ByteIterator bi = ByteIterator.ofBytes(message);
                ByteIterator di = bi.delimitedBy(',');
                CodePointIterator cpi = di.asUtf8String();
                boolean gs2CbFlagPUsed = false;

                // == Parse message ==
                boolean nonStd = false;
                int b = bi.next();

                // gs2-nonstd-flag
                if (b == 'F') {
                    skipDelimiter(bi);
                    nonStd = true;
                    b = bi.next();
                }

                // gs2-cb-flag
                if (b == 'p') {
                    gs2CbFlagPUsed = true;
                    if (! plus) {
                        throw log.saslChannelBindingNotSupported(getMechanismName());
                    }
                    if (bi.next() != '=') {
                        throw log.saslInvalidMessageReceived();
                    }
                    assert bindingType != null;
                    assert bindingData != null;
                    if (! bindingType.equals(cpi.drainToString())) {
                        throw log.saslChannelBindingTypeMismatch();
                    }
                    skipDelimiter(bi);
                } else if (b == 'y' || b == 'n') {
                    if (plus) {
                        throw log.saslChannelBindingNotProvided(getMechanismName());
                    }
                    skipDelimiter(bi);
                } else {
                    throw log.saslInvalidMessageReceived();
                }

                // gs2-authzid
                b = bi.next();
                if (b == 'a') {
                    if (bi.next() != '=') {
                        throw log.saslInvalidMessageReceived();
                    }
                    authorizationID = cpi.drainToString();
                    skipDelimiter(bi);
                } else if (b != ',') {
                    throw log.saslInvalidMessageReceived();
                }

                // Restore the initial context token header, if necessary
                byte[] token;
                int gs2HeaderStartIndex;
                int gs2HeaderLength;
                if (nonStd) {
                    gs2HeaderStartIndex = 2;
                    gs2HeaderLength = bi.offset() - 2;
                    token = bi.drain();
                } else {
                    gs2HeaderStartIndex = 0;
                    gs2HeaderLength = bi.offset();
                    try {
                        token = restoreTokenHeader(bi.drain());
                    } catch (ASN1Exception e) {
                        throw log.saslUnableToCreateResponseToken(e);
                    }
                }

                ByteStringBuilder gs2HeaderExcludingNonStdFlag = new ByteStringBuilder();
                gs2HeaderExcludingNonStdFlag.append(message, gs2HeaderStartIndex, gs2HeaderLength);
                try {
                    ChannelBinding channelBinding = Gs2Util.createChannelBinding(gs2HeaderExcludingNonStdFlag, gs2CbFlagPUsed, bindingData);
                    gssContext.setChannelBinding(channelBinding);
                } catch (GSSException e) {
                    throw log.saslUnableToSetChannelBinding(e);
                }

                try {
                    byte[] response = gssContext.acceptSecContext(token, 0, token.length);
                    if (gssContext.isEstablished()) {
                        Oid actualMechanism = gssContext.getMech();
                        if (! mechanism.equals(actualMechanism)) {
                            throw log.saslGssApiMechanismMismatch();
                        }
                        checkAuthorizationID();
                        negotiationComplete();
                    } else {
                        // Expecting subsequent exchanges
                        setNegotiationState(ST_ACCEPTOR);
                    }
                    return response;
                } catch (GSSException e) {
                    throw log.saslUnableToAcceptClientMessage(e);
                }
            }
            case ST_ACCEPTOR: {
                assert gssContext.isEstablished() == false;
                try {
                    byte[] response = gssContext.acceptSecContext(message, 0, message.length);
                    if (gssContext.isEstablished()) {
                        Oid actualMechanism = gssContext.getMech();
                        if (! mechanism.equals(actualMechanism)) {
                            throw log.saslGssApiMechanismMismatch();
                        }
                        checkAuthorizationID();
                        negotiationComplete();
                    }
                    return response;
                } catch (GSSException e) {
                    throw log.saslUnableToAcceptClientMessage(e);
                }
            }
            case COMPLETE_STATE: {
                if (message != null && message.length != 0) {
                    throw log.saslMessageAfterComplete();
                }
                return null;
            }
            default: throw new IllegalStateException();
        }
    }

    public void dispose() throws SaslException {
        try {
            gssContext.dispose();
        } catch (GSSException e) {
            throw log.saslUnableToDisposeGssContext(e);
        } finally {
            gssContext = null;
        }
    }

    /**
     * Recompute and restore the initial context token header for the given token.
     *
     * @param token the initial context token without the token header
     * @return the initial context token with the token header restored
     * @throws ASN1Exception if the mechanism OID cannot be DER encoded
     */
    private byte[] restoreTokenHeader(byte[] token) throws ASN1Exception {
        ByteStringBuilder headerAndToken = new ByteStringBuilder();
        final DEREncoder encoder = new DEREncoder(headerAndToken);
        encoder.encodeImplicit(APPLICATION_SPECIFIC_MASK, 0);
        encoder.startSequence();
        try {
            encoder.writeEncoded(mechanism.getDER());
        } catch (GSSException e) {
            throw new ASN1Exception(e.getMessage());
        }
        encoder.writeEncoded(token);
        encoder.endSequence();
        return headerAndToken.toArray();
    }

    private void checkAuthorizationID() throws SaslException {
        final String authenticationID;
        try {
            authenticationID = gssContext.getSrcName().toString();
        } catch (GSSException e) {
            throw log.saslUnableToDeterminePeerName(e);
        }
        if (authorizationID == null) {
            authorizationID = authenticationID;
        }
        AuthorizeCallback authorizeCallback = new AuthorizeCallback(authenticationID, authorizationID);
        handleCallbacks(authorizeCallback);
        if (! authorizeCallback.isAuthorized()) {
            throw log.saslAuthorizationFailed(authenticationID, authorizationID);
        }
    }

    private void skipDelimiter(ByteIterator bi) throws SaslException {
        if (bi.next() != ',') {
            throw log.saslInvalidMessageReceived();
        }
    }
}
