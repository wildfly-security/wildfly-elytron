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
import static org.wildfly.security.asn1.ASN1.APPLICATION_SPECIFIC_MASK;

import java.io.IOException;

import javax.security.auth.callback.Callback;
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
import org.wildfly.common.Assert;
import org.wildfly.security.asn1.ASN1Exception;
import org.wildfly.security.asn1.DEREncoder;
import org.wildfly.security.auth.callback.ServerCredentialCallback;
import org.wildfly.security.credential.GSSKerberosCredential;
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
    private GSSContext gssContext;
    private String authorizationID;

    Gs2SaslServer(final String mechanismName, final String protocol, final String serverName, final CallbackHandler callbackHandler,
            final GSSManager gssManager, final boolean plus, final String bindingType, final byte[] bindingData) throws SaslException {
        super(mechanismName, protocol, serverName, callbackHandler);
        this.plus = plus;
        this.bindingType = bindingType;
        this.bindingData = bindingData;

        try {
            mechanism = Gs2.getMechanismForSaslName(gssManager, mechanismName);
        } catch (GSSException e) {
            throw log.mechMechanismToOidMappingFailed(getMechanismName(), e).toSaslException();
        }

        // Attempt to obtain a credential
        GSSCredential credential = null;
        ServerCredentialCallback credentialCallback = new ServerCredentialCallback(GSSKerberosCredential.class);

        try {
            log.trace("Obtaining GSSCredential for the service from callback handler");
            callbackHandler.handle(new Callback[] { credentialCallback });
            credential = credentialCallback.applyToCredential(GSSKerberosCredential.class, GSSKerberosCredential::getGssCredential);
        } catch (IOException e) {
            throw log.mechCallbackHandlerFailedForUnknownReason(getMechanismName(), e).toSaslException();
        } catch (UnsupportedCallbackException e) {
            log.trace("Unable to obtain GSSCredential from callback handler", e);
        }

        try {
            if (credential == null) {
                String localNameStr = protocol + "@" + serverName;
                log.tracef("Our name '%s'", localNameStr);
                GSSName localName = gssManager.createName(localNameStr, GSSName.NT_HOSTBASED_SERVICE, mechanism);
                credential = gssManager.createCredential(localName, GSSContext.INDEFINITE_LIFETIME, mechanism, GSSCredential.ACCEPT_ONLY);
            }
            gssContext = gssManager.createContext(credential);
        } catch (GSSException e) {
            throw log.mechUnableToCreateGssContext(getMechanismName(), e).toSaslException();
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
                    throw log.mechClientRefusesToInitiateAuthentication(getMechanismName()).toSaslException();
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
                        throw log.mechChannelBindingNotSupported(getMechanismName()).toSaslException();
                    }
                    if (bi.next() != '=') {
                        throw log.mechInvalidMessageReceived(getMechanismName()).toSaslException();
                    }
                    assert bindingType != null;
                    assert bindingData != null;
                    if (! bindingType.equals(cpi.drainToString())) {
                        throw log.mechChannelBindingTypeMismatch(getMechanismName()).toSaslException();
                    }
                    skipDelimiter(bi);
                } else if (b == 'y' || b == 'n') {
                    if (plus) {
                        throw log.mechChannelBindingNotProvided(getMechanismName()).toSaslException();
                    }
                    skipDelimiter(bi);
                } else {
                    throw log.mechInvalidMessageReceived(getMechanismName()).toSaslException();
                }

                // gs2-authzid
                b = bi.next();
                if (b == 'a') {
                    if (bi.next() != '=') {
                        throw log.mechInvalidMessageReceived(getMechanismName()).toSaslException();
                    }
                    authorizationID = cpi.drainToString();
                    skipDelimiter(bi);
                } else if (b != ',') {
                    throw log.mechInvalidMessageReceived(getMechanismName()).toSaslException();
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
                        throw log.mechUnableToCreateResponseTokenWithCause(getMechanismName(), e).toSaslException();
                    }
                }

                ByteStringBuilder gs2HeaderExcludingNonStdFlag = new ByteStringBuilder();
                gs2HeaderExcludingNonStdFlag.append(message, gs2HeaderStartIndex, gs2HeaderLength);
                try {
                    ChannelBinding channelBinding = Gs2Util.createChannelBinding(gs2HeaderExcludingNonStdFlag, gs2CbFlagPUsed, bindingData);
                    gssContext.setChannelBinding(channelBinding);
                } catch (GSSException e) {
                    throw log.mechUnableToSetChannelBinding(getMechanismName(), e).toSaslException();
                }

                try {
                    byte[] response = gssContext.acceptSecContext(token, 0, token.length);
                    if (gssContext.isEstablished()) {
                        Oid actualMechanism = gssContext.getMech();
                        if (! mechanism.equals(actualMechanism)) {
                            throw log.mechGssApiMechanismMismatch(getMechanismName()).toSaslException();
                        }
                        checkAuthorizationID();
                        negotiationComplete();
                    } else {
                        // Expecting subsequent exchanges
                        setNegotiationState(ST_ACCEPTOR);
                    }
                    return response;
                } catch (GSSException e) {
                    throw log.mechUnableToAcceptClientMessage(getMechanismName(), e).toSaslException();
                }
            }
            case ST_ACCEPTOR: {
                assert gssContext.isEstablished() == false;
                try {
                    byte[] response = gssContext.acceptSecContext(message, 0, message.length);
                    if (gssContext.isEstablished()) {
                        Oid actualMechanism = gssContext.getMech();
                        if (! mechanism.equals(actualMechanism)) {
                            throw log.mechGssApiMechanismMismatch(getMechanismName()).toSaslException();
                        }
                        checkAuthorizationID();
                        negotiationComplete();
                    }
                    return response;
                } catch (GSSException e) {
                    throw log.mechUnableToAcceptClientMessage(getMechanismName(), e).toSaslException();
                }
            }
            case COMPLETE_STATE: {
                if (message != null && message.length != 0) {
                    throw log.mechMessageAfterComplete(getMechanismName()).toSaslException();
                }
                return null;
            }
        }
        throw Assert.impossibleSwitchCase(state);
    }

    public void dispose() throws SaslException {
        try {
            gssContext.dispose();
        } catch (GSSException e) {
            throw log.mechUnableToDisposeGssContext(getMechanismName(), e).toSaslException();
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
            throw new ASN1Exception(e);
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
            throw log.mechUnableToDeterminePeerName(getMechanismName(), e).toSaslException();
        }
        log.tracef("checking if [%s] is authorized to act as [%s]...", authenticationID, authorizationID);
        if (authorizationID == null) {
            authorizationID = authenticationID;
        }
        AuthorizeCallback authorizeCallback = new AuthorizeCallback(authenticationID, authorizationID);
        handleCallbacks(authorizeCallback);
        if (! authorizeCallback.isAuthorized()) {
            throw log.mechAuthorizationFailed(getMechanismName(), authenticationID, authorizationID).toSaslException();
        }
        log.trace("authorization id check successful");
    }

    private void skipDelimiter(ByteIterator bi) throws SaslException {
        if (bi.next() != ',') {
            throw log.mechInvalidMessageReceived(getMechanismName()).toSaslException();
        }
    }
}
