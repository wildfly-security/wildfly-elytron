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

import static org.wildfly.security._private.ElytronMessages.saslGs2;
import static org.wildfly.security.asn1.util.ASN1.APPLICATION_SPECIFIC_MASK;
import static org.wildfly.security.sasl.gs2.Gs2Util.TOKEN_HEADER_TAG;

import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.SaslException;

import org.ietf.jgss.ChannelBinding;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import org.wildfly.common.Assert;
import org.wildfly.security.asn1.DERDecoder;
import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.credential.GSSKerberosCredential;
import org.wildfly.security.sasl.WildFlySasl;
import org.wildfly.security.sasl.util.AbstractSaslClient;
import org.wildfly.security.sasl.util.StringPrep;
import org.wildfly.security.util.ByteStringBuilder;

/**
 * SaslClient for the GS2 mechanism family as defined by
 * <a href="https://tools.ietf.org/html/rfc5801">RFC 5801</a>.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
final class Gs2SaslClient extends AbstractSaslClient {

    private static final int ST_INITIAL_CHALLENGE = 1;
    private static final int ST_CHALLENGE_RESPONSE = 2;

    private final boolean plus;
    private final byte[] bindingData;
    private final String bindingType;
    private final Oid mechanism;
    private GSSContext gssContext;
    private ByteStringBuilder gs2HeaderExcludingNonStdFlag;

    Gs2SaslClient(final String mechanismName, final String protocol, final String serverName, final CallbackHandler callbackHandler, final String authorizationId,
            final Map<String, ?> props, final GSSManager gssManager, final boolean plus, final String bindingType, final byte[] bindingData) throws SaslException {
        super(mechanismName, protocol, serverName, callbackHandler, authorizationId, true, saslGs2);
        this.bindingType = bindingType;
        this.plus = plus;
        this.bindingData = bindingData;

        try {
            mechanism = Gs2.getMechanismForSaslName(gssManager, mechanismName);
        } catch (GSSException e) {
            throw saslGs2.mechMechanismToOidMappingFailed(e).toSaslException();
        }

        // Create a GSSContext
        String acceptorNameStr = protocol + "@" + serverName;
        final GSSName acceptorName;
        try {
            acceptorName = gssManager.createName(acceptorNameStr, GSSName.NT_HOSTBASED_SERVICE, mechanism);
        } catch (GSSException e) {
            throw saslGs2.mechUnableToCreateNameForAcceptor(e).toSaslException();
        }

        // Attempt to obtain a credential
        GSSCredential credential = null;
        CredentialCallback credentialCallback = new CredentialCallback(GSSKerberosCredential.class);

        try {
            tryHandleCallbacks(credentialCallback);
            credential = credentialCallback.applyToCredential(GSSKerberosCredential.class, GSSKerberosCredential::getGssCredential);
        } catch (UnsupportedCallbackException e) {
            saslGs2.trace("Unable to obtain GSSCredential, ignored (act as the default initiator principal instead)", e);
        }
        try {
            gssContext = gssManager.createContext(acceptorName, mechanism, credential, GSSContext.INDEFINITE_LIFETIME);
        } catch (GSSException e) {
            throw saslGs2.mechUnableToCreateGssContext(e).toSaslException();
        }

        try {
            // Set flags
            boolean delegateCredential = (credential != null);
            if (props.containsKey(WildFlySasl.GS2_DELEGATE_CREDENTIAL)) {
                delegateCredential = Boolean.parseBoolean((String) props.get(WildFlySasl.GS2_DELEGATE_CREDENTIAL));
            }
            gssContext.requestCredDeleg(delegateCredential);
            gssContext.requestMutualAuth(true); // Required
        } catch (GSSException e) {
            throw saslGs2.mechUnableToSetGssContextRequestFlags(e).toSaslException();
        }

        gs2HeaderExcludingNonStdFlag = createGs2HeaderExcludingNonStdFlag();
        try {
            boolean gs2CbFlagPUsed = ((bindingData != null) && plus);
            ChannelBinding channelBinding = Gs2Util.createChannelBinding(gs2HeaderExcludingNonStdFlag.toArray(), gs2CbFlagPUsed, bindingData);
            gssContext.setChannelBinding(channelBinding);
        } catch (GSSException e) {
            throw saslGs2.mechUnableToSetChannelBinding(e).toSaslException();
        }
    }

    public void dispose() throws SaslException {
        try {
            gssContext.dispose();
        } catch (GSSException e) {
            throw saslGs2.mechUnableToDisposeGssContext(e).toSaslException();
        } finally {
            gssContext = null;
        }
    }

    public void init() {
        setNegotiationState(ST_INITIAL_CHALLENGE);
    }

    protected byte[] evaluateMessage(final int state, final byte[] challenge) throws SaslException {
        switch (state) {
            case ST_INITIAL_CHALLENGE: {
                assert gssContext.isEstablished() == false;
                if ((challenge != null) && (challenge.length != 0)) {
                    throw saslGs2.mechInitialChallengeMustBeEmpty().toSaslException();
                }
                try {
                    byte[] response = gssContext.initSecContext(NO_BYTES, 0, 0);
                    // Expect at least one subsequent exchange
                    assert gssContext.isEstablished() == false;
                    setNegotiationState(ST_CHALLENGE_RESPONSE);
                    return modifyInitialContextToken(response);
                } catch (GSSException e) {
                    throw saslGs2.mechUnableToCreateResponseTokenWithCause(e).toSaslException();
                }
            }
            case ST_CHALLENGE_RESPONSE: {
                assert gssContext.isEstablished() == false;
                try {
                    byte[] response = gssContext.initSecContext(challenge, 0, challenge.length);
                    if (gssContext.isEstablished()) {
                        if (!gssContext.getMutualAuthState()) {
                            throw saslGs2.mechMutualAuthenticationNotEnabled().toSaslException();
                        }
                        negotiationComplete();
                    }
                    return response;
                } catch (GSSException e) {
                    throw saslGs2.mechUnableToCreateResponseTokenWithCause(e).toSaslException();
                }
            }
        }
        throw Assert.impossibleSwitchCase(state);
    }

    /**
     * Create a GS2 header, excluding the initial gs2-nonstd-flag, where:
     *
     *    gs2-header = [gs2-nonstd-flag "," ] gs2-cb-flag "," [gs2-authzid] ","
     *
     *  UTF8-1-safe    = %x01-2B / %x2D-3C / %x3E-7F
     *  UTF8-2         = <as defined in RFC 3629 (STD 63)>
     *  UTF8-3         = <as defined in RFC 3629 (STD 63)>
     *  UTF8-4         = <as defined in RFC 3629 (STD 63)>
     *  UTF8-char-safe = UTF8-1-safe / UTF8-2 / UTF8-3 / UTF8-4
     *  saslname       = 1*(UTF8-char-safe / "=2C" / "=3D")
     *  gs2-authzid    = "a=" saslname
     *  gs2-nonstd-flag = "F"
     *  cb-name         = 1*(ALPHA / DIGIT / "." / "-")
     *  gs2-cb-flag     = ("p=" cb-name) / "n" / "y"
     *
     * @return the GS2 header, excluding the initial gs2-nonstd-flag
     */
    private ByteStringBuilder createGs2HeaderExcludingNonStdFlag() {
        ByteStringBuilder header = new ByteStringBuilder();

        // gs2-cb-flag
        if (bindingData != null) {
            if (plus) {
                header.append("p=");
                header.append(bindingType);
                header.append(',');
            } else {
                header.append("y,");
            }
        } else {
            header.append("n,");
        }

        // gs2-authzid
        final String authorizationId = getAuthorizationId();
        if (authorizationId != null) {
            header.append("a=");
            StringPrep.encode(authorizationId, header, StringPrep.PROFILE_SASL_STORED | StringPrep.MAP_GS2_LOGIN_CHARS);
        }
        header.append(",");
        return header;
    }

    /**
     * Modify the given token by removing the initial context token header, if present, and
     * prefix the resulting token with a GS2 header.
     *
     * @param token the initial context token
     * @return the modified token
     * @throws GSSException if the given initial context token is invalid
     */
    private byte[] modifyInitialContextToken(byte[] token) throws GSSException {
        boolean nonStandard = false;
        if (token[0] == TOKEN_HEADER_TAG) {
            // Remove the initial context token header, where:
            // InitialContextToken ::=
            //      [APPLICATION 0] IMPLICIT SEQUENCE {
            //              thisMech MechType,
            //              innerContextToken ANY DEFINED BY thisMech
            //              -- contents mechanism-specific
            //              -- ASN.1 structure not required
            //      }
            // MechType ::= OBJECT IDENTIFIER
            final DERDecoder decoder = new DERDecoder(token);
            decoder.decodeImplicit(APPLICATION_SPECIFIC_MASK, 0);
            decoder.startSequence();
            String decodedOid = decoder.decodeObjectIdentifier();
            if (! mechanism.equals(new Oid(decodedOid))) {
                throw new GSSException(GSSException.DEFECTIVE_TOKEN);
            }
            token = decoder.drain();
        } else {
            // Set gs2-nonstd-flag
            nonStandard = true;
        }
        ByteStringBuilder modifiedToken = new ByteStringBuilder();
        if (nonStandard) {
            modifiedToken.append("F,");
        }
        modifiedToken.append(gs2HeaderExcludingNonStdFlag);
        modifiedToken.append(token);
        return modifiedToken.toArray();
    }
}
