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

package org.wildfly.security.sasl.entity;

import static org.wildfly.security._private.ElytronMessages.log;
import static org.wildfly.security.asn1.ASN1.CONTEXT_SPECIFIC_MASK;
import static org.wildfly.security.sasl.entity.Entity.keyType;

import java.io.IOException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.SaslException;

import org.wildfly.common.Assert;
import org.wildfly.security.asn1.ASN1Exception;
import org.wildfly.security.asn1.DERDecoder;
import org.wildfly.security.asn1.DEREncoder;
import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.auth.callback.EvidenceVerifyCallback;
import org.wildfly.security.auth.callback.TrustedAuthoritiesCallback;
import org.wildfly.security.credential.X509CertificateChainPrivateCredential;
import org.wildfly.security.evidence.X509PeerCertificateChainEvidence;
import org.wildfly.security.sasl.entity.GeneralName.DNSName;
import org.wildfly.security.sasl.entity.GeneralName.DirectoryName;
import org.wildfly.security.sasl.util.AbstractSaslClient;
import org.wildfly.security.util.ByteStringBuilder;

/**
 * SaslClient for the ISO/IEC 9798-3 authentication mechanism as defined by
 * <a href="https://tools.ietf.org/html/rfc3163">RFC 3163</a>.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
final class EntitySaslClient extends AbstractSaslClient {

    private static final int ST_CHALLENGE_RESPONSE = 1;
    private static final int ST_RESPONSE_SENT = 2;

    private final SecureRandom secureRandom;
    private final Signature signature;
    private final boolean mutual;
    private final String serverName;
    private byte[] randomA;
    private byte[] randomB;
    private X509Certificate[] clientCertChain;
    private URL clientCertUrl;

    EntitySaslClient(final String mechanismName, final boolean mutual, final Signature signature, final SecureRandom secureRandom, final String protocol,
            final String serverName, final CallbackHandler callbackHandler, final String authorizationId, final Map<String, ?> props) {
        super(mechanismName, protocol, serverName, callbackHandler, authorizationId, false);
        this.signature = signature;
        this.secureRandom = secureRandom;
        this.mutual = mutual;
        this.serverName = serverName;
    }

    @Override
    public void init() {
        setNegotiationState(ST_CHALLENGE_RESPONSE);
    }

    @Override
    protected byte[] evaluateMessage(final int state, final byte[] challenge) throws SaslException {
        switch (state) {
            case ST_CHALLENGE_RESPONSE: {
                final DERDecoder decoder = new DERDecoder(challenge);
                List<TrustedAuthority> trustedAuthorities = null;
                List<GeneralName> entityB = null;
                try {
                    // == Parse message ==
                    decoder.startSequence();

                    // randomB
                    randomB = decoder.decodeOctetString();

                    // entityB
                    if ((serverName != null) && (! serverName.isEmpty())) {
                        entityB = new ArrayList<GeneralName>(1);
                        entityB.add(new DNSName(serverName));
                    }
                    if (decoder.isNextType(CONTEXT_SPECIFIC_MASK, 0, true)) {
                        decoder.decodeImplicit(0);
                        List<GeneralName> decodedEntityB = EntityUtil.decodeGeneralNames(decoder);
                        if ((entityB != null) && (! EntityUtil.matchGeneralNames(decodedEntityB, entityB))) {
                            throw log.mechServerIdentifierMismatch(getMechanismName()).toSaslException();
                        }
                    }

                    // certPref
                    if (decoder.isNextType(CONTEXT_SPECIFIC_MASK, 1, true)) {
                        decoder.decodeImplicit(1);
                        trustedAuthorities = EntityUtil.decodeTrustedAuthorities(decoder);
                    }
                    decoder.endSequence();
                } catch (ASN1Exception e) {
                    throw log.mechInvalidServerMessageWithCause(getMechanismName(), e).toSaslException();
                }

                // == Send response ==

                // Construct TokenAB, where:
                // TokenAB ::= SEQUENCE {
                //      randomA         RandomNumber,
                //      entityB         [0] GeneralNames OPTIONAL,
                //      certA           [1] CertData,
                //      authId          [2] GeneralNames OPTIONAL,
                //      signature       SIGNATURE { TBSDataAB }
                // }
                // TBSDataAB ::= SEQUENCE {
                //      randomA         RandomNumber,
                //      randomB         RandomNumber,
                //      entityB         [0] GeneralNames OPTIONAL,
                //      authId          [1] GeneralNames OPTIONAL
                // }
                // CertData ::= CHOICE {
                //      certificateSet  SET SIZE (1..MAX) OF Certificate
                //      certURL         IA5String
                // }
                // SIGNATURE { ToBeSigned } ::= SEQUENCE {
                //      algorithm       AlgorithmIdentifier,
                //      signature       BIT STRING
                // }
                ByteStringBuilder tokenAB = new ByteStringBuilder();
                final DEREncoder encoder = new DEREncoder(tokenAB);
                try {
                    encoder.startSequence();

                    // randomA
                    randomA = EntityUtil.encodeRandomNumber(encoder, secureRandom);

                    // entityB
                    if (entityB != null) {
                        encoder.encodeImplicit(0);
                        EntityUtil.encodeGeneralNames(encoder, entityB);
                    }

                    // certA (try obtaining a certificate chain first)
                    encoder.startExplicit(1);
                    TrustedAuthoritiesCallback trustedAuthoritiesCallback = new TrustedAuthoritiesCallback();
                    trustedAuthoritiesCallback.setTrustedAuthorities(trustedAuthorities); // Server's preferred certificates
                    CredentialCallback credentialCallback = new CredentialCallback(X509CertificateChainPrivateCredential.class, keyType(signature.getAlgorithm()));

                    PrivateKey privateKey;
                    try {
                        tryHandleCallbacks(trustedAuthoritiesCallback, credentialCallback);
                        final X509CertificateChainPrivateCredential clientCertChainPrivateCredential = (X509CertificateChainPrivateCredential) credentialCallback.getCredential();
                        if (clientCertChainPrivateCredential != null) {
                            clientCertChain = clientCertChainPrivateCredential.getCertificateChain();
                            if ((clientCertChain != null) && (clientCertChain.length > 0)) {
                                EntityUtil.encodeX509CertificateChain(encoder, clientCertChain);
                            } else {
                                throw log.mechCallbackHandlerNotProvidedClientCertificate(getMechanismName()).toSaslException();
                            }
                            privateKey = clientCertChainPrivateCredential.getPrivateKey();
                        } else {
                            throw log.mechCallbackHandlerNotProvidedClientCertificate(getMechanismName()).toSaslException();
                        }
                    } catch (UnsupportedCallbackException e) {
                        throw log.mechCallbackHandlerNotProvidedClientCertificate(getMechanismName()).toSaslException();
                    }
                    encoder.endExplicit();

                    // authId
                    final String authorizationId = getAuthorizationId();
                    List<GeneralName> authId = null;
                    if (authorizationId != null) {
                        encoder.encodeImplicit(2);
                        // TODO: Will authorizationId be a distinguished name or is a callback needed to
                        // determine the appropriate GeneralName type to use?
                        authId = new ArrayList<GeneralName>(1);
                        authId.add(new DirectoryName(authorizationId));
                        EntityUtil.encodeGeneralNames(encoder, authId);
                    }

                    // Private key
                    if (privateKey == null) {
                        throw log.mechCallbackHandlerNotProvidedPrivateKey(getMechanismName()).toSaslException();
                    }

                    // TBSDataAB
                    ByteStringBuilder tbsDataAB = new ByteStringBuilder();
                    final DEREncoder tbsEncoder = new DEREncoder(tbsDataAB);
                    tbsEncoder.startSequence();
                    tbsEncoder.encodeOctetString(randomA);
                    tbsEncoder.encodeOctetString(randomB);
                    if (entityB != null) {
                        tbsEncoder.encodeImplicit(0);
                        EntityUtil.encodeGeneralNames(tbsEncoder, entityB);
                    }
                    if (authId != null) {
                        tbsEncoder.encodeImplicit(1);
                        EntityUtil.encodeGeneralNames(tbsEncoder, authId);
                    }
                    tbsEncoder.endSequence();

                    // Signature
                    byte[] signatureBytes;
                    try {
                        signature.initSign(privateKey);
                        signature.update(tbsDataAB.toArray());
                        signatureBytes = signature.sign();
                    } catch (SignatureException | InvalidKeyException e) {
                        throw log.mechUnableToCreateSignature(getMechanismName(), e).toSaslException();
                    }

                    encoder.startSequence();
                    EntityUtil.encodeAlgorithmIdentifier(encoder, signature.getAlgorithm());
                    encoder.encodeBitString(signatureBytes);
                    encoder.endSequence();

                    encoder.endSequence();
                } catch (ASN1Exception e) {
                    throw log.mechUnableToCreateResponseToken(getMechanismName(), e).toSaslException();
                }
                setNegotiationState(ST_RESPONSE_SENT);
                return tokenAB.toArray();
            }
            case ST_RESPONSE_SENT: {
                if (mutual) {
                    final DERDecoder decoder = new DERDecoder(challenge);
                    List<GeneralName> entityA = null;
                    try {
                        decoder.startSequence();
                        byte[] randomC = decoder.decodeOctetString();

                        if (decoder.isNextType(CONTEXT_SPECIFIC_MASK, 0, true)) {
                            decoder.decodeImplicit(0);
                            entityA = EntityUtil.decodeGeneralNames(decoder);
                            // Verify that entityA matches the client's distinguishing identifier
                            if (! EntityUtil.matchGeneralNames(entityA, getClientCertificate())) {
                                throw log.mechClientIdentifierMismatch(getMechanismName()).toSaslException();
                            }
                        }

                        // Get the server's certificate data and verify it
                        decoder.startExplicit(1);
                        final X509PeerCertificateChainEvidence evidence = new X509PeerCertificateChainEvidence(EntityUtil.decodeCertificateData(decoder));
                        decoder.endExplicit();
                        X509Certificate serverCert = evidence.getFirstCertificate();

                        EvidenceVerifyCallback evidenceVerifyCallback = new EvidenceVerifyCallback(evidence);
                        handleCallbacks(evidenceVerifyCallback);
                        if (! evidenceVerifyCallback.isVerified()) {
                            throw log.mechServerAuthenticityCannotBeVerified(getMechanismName()).toSaslException();
                        }

                        // Get the server's signature and verify it
                        decoder.startSequence();
                        decoder.skipElement();
                        byte[] serverSignature = decoder.decodeBitString();
                        decoder.endSequence();

                        ByteStringBuilder tbsDataBA = new ByteStringBuilder();
                        final DEREncoder tbsEncoder = new DEREncoder(tbsDataBA);
                        tbsEncoder.startSequence();
                        tbsEncoder.encodeOctetString(randomB);
                        tbsEncoder.encodeOctetString(randomA);
                        tbsEncoder.encodeOctetString(randomC);
                        if (entityA != null) {
                            EntityUtil.encodeGeneralNames(tbsEncoder, entityA);
                        }
                        tbsEncoder.endSequence();

                        try {
                            signature.initVerify(serverCert);
                            signature.update(tbsDataBA.toArray());
                            if (! signature.verify(serverSignature)) {
                                setNegotiationState(FAILED_STATE);
                                throw log.mechServerAuthenticityCannotBeVerified(getMechanismName()).toSaslException();
                            }
                        } catch (SignatureException | InvalidKeyException e) {
                            throw log.mechUnableToVerifyServerSignature(getMechanismName(), e).toSaslException();
                        }
                        decoder.endSequence();
                    } catch (ASN1Exception e) {
                        throw log.mechInvalidServerMessageWithCause(getMechanismName(), e).toSaslException();
                    }
                } else {
                    if (challenge != null && challenge.length != 0) {
                        throw log.mechServerSentExtraMessage(getMechanismName()).toSaslException();
                    }
                }
                negotiationComplete();
                return null;
            }
        }
        throw Assert.impossibleSwitchCase(state);
    }

    @Override
    public void dispose() throws SaslException {
        clientCertChain = null;
        clientCertUrl = null;
    }

    private X509Certificate getClientCertificate() throws SaslException {
        if ((clientCertChain != null) && (clientCertChain.length > 0)) {
            return clientCertChain[0];
        } else if (clientCertUrl != null) {
            try {
                return EntityUtil.getCertificateFromUrl(clientCertUrl);
            } catch (IOException e) {
                throw log.mechUnableToObtainServerCertificate(getMechanismName(), clientCertUrl.toString(), e).toSaslException();
            }
        } else {
            throw log.mechCallbackHandlerNotProvidedServerCertificate(getMechanismName()).toSaslException();
        }
    }
}
