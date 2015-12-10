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

import java.net.URL;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.x500.X500Principal;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.SaslException;

import org.wildfly.common.Assert;
import org.wildfly.security.asn1.ASN1Exception;
import org.wildfly.security.asn1.DERDecoder;
import org.wildfly.security.asn1.DEREncoder;
import org.wildfly.security.auth.callback.ServerCredentialCallback;
import org.wildfly.security.auth.callback.TrustedAuthoritiesCallback;
import org.wildfly.security.auth.callback.VerifyPeerTrustedCallback;
import org.wildfly.security.credential.X509CertificateChainPrivateCredential;
import org.wildfly.security.credential.X509CertificateChainPublicCredential;
import org.wildfly.security.evidence.X509PeerCertificateChainEvidence;
import org.wildfly.security.sasl.entity.GeneralName.DNSName;
import org.wildfly.security.sasl.util.AbstractSaslServer;
import org.wildfly.security.util.ByteStringBuilder;
import org.wildfly.security.x500.X509CertificateEvidenceDecoder;

/**
 * SaslServer for the ISO/IEC 9798-3 authentication mechanism as defined by
 * <a href="https://tools.ietf.org/html/rfc3163">RFC 3163</a>.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
final class EntitySaslServer extends AbstractSaslServer {

    private static final int ST_CHALLENGE = 1;
    private static final int ST_PROCESS_RESPONSE = 2;

    private final SecureRandom secureRandom;
    private final Signature signature;
    private final boolean mutual;
    private final String serverName;
    private String authorizationID;
    private byte[] randomB;

    EntitySaslServer(final String mechanismName, final String protocol, final String serverName, final CallbackHandler callbackHandler, final Map<String, ?> props, final boolean mutual, final Signature signature, final SecureRandom secureRandom) {
        super(mechanismName, protocol, serverName, callbackHandler);
        this.signature = signature;
        this.secureRandom = secureRandom;
        this.mutual = mutual;
        this.serverName = serverName;
    }

    public void init() {
        setNegotiationState(ST_CHALLENGE);
    }

    public String getAuthorizationID() {
        if (! isComplete()) {
            throw log.mechAuthenticationNotComplete(getMechanismName());
        }
        return authorizationID;
    }

    protected byte[] evaluateMessage(final int state, final byte[] response) throws SaslException {
        switch (state) {
            case ST_CHALLENGE: {
                if ((response != null) && (response.length != 0)) {
                    throw log.mechInitialChallengeMustBeEmpty(getMechanismName()).toSaslException();
                }
                // Construct TokenBA1, where:
                // TokenBA1 ::= SEQUENCE {
                //      randomB         RandomNumber,
                //      entityB         [0] GeneralNames OPTIONAL,
                //      certPref        [1] SEQUENCE SIZE (1..MAX) of TrustedAuth OPTIONAL
                // }
                // TrustedAuth ::= CHOICE {
                //      authorityName           [0] Name,
                //      issuerNameHash          [1] OCTET STRING,
                //      issuerKeyHash           [2] OCTET STRING,
                //      authorityCertificate    [3] Certificate,
                //      pkcs15KeyHash           [4] OCTET STRING
                // }
                ByteStringBuilder tokenBA1 = new ByteStringBuilder();
                final DEREncoder encoder = new DEREncoder(tokenBA1);
                try {
                    encoder.startSequence();

                    // randomB
                    randomB = EntityUtil.encodeRandomNumber(encoder, secureRandom);

                    // entityB
                    if ((serverName != null) && (! serverName.isEmpty())) {
                        encoder.encodeImplicit(0);
                        EntityUtil.encodeGeneralNames(encoder, new DNSName(serverName));
                    }

                    // certPref
                    TrustedAuthoritiesCallback trustedAuthoritiesCallback = new TrustedAuthoritiesCallback();
                    handleCallbacks(trustedAuthoritiesCallback);
                    List<TrustedAuthority> trustedAuthorities = trustedAuthoritiesCallback.getTrustedAuthorities();
                    if ((trustedAuthorities != null) && (! trustedAuthorities.isEmpty())) {
                        encoder.encodeImplicit(1);
                        EntityUtil.encodeTrustedAuthorities(encoder, trustedAuthorities);
                    }
                    encoder.endSequence();
                } catch (ASN1Exception e) {
                    throw log.mechUnableToCreateResponseTokenWithCause(getMechanismName(), e).toSaslException();
                }
                setNegotiationState(ST_PROCESS_RESPONSE);
                return tokenBA1.toArray();
            }
            case ST_PROCESS_RESPONSE: {
                final DERDecoder decoder = new DERDecoder(response);
                byte[] randomA;
                X509Certificate clientCert;
                X509Certificate[] serverCertChain = null;
                X509Certificate serverCert = null;
                URL serverCertUrl = null;
                PrivateKey privateKey = null;
                String clientName;
                List<GeneralName> entityB = null;
                List<GeneralName> authID = null;
                try {
                    decoder.startSequence();
                    randomA = decoder.decodeOctetString();
                    if (decoder.isNextType(CONTEXT_SPECIFIC_MASK, 0, true)) {
                        decoder.decodeImplicit(0);
                        entityB = EntityUtil.decodeGeneralNames(decoder);
                    }

                    // Get the client's certificate data and verify it
                    decoder.startExplicit(1);
                    final X509CertificateChainPublicCredential credential = new X509CertificateChainPublicCredential(EntityUtil.decodeCertificateData(decoder));
                    decoder.endExplicit();
                    clientCert = credential.getFirstCertificate();

                    VerifyPeerTrustedCallback verifyPeerTrustedCallback = new VerifyPeerTrustedCallback(clientCert.getSubjectX500Principal(), credential);
                    handleCallbacks(verifyPeerTrustedCallback);
                    if (! verifyPeerTrustedCallback.isVerified()) {
                        throw log.mechAuthenticationFailed(getMechanismName()).toSaslException();
                    }

                    // Determine the authorization identity
                    clientName = X509CertificateEvidenceDecoder.getInstance().getPrincipalFromEvidence(new X509PeerCertificateChainEvidence(clientCert)).getName(X500Principal.CANONICAL);
                    if (decoder.isNextType(CONTEXT_SPECIFIC_MASK, 2, true)) {
                        // The client provided an authID
                        decoder.decodeImplicit(2);
                        authID = EntityUtil.decodeGeneralNames(decoder);
                        authorizationID = EntityUtil.getDistinguishedNameFromGeneralNames(authID);
                    } else {
                        // Use the identity from the client's X.509 certificate
                        authorizationID = clientName;
                    }

                    // Get the client's signature and verify it
                    decoder.startSequence();
                    decoder.skipElement();
                    byte[] clientSignature = decoder.decodeBitString();
                    decoder.endSequence();

                    ByteStringBuilder tbsDataAB = new ByteStringBuilder();
                    final DEREncoder tbsEncoder = new DEREncoder(tbsDataAB);
                    tbsEncoder.startSequence();
                    tbsEncoder.encodeOctetString(randomA);
                    tbsEncoder.encodeOctetString(randomB);
                    if (entityB != null) {
                        tbsEncoder.encodeImplicit(0);
                        EntityUtil.encodeGeneralNames(tbsEncoder, entityB);
                    }
                    if (authID != null) {
                        tbsEncoder.encodeImplicit(1);
                        EntityUtil.encodeGeneralNames(tbsEncoder, authID);
                    }
                    tbsEncoder.endSequence();

                    try {
                        signature.initVerify(clientCert);
                        signature.update(tbsDataAB.toArray());
                        if (! signature.verify(clientSignature)) {
                            setNegotiationState(FAILED_STATE);
                            throw log.mechAuthenticationFailed(getMechanismName()).toSaslException();
                        }
                    } catch (SignatureException | InvalidKeyException e) {
                        throw log.mechUnableToVerifyClientSignature(getMechanismName(), e).toSaslException();
                    }
                    decoder.endSequence();
                } catch (ASN1Exception e) {
                    throw log.mechInvalidClientMessageWithCause(getMechanismName(), e).toSaslException();
                }

                // Get the server's certificate data, if necessary
                if ((entityB != null) || mutual) {
                    ServerCredentialCallback credentialCallback = new ServerCredentialCallback(X509CertificateChainPrivateCredential.class, keyType(signature.getAlgorithm()));

                    try {
                        tryHandleCallbacks(credentialCallback);
                        final X509CertificateChainPrivateCredential serverCertChainPrivateCredential = (X509CertificateChainPrivateCredential) credentialCallback.getCredential();
                        if (serverCertChainPrivateCredential != null) {
                            serverCertChain = serverCertChainPrivateCredential.getCertificateChain();
                            if ((serverCertChain != null) && (serverCertChain.length > 0)) {
                                serverCert = serverCertChain[0];
                            } else {
                                throw log.mechCallbackHandlerNotProvidedServerCertificate(getMechanismName()).toSaslException();
                            }
                            privateKey = serverCertChainPrivateCredential.getPrivateKey();
                        } else {
                            throw log.mechCallbackHandlerNotProvidedServerCertificate(getMechanismName()).toSaslException();
                        }
                    } catch (UnsupportedCallbackException e) {
                        throw log.mechCallbackHandlerNotProvidedServerCertificate(getMechanismName()).toSaslException();
                    }
                }

                // Verify that entityB matches the server's distinguishing identifier
                if ((entityB != null) && (! EntityUtil.matchGeneralNames(entityB, serverCert))) {
                    throw log.mechServerIdentifierMismatch(getMechanismName()).toSaslException();
                }

                // Check the authorization id
                AuthorizeCallback authorizeCallback = new AuthorizeCallback(clientName, authorizationID);
                handleCallbacks(authorizeCallback);
                if (! authorizeCallback.isAuthorized()) {
                    throw log.mechAuthorizationFailed(getMechanismName(), clientName, authorizationID).toSaslException();
                }

                if (mutual) {
                    // Construct TokenBA2, where:
                    // TokenBA2 ::= SEQUENCE {
                    //      randomC     RandomNumber,
                    //      entityA     [0] GeneralNames OPTIONAL,
                    //      certB       [1] CertData,
                    //      signature   SIGNATURE { TBSDataBA }
                    // }
                    // TBSDataBA ::= SEQUENCE {
                    //      randomB     RandomNumber,
                    //      randomA     RandomNumber,
                    //      randomC     RandomNumber,
                    //      entityA     GeneralNames OPTIONAL
                    // }
                    // CertData ::= CHOICE {
                    //      certificateSet  SET SIZE (1..MAX) OF Certificate
                    //      certURL         IA5String
                    // }
                    // SIGNATURE { ToBeSigned } ::= SEQUENCE {
                    //      algorithm       AlgorithmIdentifier,
                    //      signature       BIT STRING
                    // }
                    ByteStringBuilder tokenBA2 = new ByteStringBuilder();
                    final DEREncoder encoder = new DEREncoder(tokenBA2);
                    try {
                        encoder.startSequence();

                        // randomC
                        byte[] randomC = EntityUtil.encodeRandomNumber(encoder, secureRandom);

                        // entityA
                        Collection<List<?>> clientSubjectAltNames = null;
                        try {
                            clientSubjectAltNames = clientCert.getSubjectAlternativeNames();
                        } catch (CertificateParsingException e) {
                            // Ingore unless the subject name is empty
                            if (clientName.isEmpty()) {
                                throw log.mechUnableToDetermineClientName(getMechanismName(), e).toSaslException();
                            }
                        }
                        encoder.encodeImplicit(0);
                        EntityUtil.encodeGeneralNames(encoder, clientName, clientSubjectAltNames);

                        // certB
                        encoder.startExplicit(1);
                        if ((serverCertChain != null) && (serverCertChain.length > 0)) {
                            EntityUtil.encodeX509CertificateChain(encoder, serverCertChain);
                        } else if (serverCertUrl != null) {
                            // Use a certificate URL instead
                            encoder.encodeIA5String(serverCertUrl.toString());
                        } else {
                            throw log.mechCallbackHandlerNotProvidedServerCertificate(getMechanismName()).toSaslException();
                        }
                        encoder.endExplicit();

                        // Private key
                        if (privateKey == null) {
                            throw log.mechCallbackHandlerNotProvidedPrivateKey(getMechanismName()).toSaslException();
                        }

                        // TBSDataBA
                        ByteStringBuilder tbsDataBA = new ByteStringBuilder();
                        final DEREncoder tbsEncoder = new DEREncoder(tbsDataBA);
                        tbsEncoder.startSequence();
                        tbsEncoder.encodeOctetString(randomB);
                        tbsEncoder.encodeOctetString(randomA);
                        tbsEncoder.encodeOctetString(randomC);
                        EntityUtil.encodeGeneralNames(tbsEncoder, clientName, clientSubjectAltNames);
                        tbsEncoder.endSequence();

                        // Signature
                        byte[] signatureBytes;
                        try {
                            signature.initSign(privateKey);
                            signature.update(tbsDataBA.toArray());
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
                        throw log.mechUnableToCreateResponseTokenWithCause(getMechanismName(), e).toSaslException();
                    }
                    negotiationComplete();
                    return tokenBA2.toArray();
                } else {
                    negotiationComplete();
                    return null;
                }
            } case COMPLETE_STATE: {
                  if (response != null && response.length != 0) {
                      throw log.mechClientSentExtraMessage(getMechanismName()).toSaslException();
                  }
                  return null;
            }
        }
        throw Assert.impossibleSwitchCase(state);
    }
}
