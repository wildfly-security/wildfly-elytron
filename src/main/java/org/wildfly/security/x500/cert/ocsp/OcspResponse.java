/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2018 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.x500.cert.ocsp;

import static org.wildfly.security.asn1.util.ASN1.CONTEXT_SPECIFIC_MASK;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CRLReason;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

import org.wildfly.security._private.ElytronMessages;
import org.wildfly.security.asn1.ASN1Decoder;
import org.wildfly.security.asn1.DERDecoder;
import org.wildfly.security.x500.X500;
import org.wildfly.security.x500.cert.ocsp.OcspStatus.CertStatus;

/**
 * A response from the OCSP responder.
 */
class OcspResponse {

    private Map<CertId, OcspStatus> results = new HashMap<>();
    private List<X509Certificate> certificates = new LinkedList<>();
    private String signatureAlgorithmOid;
    private byte[] tbsResponseData;
    private byte[] signatureBytes;
    private X500Principal responderName;
    private byte[] responderKeyHash;

    /**
     * Test whether the OCSP response is signed using given certificate.
     * @param certificate the signing certificate
     * @return {@code true} if the OCSP response is signed using given certificate, {@code false} otherwise
     * @throws NoSuchAlgorithmException if no provider supports a used signature
     * @throws InvalidKeyException if the public key in the certificate is not valid
     * @throws SignatureException if the signature in the response is improperly encoded or of the wrong type, etc.
     */
    boolean checkSignature(Certificate certificate) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(signatureAlgorithmOid);
        signature.initVerify(certificate.getPublicKey());
        signature.update(tbsResponseData);
        return signature.verify(signatureBytes);
    }

    /**
     * Get the OCSP statuses for individual certificates
     * @return the OCSP statuses for individual certificates
     */
    Map<CertId, OcspStatus> getResults() {
        return results;
    }

    /**
     * Get certificates provided by OCSP responder to help verify responder's signature
     * @return certificates to help verify responder's signature
     */
    public List<X509Certificate> getCertificates() {
        return certificates;
    }

    /**
     * Get the responder identifier
     * @return the responder identifier
     */
    X500Principal getResponderName() {
        return responderName;
    }

    /**
     * Get the responder key hash
     * @return the responder key hash
     */
    byte[] getResponderKeyHash() {
        return responderKeyHash;
    }

    /**
     * Parse the OCSP response
     * @param ocspResponse the DER encoded OCSP response
     * @throws CertificateException if the response does not contain requested results (the response is error message)
     */
    // OCSPResponse ::= SEQUENCE {
    //    responseStatus         OCSPResponseStatus,
    //    responseBytes          [0] EXPLICIT ResponseBytes OPTIONAL }
    //
    // OCSPResponseStatus ::= ENUMERATED {
    //    successful            (0),      --Response has valid confirmations
    //    malformedRequest      (1),      --Illegal confirmation request
    //    internalError         (2),      --Internal error in issuer
    //    tryLater              (3),      --Try again later
    //                                    --(4) is not used
    //    sigRequired           (5),      --Must sign the request
    //    unauthorized          (6)       --Request unauthorized
    // }
    //
    // ResponseBytes ::= SEQUENCE {
    //    responseType   OBJECT IDENTIFIER,
    //    response       OCTET STRING
    // }
    //
    void parse(byte[] ocspResponse) throws CertificateException {
        ASN1Decoder decoder = new DERDecoder(ocspResponse);
        decoder.startSequence(); // OCSPResponse

        int responseStatus = decoder.decodeEnumerated().intValue();
        if (responseStatus != 0) {
            throw ElytronMessages.ocsp.ocspResponseStatus(responseStatus);
        }

        decoder.startExplicit(0);
        decoder.startSequence(); // ResponseBytes

        String responseType = decoder.decodeObjectIdentifier();

        if (X500.OID_BASIC_OCSP_RESPONSE.equals(responseType)) {
            decodeBasicOcspResponse(decoder.decodeOctetString());
        } else {
            throw ElytronMessages.ocsp.unsupportedOcspResponseType(responseType);
        }

        decoder.endSequence(); // ResponseBytes
        decoder.endExplicit();

        decoder.endSequence(); // OCSPResponse
    }

    //   BasicOCSPResponse ::= SEQUENCE {
    //      tbsResponseData      ResponseData,
    //      signatureAlgorithm   AlgorithmIdentifier,
    //      signature            BIT STRING,
    //      certs                [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL
    //   }
    //
    private void decodeBasicOcspResponse(byte[] basicOcspResponse) throws CertificateException {
        ASN1Decoder decoder = new DERDecoder(basicOcspResponse);
        decoder.startSequence();

        tbsResponseData = decoder.drainElement();
        decodeTbsResponseData(tbsResponseData);

        decoder.startSequence();
        signatureAlgorithmOid = decoder.decodeObjectIdentifier();
        decoder.endSequence();
        signatureBytes = decoder.decodeBitString();

        decoder.startExplicit(0);
        decoder.startSequence();

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        while (decoder.hasNextElement()) {
            Certificate cert = cf.generateCertificate(new ByteArrayInputStream(decoder.drainElement()));
            certificates.add((X509Certificate) cert);
        }

        decoder.endSequence();
        decoder.endExplicit();

        decoder.endSequence();
    }

    //   ResponseData ::= SEQUENCE {
    //      version              [0] EXPLICIT Version DEFAULT v1,
    //      responderID              ResponderID,
    //      producedAt               GeneralizedTime,
    //      responses                SEQUENCE OF SingleResponse,
    //      responseExtensions   [1] EXPLICIT Extensions OPTIONAL
    //   }
    //
    //   SingleResponse ::= SEQUENCE {
    //      certID                       CertID,
    //      certStatus                   CertStatus,
    //      thisUpdate                   GeneralizedTime,
    //      nextUpdate         [0]       EXPLICIT GeneralizedTime OPTIONAL,
    //      singleExtensions   [1]       EXPLICIT Extensions OPTIONAL
    //   }
    //
    //   CertStatus ::= CHOICE {
    //       good        [0]     IMPLICIT NULL,
    //       revoked     [1]     IMPLICIT RevokedInfo,
    //       unknown     [2]     IMPLICIT UnknownInfo
    //   }
    //
    //   RevokedInfo ::= SEQUENCE {
    //       revocationTime              GeneralizedTime,
    //       revocationReason    [0]     EXPLICIT CRLReason OPTIONAL
    //   }
    //
    //   UnknownInfo ::= NULL -- this can be replaced with an enumeration
    //
    private void decodeTbsResponseData(byte[] tbsResponseData) {
        ASN1Decoder decoder = new DERDecoder(tbsResponseData);
        decoder.startSequence(); // tbsResponseData

        // responderID
        if (decoder.isNextType(CONTEXT_SPECIFIC_MASK, 1, true)) {
            decoder.decodeImplicit(1); // byName: RDNSequence
            responderName = new X500Principal(decoder.drainElementValue());
        } else if (decoder.isNextType(CONTEXT_SPECIFIC_MASK, 2, true)) {
            decoder.decodeImplicit(2); // byKey: SHA-1 hash of responder's public key
            responderKeyHash = decoder.decodeOctetString();
        } else {
            throw new IllegalStateException();
        }

        decoder.skipElement(); // producedAt

        decoder.startSequence(); // responses
        while(decoder.hasNextElement()) {
            decoder.startSequence(); // SingleResponse

            decoder.startSequence(); // CertID
            decoder.startSequence();
            String hashAlgorithm = decoder.decodeObjectIdentifier();
            decoder.endSequence();
            byte[] issuerNameHash = decoder.decodeOctetString();
            byte[] issuerKeyHash = decoder.decodeOctetString();
            BigInteger serialNumber = decoder.decodeInteger();
            decoder.endSequence(); // CertID
            CertId certId = new CertId(hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber);

            if (decoder.isNextType(CONTEXT_SPECIFIC_MASK, 0, false)) {
                decoder.decodeImplicit(0);
                decoder.decodeNull();
                results.put(certId, new OcspStatus(CertStatus.GOOD, null));
            } else if (decoder.isNextType(CONTEXT_SPECIFIC_MASK, 1, true)) {
                decoder.decodeImplicit(1);
                decoder.startSequence();
                decoder.skipElement(); // revocationTime
                CRLReason reason = null;
                if (decoder.isNextType(CONTEXT_SPECIFIC_MASK, 0, true)) {
                    decoder.startExplicit(0);
                    reason = crlReasonFromInteger(decoder.decodeEnumerated().intValue());
                    decoder.endExplicit();
                }
                decoder.endSequence();
                results.put(certId, new OcspStatus(CertStatus.REVOKED, reason));
            } else {
                results.put(certId, new OcspStatus(CertStatus.UNKNOWN, null));
            }

            decoder.endSequence(); // SingleResponse
        }
        decoder.endSequence(); // responses
        decoder.endSequence(); // tbsResponseData
    }

    private CRLReason crlReasonFromInteger(int value) {
        switch (value) {
            case 0: return CRLReason.UNSPECIFIED;
            case 1: return CRLReason.KEY_COMPROMISE;
            case 2: return CRLReason.CA_COMPROMISE;
            case 3: return CRLReason.AFFILIATION_CHANGED;
            case 4: return CRLReason.SUPERSEDED;
            case 5: return CRLReason.CESSATION_OF_OPERATION;
            case 6: return CRLReason.CERTIFICATE_HOLD;
            case 8: return CRLReason.REMOVE_FROM_CRL;
            case 9: return CRLReason.PRIVILEGE_WITHDRAWN;
            case 10: return CRLReason.AA_COMPROMISE;
        }
        throw new IllegalArgumentException();
    }

}
