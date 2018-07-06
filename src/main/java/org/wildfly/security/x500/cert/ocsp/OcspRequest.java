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

import java.util.Collection;

import org.wildfly.security.asn1.ASN1Encoder;
import org.wildfly.security.asn1.DEREncoder;

/**
 * A request to the OCSP responder.
 */
class OcspRequest {

    private Collection<CertId> certificateIds;

    /**
     * Construct an OCSP request
     * @param certificateIds certificates to check
     */
    OcspRequest(Collection<CertId> certificateIds) {
        this.certificateIds = certificateIds;
    }

    /**
     * Get the collection of certificates to check.
     * @return certificates to check
     */
    Collection<CertId> getCertificateIds() {
        return certificateIds;
    }

    /**
     * Get the request encoded for sending to the OCSP responder.
     * @return the encoded request
     */
    byte[] getEncoded() {
        ASN1Encoder encoder = new DEREncoder();
        encodeOcspRequest(encoder);
        return encoder.getEncoded();
    }

    //   OCSPRequest     ::=     SEQUENCE {
    //       tbsRequest                  TBSRequest,
    //       optionalSignature   [0]     EXPLICIT Signature OPTIONAL
    //   }
    //
    //   TBSRequest      ::=     SEQUENCE {
    //       version             [0]     EXPLICIT Version DEFAULT v1,
    //       requestorName       [1]     EXPLICIT GeneralName OPTIONAL,
    //       requestList                 SEQUENCE OF Request,
    //       requestExtensions   [2]     EXPLICIT Extensions OPTIONAL
    //   }
    //
    //   Version         ::=             INTEGER  {  v1(0) }
    //
    private void encodeOcspRequest(ASN1Encoder encoder) {
        encoder.startSequence(); // OCSPRequest
        encoder.startSequence(); // TBSRequest

        encoder.startExplicit(0);
        encoder.encodeInteger(0); // version = v1(0)
        encoder.endExplicit();

        encoder.startSequence(); // SEQUENCE OF Request
        for (CertId certId : certificateIds) {
            encodeRequest(encoder, certId);
        }
        encoder.endSequence(); // SEQUENCE OF Request

        encoder.endSequence(); // TBSRequest
        // TODO optionalSignature
        encoder.endSequence(); // OCSPRequest
    }

    //   Request         ::=     SEQUENCE {
    //       reqCert                     CertID,
    //       singleRequestExtensions     [0] EXPLICIT Extensions OPTIONAL
    //   }
    //
    //   CertID          ::=     SEQUENCE {
    //       hashAlgorithm       AlgorithmIdentifier,
    //       issuerNameHash      OCTET STRING, -- Hash of Issuer's DN
    //       issuerKeyHash       OCTET STRING, -- Hash of Issuers public key
    //       serialNumber        CertificateSerialNumber
    //   }
    //
    //   CertificateSerialNumber  ::=  INTEGER
    //
    //   AlgorithmIdentifier  ::=  SEQUENCE  {
    //       algorithm               OBJECT IDENTIFIER,
    //       parameters              ANY DEFINED BY algorithm OPTIONAL
    //   }
    //
    private void encodeRequest(ASN1Encoder encoder, CertId certId) {
        encoder.startSequence(); // Request
        encoder.startSequence(); // CertID

        encoder.startSequence();
        encoder.encodeObjectIdentifier(certId.getHashAlgorithm());
        encoder.endSequence();

        encoder.encodeOctetString(certId.getIssuerNameHash());
        encoder.encodeOctetString(certId.getIssuerKeyHash());
        encoder.encodeInteger(certId.getSerialNumber());

        encoder.endSequence(); // CertID
        encoder.endSequence(); // Request
    }
}
