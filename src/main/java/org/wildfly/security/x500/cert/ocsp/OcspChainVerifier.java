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
import static org.wildfly.security.x500.GeneralName.URI_NAME;
import static org.wildfly.security.x500.X500.OID_AD_OCSP;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;

import org.wildfly.security._private.ElytronMessages;
import org.wildfly.security.asn1.DERDecoder;
import org.wildfly.security.x500.GeneralName;
import org.wildfly.security.x500.X500;

/**
 * The certificate chain verifier.
 */
public class OcspChainVerifier {

    private final URL responder;
    private final OcspSignatureVerifier signatureVerifier;
    private final OcspChecker checker;
    private final boolean acceptUnknownCertificates;
    private final boolean acceptWhenStatusUnavailable;

    /**
     * Construct the certificate chain verifier.
     *
     * @param checker the checker providing status of individual certificates
     * @param responder the responder to use to check all certificates ({@code null} to use responder from the certificate)
     * @param trusted the collection of trusted OCSP responders certificates
     * @param acceptUnknownCertificates whether should be certificate unknown by OCSP responder considered valid
     * @param acceptWhenStatusUnavailable whether should be certificate considered valid when OCSP responder is unavailable
     */
    public OcspChainVerifier(OcspChecker checker, URL responder, Collection<X509Certificate> trusted, boolean acceptUnknownCertificates, boolean acceptWhenStatusUnavailable) {
        this.checker = checker;
        this.responder = responder;
        this.signatureVerifier = new OcspSignatureVerifier(trusted);
        this.acceptUnknownCertificates = acceptUnknownCertificates;
        this.acceptWhenStatusUnavailable = acceptWhenStatusUnavailable;
    }

    /**
     * Check the certificate chain.
     *
     * @param chain the certificate chain
     * @throws CertificateException if the validation fails (some certificate in the chain is revoked for example)
     */
    public void checkChain(X509Certificate[] chain) throws CertificateException {
        ElytronMessages.ocsp.tracef("OCSP validation of chain of %d certificates", chain.length);
        for (int i = 0; i < chain.length - 1; i++) {
            X509Certificate certificate = chain[i];
            X509Certificate issuer = chain[i + 1];
            try {
                URL responder = getResponder(certificate);
                if (responder == null) {
                    ElytronMessages.ocsp.tracef("OCSP validation of %s skipped - no OCSP responder", certificate);
                    continue;
                }
                CertId certId = CertId.fromCertificate(certificate, issuer);
                OcspStatus status = checker.obtainStatus(certId, issuer, responder, signatureVerifier);
                ElytronMessages.ocsp.tracef("OCSP status of %s: %s", certificate, status);
                if (status.getStatus() == OcspStatus.CertStatus.REVOKED ||
                        (status.getStatus() == OcspStatus.CertStatus.UNKNOWN && ! acceptUnknownCertificates)) {
                    throw ElytronMessages.ocsp.certificateIsRevoked(certificate.getSerialNumber(), responder);
                }
            } catch (IOException e) {
                ElytronMessages.ocsp.tracef(e, "OCSP validation of %s has failed", certificate);
                if (! acceptWhenStatusUnavailable) {
                    throw ElytronMessages.ocsp.ocspValidationHasFailed(certificate.toString(), e);
                }
            }
        }
    }

    private URL getResponder(X509Certificate certificate) throws MalformedURLException {
        if (responder != null) {
            // custom responder set
            return responder;
        } else {
            // decode OCSP responder URL from the certificate
            byte[] extensionBytes = certificate.getExtensionValue(X500.OID_PE_AUTHORITY_INFO_ACCESS);
            if (extensionBytes == null) {
                ElytronMessages.ocsp.tracef("Certificate %s does not define AuthorityInfoAccess extension", certificate);
                return null;
            }
            DERDecoder decoder = new DERDecoder(extensionBytes);
            decoder = new DERDecoder(decoder.decodeOctetString());
            decoder.startSequence();
            while(decoder.hasNextElement()) {
                decoder.startSequence();
                if (OID_AD_OCSP.equalsIgnoreCase(decoder.decodeObjectIdentifier())) {
                    if (decoder.isNextType(CONTEXT_SPECIFIC_MASK, URI_NAME, false)) {
                        decoder.decodeImplicit(URI_NAME);
                        GeneralName.URIName uri = new GeneralName.URIName(decoder.decodeIA5String());
                        URL responder = new URL(uri.getName());
                        ElytronMessages.ocsp.tracef("Decoded OCSP responder \"%s\" for certificate %s", responder, certificate);
                        return responder;
                    }
                }
                decoder.endSequence();
            }
            decoder.endSequence();
            ElytronMessages.ocsp.tracef("Certificate %s does not define OCSP responder", certificate);
            return null;
        }
    }
}
