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

import static org.wildfly.security.x500.X500.OID_KP_OCSP_SIGNING;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

import org.wildfly.security._private.ElytronMessages;

/**
 * The verifier of OCSP response signer.
 * Check whether the OCSP response is signed by authorized certificate.
 */
class OcspSignatureVerifier {

    private final Map<X500Principal, X509Certificate> trustedByName = new HashMap<>();
    private final Map<byte[], X509Certificate> trustedByKeyHash = new HashMap<>();

    /**
     * Construct the verifier.
     *
     * @param trusted the list of OCSP responders certificates trusted to sign any OCSP responses
     */
    OcspSignatureVerifier(Collection<X509Certificate> trusted) {
        if (trusted != null) {
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-1");
                for (X509Certificate c : trusted) {
                    trustedByName.put(c.getSubjectX500Principal(), c);
                    trustedByKeyHash.put(digest.digest(c.getPublicKey().getEncoded()), c);
                }
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
        }
    }

    /**
     * Check whether the OCSP response is signed by authorized authority.
     *
     * @param response the OCSP response to check
     * @param issuer the certificate of CA issuing the checked certificate
     * @return {@code true} if the response is signed by authorized authority
     */
    boolean check(OcspResponse response, X509Certificate issuer) {
        try {
            Certificate choosen = chooseCertificateToCheckAgainst(response, issuer);
            if (choosen == null)
                return false;
            return response.checkSignature(choosen);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private X509Certificate chooseCertificateToCheckAgainst(OcspResponse response, X509Certificate issuer) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-1");
        byte[] keyHash = response.getResponderKeyHash();
        X500Principal name = response.getResponderName();

        if (keyHash != null) {
            if (trustedByKeyHash.containsKey(keyHash)) {
                return trustedByKeyHash.get(keyHash);
            }
            if (Arrays.equals(keyHash, digest.digest(issuer.getPublicKey().getEncoded()))) {
                return issuer;
            }
            for (X509Certificate c : response.getCertificates()) {
                if (Arrays.equals(keyHash, digest.digest(c.getPublicKey().getEncoded()))) {
                    if (isResponderCertOfIssuer(c, issuer)) {
                        return c;
                    }
                }
            }
        }
        if (name != null) {
            if (trustedByName.containsKey(name)) {
                return trustedByName.get(name);
            }
            if (name.equals(issuer.getSubjectX500Principal())) {
                return issuer;
            }
            for (X509Certificate c : response.getCertificates()) {
                if (name.equals(c.getSubjectX500Principal())) {
                    if (isResponderCertOfIssuer(c, issuer)) {
                        return c;
                    }
                }
            }
        }
        return null;
    }

    private static boolean isResponderCertOfIssuer(X509Certificate certificate, X509Certificate issuer) {
        try {
            certificate.verify(issuer.getPublicKey());
            return certificate.getExtendedKeyUsage().contains(OID_KP_OCSP_SIGNING);
        } catch (Exception e) {
            ElytronMessages.ocsp.trace(e);
        }
        return false;
    }
}
