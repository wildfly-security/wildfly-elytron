/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.ssl;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import javax.security.auth.callback.UnsupportedCallbackException;

import org.wildfly.security.asn1.util.ASN1;
import org.wildfly.security.auth.callback.CallbackUtil;
import org.wildfly.security.auth.callback.ChannelBindingCallback;

/**
 * Utilities for handling the "tls-server-end-point" channel binding strategy used by various types
 * of authentication mechanisms.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class TLSServerEndPointChannelBinding {
    public static final String TLS_SERVER_ENDPOINT = "tls-server-end-point";

    private TLSServerEndPointChannelBinding() {}

    /**
     * Get the digest algorithm that would be used for a given signature algorithm OID.
     *
     * @param sigAlgOID the signature algorithm OID (must not be {@code null})
     * @return the digest algorithm, or {@code null} if the OID is not recognized
     */
    public static String getDigestAlgorithm(final String sigAlgOID) {
        switch (sigAlgOID) {
            case ASN1.OID_MD2:
            case ASN1.OID_MD2_WITH_RSA:
            case ASN1.OID_MD4_WITH_RSA:
            case ASN1.OID_MD5:
            case ASN1.OID_MD5_WITH_RSA:
            case ASN1.OID_SHA1_WITH_DSA:
            case ASN1.OID_SHA1_WITH_RSA:
            case ASN1.OID_SHA1_WITH_ECDSA:
            case ASN1.OID_SHA1:
            case ASN1.OID_SHA224_WITH_ECDSA:
            case ASN1.OID_SHA256_WITH_RSA:
            case ASN1.OID_SHA256_WITH_ECDSA:
                return "SHA-256";
            case ASN1.OID_SHA384_WITH_ECDSA:
            case ASN1.OID_SHA384_WITH_RSA:
                return "SHA-384";
            case ASN1.OID_SHA512_WITH_ECDSA:
            case ASN1.OID_SHA512_WITH_RSA:
                return "SHA-512";
            default: {
                return null;
            }
        }
    }

    /**
     * Convenience method to handle a channel binding callback.
     *
     * @param channelBindingCallback the callback (must not be {@code null})
     * @param serverCerts the server certificate chain
     * @throws UnsupportedCallbackException if the server certificates are not present or unsupported and the callback is not optional
     */
    public static void handleChannelBindingCallback(ChannelBindingCallback channelBindingCallback, X509Certificate[] serverCerts) throws UnsupportedCallbackException {
        if (serverCerts != null && serverCerts.length > 0) {
            // tls-server-end-point
            try {
                final byte[] bindingData = getChannelBindingData(serverCerts[0]);
                if (bindingData != null) {
                    channelBindingCallback.setBindingData(bindingData);
                    channelBindingCallback.setBindingType(TLS_SERVER_ENDPOINT);
                    return;
                }
            } catch (CertificateEncodingException | NoSuchAlgorithmException e) {
                // fail silently
            }
        }
        CallbackUtil.unsupported(channelBindingCallback);
    }

    static byte[] getChannelBindingData(X509Certificate serverCert) throws NoSuchAlgorithmException, CertificateEncodingException {
        if (serverCert == null) {
            return null;
        }
        final String digestAlgorithm = TLSServerEndPointChannelBinding.getDigestAlgorithm(serverCert.getSigAlgOID());
        if (digestAlgorithm == null) {
            return null;
        }
        return MessageDigest.getInstance(digestAlgorithm).digest(serverCert.getEncoded());
    }
}
