/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.x500;

import static org.wildfly.security.x500._private.ElytronMessages.log;

import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import org.wildfly.security.asn1.ASN1Encodable;
import org.wildfly.security.asn1.ASN1Encoder;
import org.wildfly.security.asn1.ASN1Exception;

/**
 * A representation of a trusted certificate authority.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public abstract class TrustedAuthority implements ASN1Encodable {

    // Trusted authority types
    public static final int AUTHORITY_NAME = 0;
    public static final int ISSUER_NAME_HASH = 1;
    public static final int ISSUER_KEY_HASH = 2;
    public static final int AUTHORITY_CERTIFICATE = 3;
    public static final int PKCS_15_KEY_HASH = 4;

    private final int type;

    TrustedAuthority(final int type) {
        if (type < 0 || type > 4) {
            throw log.invalidValueForTrustedAuthorityType();
        }
        this.type = type;
    }

    /**
     * Get the type of this trusted authority.
     *
     * @return the type of this trusted authority
     */
    public int getType() {
        return type;
    }

    /**
     * Get the identifier for this trusted authority.
     *
     * @return the identifier for this trusted authority
     */
    public abstract Object getIdentifier();

    /**
     * <p>
     * Encode this {@code TrustedAuth} element using the given trusted authority and DER encoder,
     * where {@code TrustedAuth} is defined as:
     *
     * <pre>
     *      TrustedAuth ::= CHOICE {
     *          authorityName         [0] Name,
     *              -- SubjectName from CA certificate
     *          issuerNameHash        [1] OCTET STRING,
     *              -- SHA-1 hash of Authority's DN
     *          issuerKeyHash         [2] OCTET STRING,
     *              -- SHA-1 hash of Authority's public key
     *          authorityCertificate  [3] Certificate,
     *              -- CA certificate
     *          pkcs15KeyHash         [4] OCTET STRING
     *              -- PKCS #15 key hash
     *      }
     * </pre>
     * </p>
     *
     * @param encoder the DER encoder (must not be {@code null})
     * @throws ASN1Exception if any of the trusted authorities are invalid
     */
    public abstract void encodeTo(final ASN1Encoder encoder) throws ASN1Exception;

    /**
     * A trusted authority that is identified by its name.
     *
     * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
     */
    public static final class NameTrustedAuthority extends TrustedAuthority {

        private final String name;

        /**
         * Construct a new instance.
         *
         * @param name the distinguished name of this trusted authority, as a {@code String}
         */
        public NameTrustedAuthority(final String name) {
            super(AUTHORITY_NAME);
            this.name = name;
        }

        public String getIdentifier() {
            return name;
        }

        public void encodeTo(final ASN1Encoder encoder) {
            encoder.startExplicit(getType());
            encoder.writeEncoded(new X500Principal(name).getEncoded());
            encoder.endExplicit();
        }
    }

    /**
     * A trusted authority that is identified by its certificate.
     *
     * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
     */
    public static final class CertificateTrustedAuthority extends TrustedAuthority {

        private final X509Certificate cert;

        /**
         * Construct a new instance.
         *
         * @param cert this trusted authority's certificate
         */
        public CertificateTrustedAuthority(final X509Certificate cert) {
            super(AUTHORITY_CERTIFICATE);
            this.cert = cert;
        }

        public X509Certificate getIdentifier() {
            return cert;
        }

        public void encodeTo(final ASN1Encoder encoder) {
            encoder.encodeImplicit(getType());
            try {
                encoder.writeEncoded(cert.getEncoded());
            } catch (CertificateEncodingException e) {
                throw new ASN1Exception(e);
            }
        }
    }

    /**
     * A trusted authority that is identified by a hash.
     *
     * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
     */
    public abstract static class HashTrustedAuthority extends TrustedAuthority {

        private final byte[] hash;

        HashTrustedAuthority(final int type, final byte[] hash) {
            super(type);
            this.hash = hash;
        }

        HashTrustedAuthority(final int type, final String hash) {
            this(type, hash.getBytes(StandardCharsets.UTF_8));
        }

        public byte[] getIdentifier() {
            return hash.clone();
        }

        public void encodeTo(final ASN1Encoder encoder) {
            encoder.encodeImplicit(getType());
            encoder.encodeOctetString(hash);
        }
    }

    /**
     * A trusted authority that is identified by the hash of its name.
     *
     * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
     */
    public static final class IssuerNameHashTrustedAuthority extends HashTrustedAuthority {

        /**
         * Construct a new instance.
         *
         * @param hash an octet string that contains the SHA-1 hash of the DER encoding of the subject name from
         * this trusted authority's certificate, as a byte array
         */
        public IssuerNameHashTrustedAuthority(final byte[] hash) {
            super(ISSUER_NAME_HASH, hash);
        }

        /**
         * Construct a new instance.
         *
         * @param hash an octet string that contains the SHA-1 hash of the DER encoding of the subject name from
         * this trusted authority's certificate
         */
        public IssuerNameHashTrustedAuthority(final String hash) {
            super(ISSUER_NAME_HASH, hash);
        }
    }

    /**
     * A trusted authority that is identified by the hash of its public key.
     *
     * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
     */
    public static final class IssuerKeyHashTrustedAuthority extends HashTrustedAuthority {

        /**
         * Construct a new instance.
         *
         * @param hash an octet string that contains the SHA-1 hash of this trusted authority's public key, as a byte array
         */
        public IssuerKeyHashTrustedAuthority(final byte[] hash) {
            super(ISSUER_KEY_HASH, hash);
        }

        /**
         * Construct a new instance.
         *
         * @param hash an octet string that contains the SHA-1 hash of this trusted authority's public key
         */
        public IssuerKeyHashTrustedAuthority(final String hash) {
            super(ISSUER_KEY_HASH, hash);
        }
    }

    /**
     * A trusted authority that is identified by the PKCS #15 key hash.
     *
     * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
     */
    public static final class PKCS15KeyHashTrustedAuthority extends HashTrustedAuthority {

        /**
         * Construct a new instance.
         *
         * @param hash an octet string that contains this trusted authority's PKCS #15 key hash, as a byte array
         */
        public PKCS15KeyHashTrustedAuthority(byte[] hash) {
            super(PKCS_15_KEY_HASH, hash);
        }

        /**
         * Construct a new instance.
         *
         * @param hash an octet string that contains this trusted authority's PKCS #15 key hash
         */
        public PKCS15KeyHashTrustedAuthority(final String hash) {
            super(PKCS_15_KEY_HASH, hash);
        }
    }
}
