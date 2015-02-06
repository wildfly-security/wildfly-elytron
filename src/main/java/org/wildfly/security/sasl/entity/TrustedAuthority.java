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


import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;

/**
 * A representation of a trusted certificate authority.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public abstract class TrustedAuthority {

    // Trusted authority types
    public static final int AUTHORITY_NAME = 0;
    public static final int ISSUER_NAME_HASH = 1;
    public static final int ISSUER_KEY_HASH = 2;
    public static final int AUTHORITY_CERTIFICATE = 3;
    public static final int PKCS_15_KEY_HASH = 4;

    private final int type;

    TrustedAuthority(final int type) {
        if (type < 0 || type > 4) {
            throw new IllegalArgumentException("Invalid value for trusted authority type; expected a value between 0 and 4 (inclusive)");
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
