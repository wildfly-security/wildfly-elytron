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

package org.wildfly.security.auth.realm.ldap;

import org.wildfly.security._private.ElytronMessages;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.evidence.X509PeerCertificateChainEvidence;
import org.wildfly.security.util.ByteIterator;

import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * An {@link EvidenceVerifier} that verifies a {@link org.wildfly.security.evidence.X509PeerCertificateChainEvidence}.
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
class X509EvidenceVerifier implements EvidenceVerifier {

    private final String ENV_BINARY_ATTRIBUTES = "java.naming.ldap.attributes.binary";

    private final List<CertificateVerifier> certificateVerifiers;

    X509EvidenceVerifier(final List<CertificateVerifier> certificateVerifiers) {
        this.certificateVerifiers = certificateVerifiers;
    }

    /**
     * Object allowing to verify X509 certificate against information from LDAP
     */
    interface CertificateVerifier {
        /**
         * Construct set of LDAP attributes, which should be loaded to be able to {@link #verifyCertificate}.
         * @param requiredAttributes output set of attribute names
         */
        default void addRequiredLdapAttributes(Set<String> requiredAttributes) {}

        /**
         * Construct set of LDAP attributes, which should be loaded as binary data.
         * @param binaryAttributes output set of attribute names
         */
        default void addBinaryLdapAttributes(Set<String> binaryAttributes) {}

        /**
         * Verify X509 certificate of user using identity information from LDAP
         * @param certificate X509 certificate to verify
         * @param attributes LDAP attributes values of given identity
         * @return if certificate was accepted by this verifier
         * @throws NamingException when problem with LDAP
         */
        boolean verifyCertificate(X509Certificate certificate, Attributes attributes) throws NamingException, RealmUnavailableException;
    }

    static class SerialNumberCertificateVerifier implements CertificateVerifier {

        final String ldapAttribute;

        SerialNumberCertificateVerifier(String ldapAttribute) {
            this.ldapAttribute = ldapAttribute;
        }

        @Override
        public void addRequiredLdapAttributes(Set<String> requiredAttributes) {
            requiredAttributes.add(ldapAttribute);
        }

        @Override
        public boolean verifyCertificate(X509Certificate certificate, Attributes attributes) throws NamingException {
            Attribute attribute = attributes.get(ldapAttribute);
            final int size = attribute.size();
            for (int i = 0; i < size; i++) {
                BigInteger value = new BigInteger((String) attribute.get(i));
                if (certificate.getSerialNumber().equals(value)) {
                    return true;
                }
            }
            return false;
        }
    }

    static class SubjectDnCertificateVerifier implements CertificateVerifier {

        final String ldapAttribute;

        SubjectDnCertificateVerifier(String ldapAttribute) {
            this.ldapAttribute = ldapAttribute;
        }

        @Override
        public void addRequiredLdapAttributes(Set<String> requiredAttributes) {
            requiredAttributes.add(ldapAttribute);
        }

        @Override
        public boolean verifyCertificate(X509Certificate certificate, Attributes attributes) throws NamingException {
            Attribute attribute = attributes.get(ldapAttribute);
            final int size = attribute.size();
            for (int i = 0; i < size; i++) {
                if (certificate.getSubjectDN().getName().equals(attribute.get(i))) {
                    return true;
                }
            }
            return false;
        }
    }

    static class DigestCertificateVerifier implements CertificateVerifier {

        final String ldapAttribute;
        final String algorithm;

        DigestCertificateVerifier(String ldapAttribute, String algorithm) {
            this.ldapAttribute = ldapAttribute;
            this.algorithm = algorithm;
        }

        @Override
        public void addRequiredLdapAttributes(Set<String> requiredAttributes) {
            requiredAttributes.add(ldapAttribute);
        }

        @Override
        public boolean verifyCertificate(X509Certificate certificate, Attributes attributes) throws NamingException, RealmUnavailableException {
            Attribute attribute = attributes.get(ldapAttribute);
            final int size = attribute.size();
            try {
                MessageDigest md = MessageDigest.getInstance(algorithm);
                for (int i = 0; i < size; i++) {
                    String digest = ByteIterator.ofBytes(md.digest(certificate.getEncoded())).hexEncode(true).drainToString();
                    if (digest.equalsIgnoreCase((String) attribute.get(i))) {
                        return true;
                    }
                }
            } catch (NoSuchAlgorithmException | CertificateEncodingException e) {
                throw new RealmUnavailableException(e);
            }
            return false;
        }
    }

    static class EncodedCertificateVerifier implements CertificateVerifier {

        final String ldapAttribute;

        EncodedCertificateVerifier(String ldapAttribute) {
            this.ldapAttribute = ldapAttribute;
        }

        @Override
        public void addRequiredLdapAttributes(Set<String> requiredAttributes) {
            requiredAttributes.add(ldapAttribute);
        }

        @Override
        public void addBinaryLdapAttributes(Set<String> binaryAttributes) {
            binaryAttributes.add(ldapAttribute);
        }

        @Override
        public boolean verifyCertificate(X509Certificate certificate, Attributes attributes) throws NamingException, RealmUnavailableException {
            Attribute attribute = attributes.get(ldapAttribute);
            final int size = attribute.size();
            try {
                for (int i = 0; i < size; i++) {
                    if (Arrays.equals(certificate.getEncoded(), (byte[]) attribute.get(i))) {
                        return true;
                    }
                }
            } catch (CertificateEncodingException e) {
                throw new RealmUnavailableException(e);
            }
            return false;
        }
    }

    @Override
    public SupportLevel getEvidenceVerifySupport(DirContext context, Class<? extends Evidence> evidenceType, String algorithmName) throws RealmUnavailableException {
        return evidenceType == X509PeerCertificateChainEvidence.class ? SupportLevel.POSSIBLY_SUPPORTED : SupportLevel.UNSUPPORTED;
    }

    @Override
    public IdentityEvidenceVerifier forIdentity(DirContext context, String distinguishedName) throws RealmUnavailableException {
        return new IdentityEvidenceVerifier() {

            @Override
            public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) throws RealmUnavailableException {
                return evidenceType == X509PeerCertificateChainEvidence.class ? SupportLevel.POSSIBLY_SUPPORTED : SupportLevel.UNSUPPORTED;
            }

            @Override
            public boolean verifyEvidence(Evidence evidence) throws RealmUnavailableException {
                if (evidence instanceof X509PeerCertificateChainEvidence) {
                    X509Certificate certificate = ((X509PeerCertificateChainEvidence) evidence).getFirstCertificate();

                    Set<String> requiredAttributes = new HashSet<>();
                    Set<String> binaryAttributes = new HashSet<>();
                    for (CertificateVerifier certificateVerifier : certificateVerifiers) {
                        certificateVerifier.addRequiredLdapAttributes(requiredAttributes);
                        certificateVerifier.addBinaryLdapAttributes(binaryAttributes);
                    }
                    try {
                        Object binaryAttributesBackup = null;
                        if (binaryAttributes.size() != 0) { // set attributes which should be returned in binary form
                            binaryAttributesBackup = context.getEnvironment().get(ENV_BINARY_ATTRIBUTES);
                            context.addToEnvironment(ENV_BINARY_ATTRIBUTES, String.join(" ", binaryAttributes));
                        }

                        String[] requestedAttributes = requiredAttributes.toArray(new String[requiredAttributes.size()]);
                        Attributes attributes = context.getAttributes(distinguishedName, requestedAttributes);

                        if (binaryAttributes.size() != 0) { // revert environment change
                            if (binaryAttributesBackup == null) {
                                context.removeFromEnvironment(ENV_BINARY_ATTRIBUTES);
                            } else {
                                context.addToEnvironment(ENV_BINARY_ATTRIBUTES, binaryAttributesBackup);
                            }
                        }

                        for (CertificateVerifier certificateVerifier : certificateVerifiers) {
                            if ( ! certificateVerifier.verifyCertificate(certificate, attributes)) {
                                ElytronMessages.log.tracef("X509 client certificate rejected by %s of X509EvidenceVerifier", certificateVerifier);
                                return false;
                            }
                        }
                        ElytronMessages.log.trace("X509 client certificate accepted by X509EvidenceVerifier");
                        return true;
                    } catch (NamingException e) {
                        throw new RealmUnavailableException(e);
                    }
                }
                return false;
            }
        };
    }
}
