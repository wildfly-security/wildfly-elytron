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

import org.wildfly.common.iteration.ByteIterator;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.evidence.X509PeerCertificateChainEvidence;
import org.wildfly.security.util.LdapUtil;

import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.function.Supplier;

/**
 * An {@link EvidenceVerifier} that verifies a {@link org.wildfly.security.evidence.X509PeerCertificateChainEvidence}.
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
class X509EvidenceVerifier implements EvidenceVerifier {

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
        default void addRequiredLdapAttributes(Collection<String> requiredAttributes) {}

        /**
         * Construct set of LDAP attributes, which should be loaded as binary data.
         * @param binaryAttributes output set of attribute names
         */
        default void addBinaryLdapAttributes(Collection<String> binaryAttributes) {}

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
        public void addRequiredLdapAttributes(Collection<String> requiredAttributes) {
            requiredAttributes.add(ldapAttribute);
        }

        @Override
        public boolean verifyCertificate(X509Certificate certificate, Attributes attributes) throws NamingException {
            Attribute attribute = attributes.get(ldapAttribute);

            if (attribute == null) return false;

            final int size = attribute.size();
            for (int i = 0; i < size; i++) {
                Object attrSerialNumber = attribute.get(i);
                if (attrSerialNumber != null){
                    BigInteger value = new BigInteger((String) attrSerialNumber);
                    if (certificate.getSerialNumber().equals(value)) {
                        return true;
                    }
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
        public void addRequiredLdapAttributes(Collection<String> requiredAttributes) {
            requiredAttributes.add(ldapAttribute);
        }

        @Override
        public boolean verifyCertificate(X509Certificate certificate, Attributes attributes) throws NamingException {
            Attribute attribute = attributes.get(ldapAttribute);

            if (attribute == null) return false;

            final int size = attribute.size();
            for (int i = 0; i < size; i++) {
                Object attrSubject = attribute.get(i);
                if (attrSubject != null){

                    X500Principal certSubjectX500Principal = certificate.getSubjectX500Principal();
                    X500Principal attSubjectX500Principal = new X500Principal((String) attrSubject);

                    if ( certSubjectX500Principal.equals(attSubjectX500Principal) ) {
                        return true;
                    }
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
        public void addRequiredLdapAttributes(Collection<String> requiredAttributes) {
            requiredAttributes.add(ldapAttribute);
        }

        @Override
        public boolean verifyCertificate(X509Certificate certificate, Attributes attributes) throws NamingException, RealmUnavailableException {
            Attribute attribute = attributes.get(ldapAttribute);

            if (attribute == null) return false;

            final int size = attribute.size();
            try {
                MessageDigest md = MessageDigest.getInstance(algorithm);
                String digest = ByteIterator.ofBytes(md.digest(certificate.getEncoded())).hexEncode(true).drainToString();

                for (int i = 0; i < size; i++) {
                    Object attrDigest = attribute.get(i);
                    if (attrDigest != null){
                        if (digest.equalsIgnoreCase((String) attrDigest)) {
                            return true;
                        }
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
        public void addRequiredLdapAttributes(Collection<String> requiredAttributes) {
            requiredAttributes.add(ldapAttribute);
        }

        @Override
        public void addBinaryLdapAttributes(Collection<String> binaryAttributes) {
            binaryAttributes.add(ldapAttribute);
        }

        @Override
        public boolean verifyCertificate(X509Certificate certificate, Attributes attributes) throws NamingException, RealmUnavailableException {
            Attribute attribute = LdapUtil.getBinaryAttribute(attributes, ldapAttribute);

            if (attribute == null) return false;

            final int size = attribute.size();
            try {
                for (int i = 0; i < size; i++) {
                    Object attrCertificate = attribute.get(i);
                    if (attrCertificate != null){
                        if (MessageDigest.isEqual(certificate.getEncoded(), (byte[]) attrCertificate)) {
                            return true;
                        }
                    }
                }
            } catch (CertificateEncodingException e) {
                throw new RealmUnavailableException(e);
            }
            return false;
        }
    }

    @Override
    public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) throws RealmUnavailableException {
        return evidenceType == X509PeerCertificateChainEvidence.class ? SupportLevel.POSSIBLY_SUPPORTED : SupportLevel.UNSUPPORTED;
    }

    @Override
    public IdentityEvidenceVerifier forIdentity(final DirContext dirContext, final String distinguishedName, final String url, Attributes attributes) throws RealmUnavailableException {
        return new IdentityEvidenceVerifier() {

            @Override
            public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName, Supplier<Provider[]> providers) throws RealmUnavailableException {
                return evidenceType == X509PeerCertificateChainEvidence.class ? SupportLevel.POSSIBLY_SUPPORTED : SupportLevel.UNSUPPORTED;
            }

            @Override
            public boolean verifyEvidence(Evidence evidence, Supplier<Provider[]> providers) throws RealmUnavailableException {
                if (evidence instanceof X509PeerCertificateChainEvidence) {
                    X509Certificate certificate = ((X509PeerCertificateChainEvidence) evidence).getFirstCertificate();

                    try {
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

    @Override
    public void addRequiredIdentityAttributes(Collection<String> attributes) {
        for (CertificateVerifier verifier : certificateVerifiers) {
            verifier.addRequiredLdapAttributes(attributes);
        }
    }

    @Override
    public void addBinaryIdentityAttributes(Collection<String> attributes) {
        for (CertificateVerifier verifier : certificateVerifiers) {
            verifier.addBinaryLdapAttributes(attributes);
        }
    }
}
