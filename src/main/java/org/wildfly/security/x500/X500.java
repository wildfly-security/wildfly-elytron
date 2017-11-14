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

package org.wildfly.security.x500;

import static org.wildfly.security._private.ElytronMessages.log;

import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;

import org.wildfly.common.Assert;

/**
 * Useful X500 constants and utilities.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class X500 {

    /**
     * A constant array containing zero certificates.
     */
    public static final X509Certificate[] NO_CERTIFICATES = new X509Certificate[0];

    private X500() {}

    // RFC 4514, 4517, 4519, and 5280 attribute type strings

    public static final String OID_AT                               = "2.5.4";

    public static final String OID_AT_COMMON_NAME                   = OID_AT + ".3";
    public static final String OID_AT_SURNAME                       = OID_AT + ".4";
    public static final String OID_AT_SERIAL_NUMBER                 = OID_AT + ".5";
    public static final String OID_AT_COUNTRY_NAME                  = OID_AT + ".6";
    public static final String OID_AT_LOCALITY_NAME                 = OID_AT + ".7";
    public static final String OID_AT_STATE_OR_PROVINCE_NAME        = OID_AT + ".8";
    public static final String OID_AT_STREET_ADDRESS                = OID_AT + ".9";
    public static final String OID_AT_ORGANIZATION_NAME             = OID_AT + ".10";
    public static final String OID_AT_ORGANIZATIONAL_UNIT_NAME      = OID_AT + ".11";
    public static final String OID_AT_TITLE                         = OID_AT + ".12";
    public static final String OID_AT_DESCRIPTION                   = OID_AT + ".13";
    public static final String OID_AT_BUSINESS_CATEGORY             = OID_AT + ".15";
    public static final String OID_AT_TELEPHONE_NUMBER              = OID_AT + ".20";
    public static final String OID_AT_FAX_NUMBER                    = OID_AT + ".23";
    public static final String OID_AT_NAME                          = OID_AT + ".41";
    public static final String OID_AT_GIVEN_NAME                    = OID_AT + ".42";
    public static final String OID_AT_INITIALS                      = OID_AT + ".43";
    public static final String OID_AT_GENERATION_QUALIFIER          = OID_AT + ".44";
    public static final String OID_AT_DN_QUALIFIER                  = OID_AT + ".46";
    public static final String OID_AT_HOUSE_IDENTIFIER              = OID_AT + ".51";
    public static final String OID_AT_PSEUDONYM                     = OID_AT + ".65";

    public static final String OID_UID      = "0.9.2342.19200300.100.1.1";
    public static final String OID_DC       = "0.9.2342.19200300.100.1.25";

    // RFC 5280 IDs

    public static final String OID_CE                               = "2.5.29";
    public static final String OID_CE_SUBJECT_DIRECTORY_ATTRIBUTES  = OID_CE + ".9";
    public static final String OID_CE_SUBJECT_KEY_IDENTIFIER        = OID_CE + ".14";
    public static final String OID_CE_KEY_USAGE                     = OID_CE + ".15";
    public static final String OID_CE_PRIVATE_KEY_USAGE_PERIOD      = OID_CE + ".16";
    public static final String OID_CE_SUBJECT_ALT_NAME              = OID_CE + ".17";
    public static final String OID_CE_ISSUER_ALT_NAME               = OID_CE + ".18";
    public static final String OID_CE_BASIC_CONSTRAINTS             = OID_CE + ".19";
    public static final String OID_CE_CRL_NUMBER                    = OID_CE + ".20";
    public static final String OID_CE_CRL_REASONS                   = OID_CE + ".21";
    public static final String OID_CE_HOLD_INSTRUCTION_CODE         = OID_CE + ".23";
    public static final String OID_CE_INVALIDITY_DATE               = OID_CE + ".24";
    public static final String OID_CE_DELTA_CLR_INDICATOR           = OID_CE + ".27";
    public static final String OID_CE_ISSUING_DISTRIBUTION_POINT    = OID_CE + ".28";
    public static final String OID_CE_CERTIFICATE_ISSUER            = OID_CE + ".29";
    public static final String OID_CE_NAME_CONSTRAINTS              = OID_CE + ".30";
    public static final String OID_CE_CRL_DISTRIBUTION_POINTS       = OID_CE + ".31";
    public static final String OID_CE_CERTIFICATE_POLICIES          = OID_CE + ".32";
    public static final String OID_CE_POLICY_MAPPINGS               = OID_CE + ".33";
    public static final String OID_CE_AUTHORITY_KEY_IDENTIFIER      = OID_CE + ".35";
    public static final String OID_CE_POLICY_CONSTRAINTS            = OID_CE + ".36";
    public static final String OID_CE_EXT_KEY_USAGE                 = OID_CE + ".37";
    public static final String OID_CE_FRESHEST_CRL                  = OID_CE + ".46";
    public static final String OID_CE_INHIBIT_ANY_POLICY            = OID_CE + ".54";

    public static final String OID_PKIX                             = "1.3.6.1.5.5.7";
    public static final String OID_PE                               = OID_PKIX + ".1";
    public static final String OID_QT                               = OID_PKIX + ".2";
    public static final String OID_KP                               = OID_PKIX + ".3";
    public static final String OID_AD                               = OID_PKIX + ".48";

    public static final String OID_PE_AUTHORITY_INFO_ACCESS         = OID_PE + ".1";
    public static final String OID_PE_SUBJECT_INFO_ACCESS           = OID_PE + ".11";

    public static final String OID_QT_CPS                           = OID_QT + ".1";
    public static final String OID_QT_UNOTICE                       = OID_QT + ".2";

    public static final String OID_KP_SERVER_AUTH                   = OID_KP + ".1";
    public static final String OID_KP_CLIENT_AUTH                   = OID_KP + ".2";
    public static final String OID_KP_CODE_SIGNING                  = OID_KP + ".3";
    public static final String OID_KP_EMAIL_PROTECTION              = OID_KP + ".4";
    public static final String OID_KP_TIME_STAMPING                 = OID_KP + ".8";
    public static final String OID_KP_OCSP_SIGNING                  = OID_KP + ".9";

    public static final String OID_AD_OCSP                          = OID_AD + ".1";
    public static final String OID_AD_CA_ISSUERS                    = OID_AD + ".2";
    public static final String OID_AD_TIME_STAMPING                 = OID_AD + ".3";
    public static final String OID_AD_CA_REPOSITORY                 = OID_AD + ".5";

    public static final String OID_HOLD_INSTRUCTION                 = "2.2.840.10040.2";
    @Deprecated // deprecated by RFC 5280
    public static final String OID_HOLD_INSTRUCTION_NONE            = OID_HOLD_INSTRUCTION + ".1";
    public static final String OID_HOLD_INSTRUCTION_CALL_ISSUER     = OID_HOLD_INSTRUCTION + ".2";
    public static final String OID_HOLD_INSTRUCTION_REJECT          = OID_HOLD_INSTRUCTION + ".3";

    /**
     * Convert an array into a {@link X509Certificate X509Certificate[]}.
     *
     * @param certificates the certificates (may not be {@code null})
     * @return the X.509 certificate array (not {@code null})
     * @throws ArrayStoreException if one of the certificates in the array is not an {@code X509Certificate}
     */
    public static X509Certificate[] asX509CertificateArray(Object[] certificates) throws ArrayStoreException {
        if (certificates.length == 0) {
            return NO_CERTIFICATES;
        } else if (certificates instanceof X509Certificate[]) {
            return (X509Certificate[]) certificates;
        } else {
            return Arrays.copyOf(certificates, certificates.length, X509Certificate[].class);
        }
    }

    /**
     * Convert an unordered array of certificates into an ordered X.509 certificate chain.
     *
     * @param firstPublicKey the public key that should be in the first certificate in the ordered X.509 certificate
     *                       chain (may not be {@code null})
     * @param certificates the unordered array of certificates (may not be {@code null})
     * @return the ordered X.509 certificate chain, as an array
     * @throws IllegalArgumentException if the given unordered array of certificates cannot be converted into an ordered X.509 certificate chain
     */
    public static X509Certificate[] asOrderedX509CertificateChain(PublicKey firstPublicKey, Certificate[] certificates) throws IllegalArgumentException {
        Assert.checkNotNullParam("firstPublicKey", firstPublicKey);
        Assert.checkNotNullParam("certificates", certificates);
        X509Certificate[] x509Certificates;
        try {
            x509Certificates = asX509CertificateArray(certificates);
        } catch (ArrayStoreException e) {
            throw log.nonX509CertificateInCertificateArray();
        }
        boolean foundFirstCertificate = false;
        for (int i = 0; i < x509Certificates.length; i++) {
            if (x509Certificates[i].getPublicKey().equals(firstPublicKey)) {
                foundFirstCertificate = true;
                swapCertificates(x509Certificates, 0, i);
                break;
            }
        }
        if (! foundFirstCertificate) {
            throw log.startingPublicKeyNotFoundInCertificateArray();
        }
        X509Certificate currentCertificate = x509Certificates[0];
        for (int i = 1; i < x509Certificates.length - 1; i++) {
            boolean issuerCertificateFound = false;
            for (int j = i; j < x509Certificates.length; j++) {
                if (issuedBy(currentCertificate, x509Certificates[j])) {
                    swapCertificates(x509Certificates, i, j);
                    issuerCertificateFound = true;
                    currentCertificate = x509Certificates[i];
                    break;
                }
            }
            if (! issuerCertificateFound) {
                throw log.incompleteCertificateArray();
            }
        }
        return x509Certificates;
    }

    /**
     * Create an X.509 certificate chain given the first certificate that should be in the chain and a map of certificates.
     *
     * @param firstCertificate the certificate that should be first in the newly created X.509 certificate chain
     * @param certificatesMap a map of distinguished names to certificates to use to create the X.509 certificate chain
     * @return the newly created X.509 certificate chain, as an array
     * @throws IllegalArgumentException if the X.509 certificate chain could not be created
     */
    public static X509Certificate[] createX509CertificateChain(final X509Certificate firstCertificate,
                                                               final HashMap<Principal, HashSet<X509Certificate>> certificatesMap) throws IllegalArgumentException {
        Assert.checkNotNullParam("firstCertificate", firstCertificate);
        Assert.checkNotNullParam("certificatesMap", certificatesMap);
        final ArrayList<X509Certificate> certificateChain = new ArrayList<>();
        if (createX509CertificateChain(firstCertificate, certificateChain, certificatesMap)) {
            Collections.reverse(certificateChain);
            return certificateChain.toArray(new X509Certificate[certificateChain.size()]);
        }
        throw log.unableToCreateCertificateChainFromCertificateMap();
    }

    private static void swapCertificates(Certificate[] certificates, int i, int j) {
        Certificate tempCertificate = certificates[i];
        certificates[i] = certificates[j];
        certificates[j] = tempCertificate;
    }

    private static boolean issuedBy(final X509Certificate certificate, X509Certificate issuer) {
        if (issuer.getSubjectDN().equals(certificate.getIssuerDN())) {
            try {
                certificate.verify(issuer.getPublicKey());
                return true;
            } catch (Exception e) {
                return false;
            }
        }
        return false;
    }

    private static boolean createX509CertificateChain(final X509Certificate firstCertificate, final ArrayList<X509Certificate> certificateChain,
                                                      final HashMap<Principal, HashSet<X509Certificate>> certificatesMap) {
        if (issuedBy(firstCertificate, firstCertificate)) {
            // self-signed
            certificateChain.add(firstCertificate);
            return true;
        }
        final HashSet<X509Certificate> issuerCertificates = certificatesMap.get(firstCertificate.getIssuerDN());
        if (issuerCertificates == null || issuerCertificates.isEmpty()) {
            return false;
        }
        for (X509Certificate issuerCertificate : issuerCertificates) {
            if (issuedBy(firstCertificate, issuerCertificate)) {
                // recurse
                if (createX509CertificateChain(issuerCertificate, certificateChain, certificatesMap)) {
                    certificateChain.add(firstCertificate);
                    return true;
                }
            }
        }
        return false;
    }

}
