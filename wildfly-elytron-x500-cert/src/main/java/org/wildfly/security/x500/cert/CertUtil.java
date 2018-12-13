/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wildfly.security.x500.cert;

import static org.wildfly.security.x500.cert.ElytronMessages.log;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import org.wildfly.common.iteration.CodePointIterator;
import org.wildfly.security.x500.GeneralName;
import org.wildfly.security.x500.X500;


/**
 * A utility class with common methods used for generating certificate signing requests and self-signed certificates.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 * @since 1.2.0
 */
class CertUtil {

    private static final String BASIC_CONSTRAINTS = "BasicConstraints";
    private static final String KEY_USAGE = "KeyUsage";
    private static final String CE_EXT_KEY_USAGE = "ExtendedKeyUsage";
    private static final String CE_SUBJECT_ALT_NAME = "SubjectAlternativeName";
    private static final String CE_ISSUER_ALT_NAME = "IssuerAlternativeName";
    private static final String PE_AUTHORITY_INFO_ACCESS = "AuthorityInfoAccess";
    private static final String PE_SUBJECT_INFO_ACCESS = "SubjectInfoAccess";
    private static final String CA = "ca";
    private static final String PATH_LEN = "pathlen";
    private static final String KP_SERVER_AUTH = "serverAuth";
    private static final String KP_CLIENT_AUTH = "clientAuth";
    private static final String KP_CODE_SIGNING = "codeSigning";
    private static final String KP_EMAIL_PROTECTION = "emailProtection";
    private static final String KP_TIME_STAMPING = "timeStamping";
    private static final String KP_OCSP_SIGNING = "OCSPSigning";
    private static final String AD_OCSP = "ocsp";
    private static final String AD_CA_ISSUERS = "caIssuers";
    private static final String AD_TIME_STAMPING = "timeStamping";
    private static final String AD_CA_REPOSITORY = "caRepository";
    private static final String EMAIL = "EMAIL";
    private static final String URI = "URI";
    private static final String DNS = "DNS";
    private static final String IP = "IP";
    private static final String OID = "OID";
    private static final String[] ALT_NAMES_TYPES = new String[] { EMAIL, URI, DNS, IP, OID };
    private static final int[] DELIMS = new int[] {',', ' '};

    /**
     * Create an {@code X509CertificateExtension} using the given extension name and string value.
     *
     * @param critical whether the extension should be marked as critical
     * @param extensionName the extension name
     * @param extensionValue the extension value, as a string
     * @return the newly created {@code X509CertificateExtension}
     * @throws IllegalArgumentException if the given extension name or value is invalid or if creating an {@code X509CertificateExtension}
     * from a string value is not supported for the given extension name
     */
    public static X509CertificateExtension getX509CertificateExtension(final boolean critical, final String extensionName, final String extensionValue) throws IllegalArgumentException {
        final X509CertificateExtension extension;
        try {
            if (extensionName.equalsIgnoreCase(BASIC_CONSTRAINTS)) {
                // ca:{true|false}[,pathlen:<len>]
                final CodePointIterator cpi = CodePointIterator.ofString(extensionValue);
                final CodePointIterator di = cpi.delimitedBy(DELIMS);
                final boolean ca = Boolean.parseBoolean(getKeyValue(CA, di.drainToString()));
                skipDelims(di, cpi, DELIMS);
                int pathLen = -1;
                if (di.hasNext()) {
                    pathLen = Integer.parseInt(getKeyValue(PATH_LEN, di.drainToString()));
                }
                extension = new BasicConstraintsExtension(critical, ca, pathLen);
            } else if (extensionName.equalsIgnoreCase(KEY_USAGE)) {
                // usage(,usage)*
                final CodePointIterator cpi = CodePointIterator.ofString(extensionValue);
                final CodePointIterator di = cpi.delimitedBy(DELIMS);
                if (! di.hasNext()) {
                    throw log.invalidCertificateExtensionStringValue(extensionValue);
                }
                final List<KeyUsage> keyUsages = new ArrayList<>();
                while (di.hasNext()) {
                    final KeyUsage keyUsage = KeyUsage.forName(di.drainToString());
                    if (keyUsage == null) {
                        throw log.invalidCertificateExtensionStringValue(extensionValue);
                    }
                    keyUsages.add(keyUsage);
                    skipDelims(di, cpi, DELIMS);
                }
                extension = new KeyUsageExtension(critical, keyUsages.toArray(new KeyUsage[keyUsages.size()]));
            } else if (extensionName.equalsIgnoreCase(CE_EXT_KEY_USAGE)) {
                // usage(,usage)*
                final CodePointIterator cpi = CodePointIterator.ofString(extensionValue);
                final CodePointIterator di = cpi.delimitedBy(DELIMS);
                if (! di.hasNext()) {
                    throw log.invalidCertificateExtensionStringValue(extensionValue);
                }
                final List<String> keyPurposeIds = new ArrayList<>();
                while (di.hasNext()) {
                    final String keyPurposeId = oidFromKeyPurpose(di.drainToString());
                    keyPurposeIds.add(keyPurposeId);
                    skipDelims(di, cpi, DELIMS);
                }
                extension = new ExtendedKeyUsageExtension(critical, keyPurposeIds);
            } else if (extensionName.equalsIgnoreCase(CE_SUBJECT_ALT_NAME)) {
                extension = new SubjectAlternativeNamesExtension(critical, getGeneralNames(extensionValue));
            } else if (extensionName.equalsIgnoreCase(CE_ISSUER_ALT_NAME)) {
                extension = new IssuerAlternativeNamesExtension(critical, getGeneralNames(extensionValue));
            } else if (extensionName.equalsIgnoreCase(PE_AUTHORITY_INFO_ACCESS)) {
                if (critical) {
                    throw log.certificateExtensionMustBeNonCritical(extensionName);
                }
                extension = new AuthorityInformationAccessExtension(getAccessDescriptions(extensionValue));
            } else if (extensionName.equalsIgnoreCase(PE_SUBJECT_INFO_ACCESS)) {
                if (critical) {
                    throw log.certificateExtensionMustBeNonCritical(extensionName);
                }
                extension = new SubjectInformationAccessExtension(getAccessDescriptions(extensionValue));
            } else {
                throw log.certificateExtensionCreationFromStringNotSupported(extensionName);
            }
        } catch (Exception e) {
            throw log.certificateExtensionCreationFromStringFailed(e);
        }
        return extension;
    }

    private static void skipDelims(CodePointIterator di, CodePointIterator cpi, int...delims) throws IllegalArgumentException {
        while ((! di.hasNext()) && cpi.hasNext()) {
            if (! isDelim(cpi.next(), delims)) {
                throw log.invalidCertificateExtensionStringValue();
            }
        }
    }

    private static boolean isDelim(int c, int... delims) {
        for (int delim : delims) {
            if (delim == c) {
                return true;
            }
        }
        return false;
    }

    private static String getKeyValue(final String requiredKey, final String keyAndValue) throws IllegalArgumentException {
        // key:value
        final CodePointIterator cpi = CodePointIterator.ofString(keyAndValue);
        final CodePointIterator di = cpi.delimitedBy(':');
        if (! requiredKey.equalsIgnoreCase(di.drainToString())) {
           throw log.invalidCertificateExtensionStringValue(keyAndValue);
        }
        skipDelims(di, cpi, ':');
        return di.drainToString();
    }

    private static String oidFromKeyPurpose(final String keyPurpose) {
        switch (keyPurpose) {
            case KP_SERVER_AUTH: return X500.OID_KP_SERVER_AUTH;
            case KP_CLIENT_AUTH: return X500.OID_KP_CLIENT_AUTH;
            case KP_CODE_SIGNING: return X500.OID_KP_CODE_SIGNING;
            case KP_EMAIL_PROTECTION: return X500.OID_KP_EMAIL_PROTECTION;
            case KP_TIME_STAMPING: return X500.OID_KP_TIME_STAMPING;
            case KP_OCSP_SIGNING: return X500.OID_KP_OCSP_SIGNING;
            default: return keyPurpose; // must be an oid already
        }
    }

    private static List<GeneralName> getGeneralNames(final String extensionValue) throws IllegalArgumentException {
        // type:val(,type:val)*
        final CodePointIterator cpi = CodePointIterator.ofString(extensionValue);
        final CodePointIterator di = cpi.delimitedBy(DELIMS);
        if (! di.hasNext()) {
            throw log.invalidCertificateExtensionStringValue(extensionValue);
        }
        List<GeneralName> generalNames = new ArrayList<>();
        while (di.hasNext()) {
            generalNames.add(getGeneralName(di.drainToString()));
            skipDelims(di, cpi, DELIMS);
        }
        return generalNames;
    }

    private static GeneralName getGeneralName(final String typeAndValue) throws IllegalArgumentException {
        // type:val
        final CodePointIterator cpi = CodePointIterator.ofString(typeAndValue);
        final CodePointIterator di = cpi.delimitedBy(':');
        final String type = di.drainToString();
        for (String requiredType : ALT_NAMES_TYPES) {
            if (requiredType.equalsIgnoreCase(type)) {
                skipDelims(di, cpi, ':');
                final String value = cpi.drainToString();
                switch (type.toUpperCase(Locale.ENGLISH)) {
                    case EMAIL:
                        return new GeneralName.RFC822Name(value);
                    case URI:
                        return new GeneralName.URIName(value);
                    case DNS:
                        return new GeneralName.DNSName(value);
                    case IP:
                        return new GeneralName.IPAddress(value);
                    case OID:
                        return new GeneralName.RegisteredID(value);
                    default:
                        throw log.invalidCertificateExtensionStringValue(typeAndValue);
                }
            }
        }
        throw log.invalidCertificateExtensionStringValue(typeAndValue);
    }

    private static List<AccessDescription> getAccessDescriptions(final String extensionValue) throws IllegalArgumentException {
        // method:location-type:location-value(,method:location-type:location-value)*
        final CodePointIterator cpi = CodePointIterator.ofString(extensionValue);
        final CodePointIterator di = cpi.delimitedBy(DELIMS);
        if (! di.hasNext()) {
            throw log.invalidCertificateExtensionStringValue(extensionValue);
        }
        List<AccessDescription> accessDescriptions = new ArrayList<>();
        while (di.hasNext()) {
            accessDescriptions.add(getAccessDescription(di.drainToString()));
            skipDelims(di, cpi, DELIMS);
        }
        return accessDescriptions;
    }

    private static AccessDescription getAccessDescription(final String methodAndTypeAndValue) throws IllegalArgumentException {
        // method:location-type:location-value
        final CodePointIterator cpi = CodePointIterator.ofString(methodAndTypeAndValue);
        final CodePointIterator di = cpi.delimitedBy(':');
        if (! di.hasNext()) {
            throw log.invalidCertificateExtensionStringValue(methodAndTypeAndValue);
        }
        final String accessMethodId = oidFromMethod(di.drainToString());
        skipDelims(di, cpi, ':');
        final String typeAndValue = cpi.drainToString();
        final GeneralName accessLocation = getGeneralName(typeAndValue);
        return new AccessDescription(accessMethodId, accessLocation);
    }

    private static String oidFromMethod(final String method) {
        switch (method) {
            case AD_OCSP: return X500.OID_AD_OCSP;
            case AD_CA_ISSUERS: return X500.OID_AD_CA_ISSUERS;
            case AD_TIME_STAMPING: return X500.OID_AD_TIME_STAMPING;
            case AD_CA_REPOSITORY: return X500.OID_AD_CA_REPOSITORY;
            default: return method; // must be an oid already
        }
    }

}
