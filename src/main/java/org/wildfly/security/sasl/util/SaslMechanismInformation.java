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

package org.wildfly.security.sasl.util;

import static java.util.Arrays.asList;
import static java.util.Collections.emptySet;
import static java.util.Collections.singleton;
import static java.util.Collections.unmodifiableSet;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.function.Predicate;

import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.X509CertificateChainPublicCredential;
import org.wildfly.security.evidence.AlgorithmEvidence;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.evidence.PasswordGuessEvidence;
import org.wildfly.security.password.OneWayPassword;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.TwoWayPassword;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.interfaces.DigestPassword;
import org.wildfly.security.password.interfaces.OneTimePassword;
import org.wildfly.security.password.interfaces.ScramDigestPassword;
import org.wildfly.security.credential.X509CertificateChainPrivateCredential;
import org.wildfly.security.sasl.gs2.Gs2;
import org.wildfly.security.sasl.localuser.LocalUserSaslFactory;

/**
 * A collection of predicates and other information which can be used to filter SASL mechanisms.
 *
 * @see FilterMechanismSaslClientFactory
 * @see FilterMechanismSaslServerFactory
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class SaslMechanismInformation {

    public static final class Names {
        public static final String CRAM_MD5 = "CRAM-MD5";
        public static final String DIGEST_MD5 = "DIGEST-MD5";
        public static final String DIGEST_SHA = "DIGEST-SHA";
        public static final String DIGEST_SHA_256 = "DIGEST-SHA-256";
        public static final String DIGEST_SHA_384 = "DIGEST-SHA-384";
        public static final String DIGEST_SHA_512 = "DIGEST-SHA-512";
        public static final String SCRAM_SHA_1 = "SCRAM-SHA-1";
        public static final String SCRAM_SHA_1_PLUS = "SCRAM-SHA-1-PLUS";
        public static final String SCRAM_SHA_256 = "SCRAM-SHA-256";
        public static final String SCRAM_SHA_256_PLUS = "SCRAM-SHA-256-PLUS";
        public static final String SCRAM_SHA_384 = "SCRAM-SHA-384";
        public static final String SCRAM_SHA_384_PLUS = "SCRAM-SHA-384-PLUS";
        public static final String SCRAM_SHA_512 = "SCRAM-SHA-512";
        public static final String SCRAM_SHA_512_PLUS = "SCRAM-SHA-512-PLUS";
        public static final String IEC_ISO_9798_M_DSA_SHA1 = "9798-M-DSA-SHA1";
        public static final String IEC_ISO_9798_M_ECDSA_SHA1 = "9798-M-ECDSA-SHA1";
        public static final String IEC_ISO_9798_M_RSA_SHA1_ENC = "9798-M-RSA-SHA1-ENC";
        public static final String IEC_ISO_9798_U_DSA_SHA1 = "9798-U-DSA-SHA1";
        public static final String IEC_ISO_9798_U_ECDSA_SHA1 = "9798-U-ECDSA-SHA1";
        public static final String IEC_ISO_9798_U_RSA_SHA1_ENC = "9798-U-RSA-SHA1-ENC";
        public static final String ANONYMOUS = "ANONYMOUS";
        public static final String EAP_AES128 = "EAP-AES128";
        public static final String EAP_AES128_PLUS = "EAP-AES128-PLUS";
        public static final String EXTERNAL = "EXTERNAL";
        public static final String OAUTH_10_A = "OAUTH10A";
        public static final String OAUTHBEARER = "OAUTHBEARER";
        public static final String OPENID20 = "OPENID20";
        public static final String OTP = "OTP";
        public static final String SAML20 = "SAML20";
        public static final String SECURID = "SECURID";
        public static final String PLAIN = "PLAIN";
        public static final String GSSAPI = "GSSAPI";

        private Names() {}
    }

    private static final Set<String> MD5_MECHS = nSet(
        Names.CRAM_MD5,
        Names.DIGEST_MD5
    );

    private static final Set<String> SHA_MECHS = nSet(
        Names.DIGEST_SHA,
        Names.SCRAM_SHA_1,
        Names.SCRAM_SHA_1_PLUS
    );

    private static final Set<String> SHA_256_MECHS = nSet(
        Names.DIGEST_SHA_256,
        Names.SCRAM_SHA_256,
        Names.SCRAM_SHA_256_PLUS
    );

    private static final Set<String> SHA_384_MECHS = nSet(
        Names.DIGEST_SHA_384,
        Names.SCRAM_SHA_384,
        Names.SCRAM_SHA_384_PLUS
    );

    private static final Set<String> SHA_512_MECHS = nSet(
        Names.DIGEST_SHA_512,
        Names.SCRAM_SHA_512,
        Names.SCRAM_SHA_512_PLUS
    );

    private static final Set<String> MUTUAL_MECHS = nSet(
        Names.IEC_ISO_9798_M_DSA_SHA1,
        Names.IEC_ISO_9798_M_ECDSA_SHA1,
        Names.IEC_ISO_9798_M_RSA_SHA1_ENC
    );

    private static final Set<String> RECOMMENDED_MECHS = nSet(
        Names.IEC_ISO_9798_M_DSA_SHA1,
        Names.IEC_ISO_9798_M_ECDSA_SHA1,
        Names.IEC_ISO_9798_M_RSA_SHA1_ENC,
        Names.IEC_ISO_9798_U_DSA_SHA1,
        Names.IEC_ISO_9798_U_ECDSA_SHA1,
        Names.IEC_ISO_9798_U_RSA_SHA1_ENC,
        Names.ANONYMOUS,
        Names.EAP_AES128,
        Names.EAP_AES128_PLUS,
        Names.EXTERNAL,
        Names.OAUTH_10_A,
        Names.OAUTHBEARER,
        Names.OPENID20,
        Names.OTP,
        Names.SAML20,
        Names.SECURID
    );

    /**
     * A predicate which is true when the mechanism uses MD5.
     */
    public static final Predicate<String> HASH_MD5 = MD5_MECHS::contains;

    /**
     * A predicate which is true when the mechanism uses SHA.
     */
    public static final Predicate<String> HASH_SHA = SHA_MECHS::contains;

    /**
     * A predicate which is true when the mechanism uses SHA-256.
     */
    public static final Predicate<String> HASH_SHA_256 = SHA_256_MECHS::contains;

    /**
     * A predicate which is true when the mechanism uses SHA-384.
     */
    public static final Predicate<String> HASH_SHA_384 = SHA_384_MECHS::contains;

    /**
     * A predicate which is true when the mechanism uses SHA-512.
     */
    public static final Predicate<String> HASH_SHA_512 = SHA_512_MECHS::contains;

    /**
     * A predicate which is true when a GS2-family mechanism is being used.
     */
    public static final Predicate<String> GS2 = name -> name.startsWith("GS2-");

    /**
     * A predicate which is true when a SCRAM-family mechanism is being used.
     */
    public static final Predicate<String> SCRAM = name -> name.startsWith("SCRAM-");

    /**
     * A predicate which is true when a DIGEST-family mechanism is being used.
     */
    public static final Predicate<String> DIGEST = name -> name.startsWith("DIGEST-");

    /**
     * A predicate which is true when a IEC/ISO-9798-family mechanism is being used.
     */
    public static final Predicate<String> IEC_ISO_9798 = name -> name.startsWith("9798-");

    /**
     * A predicate which is true when an EAP-family mechanism is being used.
     */
    public static final Predicate<String> EAP = name -> name.startsWith("EAP-");

    /**
     * A predicate which is true when the mechanism supports mutual authentication.
     */
    public static final Predicate<String> MUTUAL = ((Predicate<String>) MUTUAL_MECHS::contains).or(SCRAM).or(GS2);

    /**
     * A predicate which is true when a mechanism which uses channel binding is being used.
     */
    public static final Predicate<String> BINDING = name -> name.endsWith("-PLUS");

    /**
     * A predicate which is true when the name being tested is a recommended mechanism as of the time of this release.
     */
    public static final Predicate<String> RECOMMENDED = ((Predicate<String>) RECOMMENDED_MECHS::contains).or(GS2).or(SCRAM).and(HASH_MD5.negate());

    // credential type sets

    static final Set<Class<? extends Password>> JUST_ONE_WAY = singleton(OneTimePassword.class);
    static final Set<Class<? extends Password>> JUST_TWO_WAY = singleton(TwoWayPassword.class);
    static final Set<Class<? extends Password>> ONE_WAY_AND_TWO_WAY = nSet(OneWayPassword.class, TwoWayPassword.class);
    static final Set<Class<? extends Password>> DIGEST_AND_TWO_WAY = nSet(DigestPassword.class, TwoWayPassword.class);
    static final Set<Class<? extends Password>> SCRAM_AND_TWO_WAY = nSet(ScramDigestPassword.class, TwoWayPassword.class);

    static final Set<Class<? extends Credential>> JUST_X509 = singleton(X509CertificateChainPrivateCredential.class);
    static final Set<Class<? extends Credential>> X_509_PUBLIC_OR_PRIVATE = nSet(X509CertificateChainPublicCredential.class, X509CertificateChainPrivateCredential.class);
    static final Set<Class<? extends Credential>> JUST_PASSWORD = singleton(PasswordCredential.class);

    static final Set<Class<? extends Evidence>> JUST_PASSWORD_EVIDENCE = singleton(PasswordGuessEvidence.class);

    // algorithm name sets

    static final Set<String> DIGEST_MD5_AND_PLAIN = nSet(DigestPassword.ALGORITHM_DIGEST_MD5, ClearPassword.ALGORITHM_CLEAR);
    static final Set<String> DIGEST_SHA_AND_PLAIN = nSet(DigestPassword.ALGORITHM_DIGEST_SHA, ClearPassword.ALGORITHM_CLEAR);
    static final Set<String> DIGEST_SHA_256_AND_PLAIN = nSet(DigestPassword.ALGORITHM_DIGEST_SHA_256, ClearPassword.ALGORITHM_CLEAR);
    static final Set<String> DIGEST_SHA_384_AND_PLAIN = nSet(DigestPassword.ALGORITHM_DIGEST_SHA_384, ClearPassword.ALGORITHM_CLEAR);
    static final Set<String> DIGEST_SHA_512_AND_PLAIN = nSet(DigestPassword.ALGORITHM_DIGEST_SHA_512, ClearPassword.ALGORITHM_CLEAR);
    static final Set<String> SCRAM_SHA_1_AND_PLAIN = nSet(ScramDigestPassword.ALGORITHM_SCRAM_SHA_1, ClearPassword.ALGORITHM_CLEAR);
    static final Set<String> SCRAM_SHA_256_AND_PLAIN = nSet(ScramDigestPassword.ALGORITHM_SCRAM_SHA_256, ClearPassword.ALGORITHM_CLEAR);
    static final Set<String> SCRAM_SHA_384_AND_PLAIN = nSet(ScramDigestPassword.ALGORITHM_SCRAM_SHA_384, ClearPassword.ALGORITHM_CLEAR);
    static final Set<String> SCRAM_SHA_512_AND_PLAIN = nSet(ScramDigestPassword.ALGORITHM_SCRAM_SHA_512, ClearPassword.ALGORITHM_CLEAR);
    static final Set<String> JUST_PLAIN = singleton(ClearPassword.ALGORITHM_CLEAR);
    static final Set<String> JUST_DSA = singleton("DSA");
    static final Set<String> JUST_EC = singleton("EC");
    static final Set<String> JUST_RSA = singleton("RSA");
    static final Set<String> ALL_ALGORITHMS = singleton("*");

    /**
     * Get the supported credential types for the given SASL client mechanism.  If an empty set is returned, then no
     * credentials are used by the mechanism or the mechanism is not known.
     *
     * @param mechName the mechanism name
     * @return the set of allowed client credentials
     */
    public static Set<Class<? extends Credential>> getSupportedClientCredentialTypes(String mechName) {
        switch (mechName) {
            case Names.EXTERNAL:
            case Names.ANONYMOUS: {
                return emptySet();
            }
            case Names.PLAIN:
            case Names.OTP:
            case Names.CRAM_MD5:
            case Names.DIGEST_MD5:
            case Names.DIGEST_SHA:
            case Names.DIGEST_SHA_256:
            case Names.DIGEST_SHA_384:
            case Names.DIGEST_SHA_512:
            case Names.SCRAM_SHA_1:
            case Names.SCRAM_SHA_1_PLUS:
            case Names.SCRAM_SHA_256:
            case Names.SCRAM_SHA_256_PLUS:
            case Names.SCRAM_SHA_384:
            case Names.SCRAM_SHA_384_PLUS:
            case Names.SCRAM_SHA_512:
            case Names.SCRAM_SHA_512_PLUS: {
                return JUST_PASSWORD;
            }
            case Names.IEC_ISO_9798_M_DSA_SHA1:
            case Names.IEC_ISO_9798_U_DSA_SHA1:
            case Names.IEC_ISO_9798_M_ECDSA_SHA1:
            case Names.IEC_ISO_9798_U_ECDSA_SHA1:
            case Names.IEC_ISO_9798_M_RSA_SHA1_ENC:
            case Names.IEC_ISO_9798_U_RSA_SHA1_ENC: {
                return X_509_PUBLIC_OR_PRIVATE;
            }
            default: {
                // unknown
                return emptySet();
            }
        }
    }

    /**
     * Get the supported password types for the given SASL client mechanism.  If an empty set is returned, then no
     * passwords are used by the mechanism or nothing is known about the mechanism.
     *
     * @param mechName the mechanism name
     * @return the set of allowed client password types
     */
    public static Set<Class<? extends Password>> getSupportedClientPasswordTypes(String mechName) {
        switch (mechName) {
            case Names.EXTERNAL:
            case Names.ANONYMOUS: {
                return emptySet();
            }
            case Names.PLAIN:
            case Names.OTP:
            case Names.CRAM_MD5: {
                return JUST_TWO_WAY;
            }
            case Names.DIGEST_MD5:
            case Names.DIGEST_SHA:
            case Names.DIGEST_SHA_256:
            case Names.DIGEST_SHA_384:
            case Names.DIGEST_SHA_512: {
                return DIGEST_AND_TWO_WAY;
            }
            case Names.SCRAM_SHA_1:
            case Names.SCRAM_SHA_1_PLUS:
            case Names.SCRAM_SHA_256:
            case Names.SCRAM_SHA_256_PLUS:
            case Names.SCRAM_SHA_384:
            case Names.SCRAM_SHA_384_PLUS:
            case Names.SCRAM_SHA_512:
            case Names.SCRAM_SHA_512_PLUS: {
                return SCRAM_AND_TWO_WAY;
            }
            case Names.IEC_ISO_9798_M_DSA_SHA1:
            case Names.IEC_ISO_9798_U_DSA_SHA1:
            case Names.IEC_ISO_9798_M_ECDSA_SHA1:
            case Names.IEC_ISO_9798_U_ECDSA_SHA1:
            case Names.IEC_ISO_9798_M_RSA_SHA1_ENC:
            case Names.IEC_ISO_9798_U_RSA_SHA1_ENC: {
                return emptySet();
            }
            default: {
                // unknown
                return emptySet();
            }
        }
    }

    /**
     * Get the supported credential types for the given SASL server mechanism.  If an empty set is returned, then no
     * credentials are used by the mechanism or the mechanism is unknown.
     *
     * @param mechName the mechanism name
     * @return the set of allowed server credential types
     */
    public static Set<Class<? extends Credential>> getSupportedServerCredentialTypes(String mechName) {
        switch (mechName) {
            case Names.EXTERNAL:
            case Names.ANONYMOUS: {
                return emptySet();
            }
            case Names.PLAIN:
            case Names.OTP:
            case Names.CRAM_MD5:
            case Names.DIGEST_MD5:
            case Names.DIGEST_SHA:
            case Names.DIGEST_SHA_256:
            case Names.DIGEST_SHA_384:
            case Names.DIGEST_SHA_512:
            case Names.SCRAM_SHA_1:
            case Names.SCRAM_SHA_1_PLUS:
            case Names.SCRAM_SHA_256:
            case Names.SCRAM_SHA_256_PLUS:
            case Names.SCRAM_SHA_384:
            case Names.SCRAM_SHA_384_PLUS:
            case Names.SCRAM_SHA_512:
            case Names.SCRAM_SHA_512_PLUS: {
                return JUST_PASSWORD;
            }
            case Names.IEC_ISO_9798_M_DSA_SHA1:
            case Names.IEC_ISO_9798_U_DSA_SHA1:
            case Names.IEC_ISO_9798_M_ECDSA_SHA1:
            case Names.IEC_ISO_9798_U_ECDSA_SHA1:
            case Names.IEC_ISO_9798_M_RSA_SHA1_ENC:
            case Names.IEC_ISO_9798_U_RSA_SHA1_ENC: {
                // TODO: look into verification process
                return JUST_X509;
            }
            default: {
                // unknown
                return emptySet();
            }
        }
    }

    /**
     * Get the supported password types for the given SASL server mechanism.  If an empty set is returned, then no
     * passwords are used by the mechanism or nothing is known about the mechanism
     *
     * @param mechName the mechanism name
     * @return the set of allowed server password types
     */
    public static Set<Class<? extends Password>> getSupportedServerPasswordTypes(String mechName) {
        switch (mechName) {
            case Names.EXTERNAL:
            case Names.ANONYMOUS: {
                return emptySet();
            }
            case Names.PLAIN: {
                return ONE_WAY_AND_TWO_WAY;
            }
            case Names.OTP: {
                return JUST_ONE_WAY;
            }
            case Names.CRAM_MD5: {
                return JUST_TWO_WAY;
            }
            case Names.DIGEST_MD5:
            case Names.DIGEST_SHA:
            case Names.DIGEST_SHA_256:
            case Names.DIGEST_SHA_384:
            case Names.DIGEST_SHA_512: {
                return DIGEST_AND_TWO_WAY;
            }
            case Names.SCRAM_SHA_1:
            case Names.SCRAM_SHA_1_PLUS:
            case Names.SCRAM_SHA_256:
            case Names.SCRAM_SHA_256_PLUS:
            case Names.SCRAM_SHA_384:
            case Names.SCRAM_SHA_384_PLUS:
            case Names.SCRAM_SHA_512:
            case Names.SCRAM_SHA_512_PLUS: {
                return SCRAM_AND_TWO_WAY;
            }
            case Names.IEC_ISO_9798_M_DSA_SHA1:
            case Names.IEC_ISO_9798_U_DSA_SHA1:
            case Names.IEC_ISO_9798_M_ECDSA_SHA1:
            case Names.IEC_ISO_9798_U_ECDSA_SHA1:
            case Names.IEC_ISO_9798_M_RSA_SHA1_ENC:
            case Names.IEC_ISO_9798_U_RSA_SHA1_ENC: {
                return emptySet();
            }
            default: {
                // unknown
                return emptySet();
            }
        }
    }

    /**
     * Get the supported algorithm names for a SASL client mechanism and credential type.  If the mechanism or
     * credential type is not recognized, or if the given credential type does not use algorithms for the
     * given mechanism name, an empty set is returned.  If all algorithms are supported, a set containing the special
     * string {@code "*"} is returned.
     *
     * @param mechName the SASL mechanism name
     * @param credentialType the proposed credential type
     *
     * @return the set of algorithms, or an empty set if all algorithms have unknown support
     */
    public static Set<String> getSupportedClientCredentialAlgorithms(String mechName, Class<? extends Credential> credentialType) {
        switch (mechName) {
            case Names.CRAM_MD5:
            case Names.PLAIN: {
                return credentialType.isAssignableFrom(PasswordCredential.class) ? JUST_PLAIN : emptySet();
            }
            case Names.DIGEST_MD5: {
                return credentialType.isAssignableFrom(PasswordCredential.class) ? DIGEST_MD5_AND_PLAIN : emptySet();
            }
            case Names.DIGEST_SHA: {
                return credentialType.isAssignableFrom(PasswordCredential.class) ? DIGEST_SHA_AND_PLAIN : emptySet();
            }
            case Names.DIGEST_SHA_256: {
                return credentialType.isAssignableFrom(PasswordCredential.class) ? DIGEST_SHA_256_AND_PLAIN : emptySet();
            }
            case Names.DIGEST_SHA_384: {
                return credentialType.isAssignableFrom(PasswordCredential.class) ? DIGEST_SHA_384_AND_PLAIN : emptySet();
            }
            case Names.DIGEST_SHA_512: {
                return credentialType.isAssignableFrom(PasswordCredential.class) ? DIGEST_SHA_512_AND_PLAIN : emptySet();
            }
            case Names.SCRAM_SHA_1:
            case Names.SCRAM_SHA_1_PLUS: {
                return credentialType.isAssignableFrom(PasswordCredential.class) ? SCRAM_SHA_1_AND_PLAIN : emptySet();
            }
            case Names.SCRAM_SHA_256:
            case Names.SCRAM_SHA_256_PLUS: {
                return credentialType.isAssignableFrom(PasswordCredential.class) ? SCRAM_SHA_256_AND_PLAIN : emptySet();
            }
            case Names.SCRAM_SHA_384:
            case Names.SCRAM_SHA_384_PLUS: {
                return credentialType.isAssignableFrom(PasswordCredential.class) ? SCRAM_SHA_384_AND_PLAIN : emptySet();
            }
            case Names.SCRAM_SHA_512:
            case Names.SCRAM_SHA_512_PLUS: {
                return credentialType.isAssignableFrom(PasswordCredential.class) ? SCRAM_SHA_512_AND_PLAIN : emptySet();
            }
            case Names.IEC_ISO_9798_M_DSA_SHA1:
            case Names.IEC_ISO_9798_U_DSA_SHA1: {
                return credentialType.isAssignableFrom(X509CertificateChainPrivateCredential.class) ? JUST_DSA : emptySet();
            }
            case Names.IEC_ISO_9798_M_ECDSA_SHA1:
            case Names.IEC_ISO_9798_U_ECDSA_SHA1: {
                // todo: double-check
                return credentialType.isAssignableFrom(X509CertificateChainPrivateCredential.class) ? JUST_EC : emptySet();
            }
            case Names.IEC_ISO_9798_M_RSA_SHA1_ENC:
            case Names.IEC_ISO_9798_U_RSA_SHA1_ENC: {
                return credentialType.isAssignableFrom(X509CertificateChainPrivateCredential.class) ? JUST_RSA : emptySet();
            }
            default:
                return emptySet();
        }
    }

    /**
     * Get the supported algorithm names for a SASL server mechanism and credential type.  If the mechanism or
     * credential type is not recognized, or if the given credential type does not use algorithms for the
     * given mechanism name, an empty set is returned.  If all algorithms are supported, a set containing the special
     * string {@code "*"} is returned.
     *
     * @param mechName the SASL mechanism name
     * @param credentialType the proposed credential type
     *
     * @return the set of algorithms, or an empty set if all algorithms have equal or unknown support
     */
    public static Set<String> getSupportedServerCredentialAlgorithms(String mechName, Class<? extends Credential> credentialType) {
        switch (mechName) {
            case Names.PLAIN: {
                return ALL_ALGORITHMS;
            }
            case Names.DIGEST_MD5: {
                return credentialType.isAssignableFrom(PasswordCredential.class) ? DIGEST_MD5_AND_PLAIN : emptySet();
            }
            case Names.DIGEST_SHA: {
                return credentialType.isAssignableFrom(PasswordCredential.class) ? DIGEST_SHA_AND_PLAIN : emptySet();
            }
            case Names.DIGEST_SHA_256: {
                return credentialType.isAssignableFrom(PasswordCredential.class) ? DIGEST_SHA_256_AND_PLAIN : emptySet();
            }
            case Names.DIGEST_SHA_384: {
                return credentialType.isAssignableFrom(PasswordCredential.class) ? DIGEST_SHA_384_AND_PLAIN : emptySet();
            }
            case Names.DIGEST_SHA_512: {
                return credentialType.isAssignableFrom(PasswordCredential.class) ? DIGEST_SHA_512_AND_PLAIN : emptySet();
            }
            case Names.SCRAM_SHA_1:
            case Names.SCRAM_SHA_1_PLUS: {
                return credentialType.isAssignableFrom(PasswordCredential.class) ? SCRAM_SHA_1_AND_PLAIN : emptySet();
            }
            case Names.SCRAM_SHA_256:
            case Names.SCRAM_SHA_256_PLUS: {
                return credentialType.isAssignableFrom(PasswordCredential.class) ? SCRAM_SHA_256_AND_PLAIN : emptySet();
            }
            case Names.SCRAM_SHA_384:
            case Names.SCRAM_SHA_384_PLUS: {
                return credentialType.isAssignableFrom(PasswordCredential.class) ? SCRAM_SHA_384_AND_PLAIN : emptySet();
            }
            case Names.SCRAM_SHA_512:
            case Names.SCRAM_SHA_512_PLUS: {
                return credentialType.isAssignableFrom(PasswordCredential.class) ? SCRAM_SHA_512_AND_PLAIN : emptySet();
            }
            case Names.IEC_ISO_9798_M_DSA_SHA1:
            case Names.IEC_ISO_9798_U_DSA_SHA1:
            case Names.IEC_ISO_9798_M_ECDSA_SHA1:
            case Names.IEC_ISO_9798_U_ECDSA_SHA1:
            case Names.IEC_ISO_9798_M_RSA_SHA1_ENC:
            case Names.IEC_ISO_9798_U_RSA_SHA1_ENC: {
                // TODO: look into verification process
                return emptySet();
            }
            default:
                return emptySet();
        }
    }

    /**
     * Get the supported evidence types for the given SASL server mechanism.  If an empty set is returned, then no
     * evidence is used by the mechanism.
     *
     * @param mechName the mechanism name
     * @return the set of allowed server credential types
     */
    public static Set<Class<? extends Evidence>> getSupportedServerEvidenceTypes(final String mechName) {
        switch (mechName) {
            case Names.OTP:
            case Names.CRAM_MD5:
            case Names.PLAIN:
            case Names.DIGEST_MD5:
            case Names.DIGEST_SHA:
            case Names.DIGEST_SHA_256:
            case Names.DIGEST_SHA_384:
            case Names.DIGEST_SHA_512:
            case Names.SCRAM_SHA_1:
            case Names.SCRAM_SHA_1_PLUS:
            case Names.SCRAM_SHA_256:
            case Names.SCRAM_SHA_256_PLUS:
            case Names.SCRAM_SHA_384:
            case Names.SCRAM_SHA_384_PLUS:
            case Names.SCRAM_SHA_512:
            case Names.SCRAM_SHA_512_PLUS: {
                return JUST_PASSWORD_EVIDENCE;
            }
            case Names.IEC_ISO_9798_M_DSA_SHA1:
            case Names.IEC_ISO_9798_U_DSA_SHA1:
            case Names.IEC_ISO_9798_M_ECDSA_SHA1:
            case Names.IEC_ISO_9798_U_ECDSA_SHA1:
            case Names.IEC_ISO_9798_M_RSA_SHA1_ENC:
            case Names.IEC_ISO_9798_U_RSA_SHA1_ENC: {
                // TODO: look into verification process
                return emptySet();
            }
            default:
                return emptySet();
        }
    }

    /**
     * Get the supported algorithm names for a SASL server mechanism and evidence type.  If the mechanism or
     * evidence type is not recognized, or if the given evidence type does not have an algorithm restriction for the
     * given mechanism name, an empty set is returned.
     *
     * @param mechName the SASL mechanism name
     * @param evidenceType the proposed evidence type
     *
     * @return the set of algorithms, or an empty set if all algorithms have equal or unknown support
     */
    public static Set<String> getSupportedServerEvidenceAlgorithms(final String mechName, final Class<? extends AlgorithmEvidence> evidenceType) {
        switch (mechName) {
            case Names.IEC_ISO_9798_M_DSA_SHA1:
            case Names.IEC_ISO_9798_U_DSA_SHA1:
            case Names.IEC_ISO_9798_M_ECDSA_SHA1:
            case Names.IEC_ISO_9798_U_ECDSA_SHA1:
            case Names.IEC_ISO_9798_M_RSA_SHA1_ENC:
            case Names.IEC_ISO_9798_U_RSA_SHA1_ENC: {
                // TODO: look into verification process
                return emptySet();
            }
            default:
                return emptySet();
        }
    }

    /**
     * Determine whether a mechanism needs server-side credentials in order to authenticate.  This may include credential
     * verification or acquisition, or both.
     *
     * @param mechName the mechanism name
     * @return {@code true} if the mechanism uses credentials, {@code false} otherwise
     */
    public static boolean needsServerCredentials(final String mechName) {
        switch (mechName) {
            case Names.ANONYMOUS:
            case Names.EXTERNAL:
            case LocalUserSaslFactory.JBOSS_LOCAL_USER:
            case Names.GSSAPI:
            case Gs2.GS2_KRB5:
            case Gs2.GS2_KRB5_PLUS: {
                return false;
            }
            default: {
                return true;
            }
        }
    }

    @SafeVarargs
    private static <T> Set<T> nSet(T... values) {
        return unmodifiableSet(new LinkedHashSet<>(asList(values)));
    }
}
