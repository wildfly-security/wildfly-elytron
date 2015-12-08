/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;

/**
 * An opaque predicate which can be used to match SSL/TLS cipher suites.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public abstract class CipherSuitePredicate {

    // constant predicates

    private static final CipherSuitePredicate DEFAULTS_PREDICATE = matchAny(
        matchEncryption(Encryption.RC2, Encryption.RC4, Encryption.NULL),
        matchAuthentication(Authentication.NULL)
    );
    private static final CipherSuitePredicate ANON_DH_PREDICATE = matchAll(
        matchKeyExchange(KeyAgreement.DHd, KeyAgreement.DHr, KeyAgreement.DHE),
        matchAuthentication(Authentication.NULL)
    );
    private static final CipherSuitePredicate OPENSSL_COMPLEMENT_OF_ALL = matchEncryption(Encryption.NULL);
    private static final CipherSuitePredicate OPENSSL_DEFAULT_DELETES = matchAny(
        matchAuthentication(Authentication.NULL),
        matchEncryption(Encryption.NULL)
    );
    private static final CipherSuitePredicate OPENSSL_COMPLEMENT_OF_DEFAULT = matchAll(
        matchAuthentication(Authentication.NULL),
        matchNot(matchEncryption(Encryption.NULL))
    );
    private static final CipherSuitePredicate OPENSSL_ALL = matchNot(OPENSSL_COMPLEMENT_OF_ALL);

    static CipherSuitePredicate optimize(CipherSuitePredicate predicate) {
        return predicate.isAlwaysFalse() ? matchFalse() : predicate.isAlwaysTrue() ? matchTrue() : predicate;
    }

    // general logical

    /**
     * Match all possible cipher suites.
     *
     * @return the {@code true} predicate
     */
    public static CipherSuitePredicate matchTrue() {
        return BooleanCipherSuitePredicate.TRUE;
    }

    /**
     * Match no possible cipher suites.
     *
     * @return the {@code false} predicate
     */
    public static CipherSuitePredicate matchFalse() {
        return BooleanCipherSuitePredicate.FALSE;
    }

    /**
     * Match all of the given predicates.
     *
     * @param predicates the predicates
     * @return a predicate that is {@code true} when all nested predicates are {@code true}
     */
    public static CipherSuitePredicate matchAll(CipherSuitePredicate... predicates) {
        return optimize(new AndCipherSuitePredicate(predicates));
    }

    /**
     * Match any of the given predicates.
     *
     * @param predicates the predicates
     * @return a predicate that is {@code true} when any nested predicate is {@code true}
     */
    public static CipherSuitePredicate matchAny(CipherSuitePredicate... predicates) {
        return optimize(new OrCipherSuitePredicate(predicates));
    }

    /**
     * Invert the given predicate.
     *
     * @param predicate the predicate
     * @return a predicate which is {@code true} when the nested predicate is {@code false}, and vice-versa
     */
    public static CipherSuitePredicate matchNot(CipherSuitePredicate predicate) {
        return optimize(new NotCipherSuitePredicate(predicate));
    }

    static <T> T[] withoutNulls(T[] orig) {
        if (orig == null) return null;
        for (T item : orig) {
            if (item == null) {
                ArrayList<T> list = null;
                for (T item2 : orig) {
                    if (item2 != null) {
                        if (list == null) {
                            list = new ArrayList<T>(orig.length - 1);
                        }
                        list.add(item2);
                    }
                }
                return list == null ? null : list.toArray(Arrays.copyOf(orig, list.size()));
            }
        }
        // no nulls
        return orig;
    }

    // specific criteria

    /**
     * Return a predicate which matches the given encryption scheme.
     *
     * @param encryption the encryption scheme
     * @return the predicate
     */
    public static CipherSuitePredicate matchEncryption(Encryption encryption) {
        return encryption == null ? matchFalse() : new EncryptionCipherSuitePredicate(EnumSet.of(encryption));
    }

    /**
     * Return a predicate which matches any of the given encryption schemes.
     *
     * @param encryptions the encryption schemes
     * @return the predicate
     */
    public static CipherSuitePredicate matchEncryption(Encryption... encryptions) {
        encryptions = withoutNulls(encryptions);
        return encryptions == null || encryptions.length == 0 ? matchFalse() : encryptions.length == Encryption.fullSize ? matchTrue() : new EncryptionCipherSuitePredicate(EnumSet.of(encryptions[0], encryptions));
    }

    /**
     * Return a predicate which matches any of the given encryption schemes.
     *
     * @param encryptions the encryption schemes
     * @return the predicate
     */
    public static CipherSuitePredicate matchEncryption(EnumSet<Encryption> encryptions) {
        return encryptions == null || encryptions.isEmpty() ? matchFalse() : Encryption.isFull(encryptions) ? matchTrue() : new EncryptionCipherSuitePredicate(encryptions);
    }

    /**
     * Return a predicate which matches the given authentication scheme.
     *
     * @param authentication the authentication scheme
     * @return the predicate
     */
    public static CipherSuitePredicate matchAuthentication(Authentication authentication) {
        return authentication == null ? matchFalse() : new AuthenticationCipherSuitePredicate(true, EnumSet.of(authentication));
    }

    /**
     * Return a predicate which matches any of the given authentication schemes.
     *
     * @param authentications the authentication schemes
     * @return the predicate
     */
    public static CipherSuitePredicate matchAuthentication(Authentication... authentications) {
        authentications = withoutNulls(authentications);
        return authentications == null || authentications.length == 0 ? matchFalse() : authentications.length == Authentication.fullSize ? matchTrue() : new AuthenticationCipherSuitePredicate(true, EnumSet.of(authentications[0], authentications));
    }

    /**
     * Return a predicate which matches any of the given authentication schemes.
     *
     * @param authentications the authentication schemes
     * @return the predicate
     */
    public static CipherSuitePredicate matchAuthentication(EnumSet<Authentication> authentications) {
        return authentications == null || authentications.isEmpty() ? matchFalse() : Authentication.isFull(authentications) ? matchTrue() : optimize(new AuthenticationCipherSuitePredicate(true, authentications));
    }

    /**
     * Return a predicate which matches the given key exchange scheme.
     *
     * @param keyAgreement the key exchange scheme
     * @return the predicate
     */
    public static CipherSuitePredicate matchKeyAgreement(KeyAgreement keyAgreement) {
        return keyAgreement == null ? matchFalse() : new KeyAgreementCipherSuitePredicate(EnumSet.of(keyAgreement));
    }

    /**
     * Return a predicate which matches any of the given key exchange schemes.
     *
     * @param keyAgreements the key exchange schemes
     * @return the predicate
     */
    public static CipherSuitePredicate matchKeyExchange(KeyAgreement... keyAgreements) {
        keyAgreements = withoutNulls(keyAgreements);
        return keyAgreements == null || keyAgreements.length == 0 ? matchFalse() : keyAgreements.length == KeyAgreement.fullSize ? matchTrue() : new KeyAgreementCipherSuitePredicate(EnumSet.of(keyAgreements[0], keyAgreements));
    }

    /**
     * Return a predicate which matches any of the given key exchange schemes.
     *
     * @param keyAgreements the key exchange schemes
     * @return the predicate
     */
    public static CipherSuitePredicate matchKeyExchange(EnumSet<KeyAgreement> keyAgreements) {
        return keyAgreements == null || keyAgreements.isEmpty() ? matchFalse() : KeyAgreement.isFull(keyAgreements) ? matchTrue() : new KeyAgreementCipherSuitePredicate(keyAgreements);
    }

    /**
     * Return a predicate which matches the given digest scheme.
     *
     * @param digest the digest scheme
     * @return the predicate
     */
    public static CipherSuitePredicate matchDigest(Digest digest) {
        return digest == null ? matchFalse() : new DigestCipherSuitePredicate(EnumSet.of(digest));
    }

    /**
     * Return a predicate which matches any of the given digest schemes.
     *
     * @param digests the digest schemes
     * @return the predicate
     */
    public static CipherSuitePredicate matchDigest(Digest... digests) {
        digests = withoutNulls(digests);
        return digests == null || digests.length == 0 ? matchFalse() : digests.length == Digest.fullSize ? matchTrue() : new DigestCipherSuitePredicate(EnumSet.of(digests[0], digests));
    }

    /**
     * Return a predicate which matches any of the given digest schemes.
     *
     * @param digests the digest schemes
     * @return the predicate
     */
    public static CipherSuitePredicate matchDigest(EnumSet<Digest> digests) {
        return digests == null || digests.isEmpty() ? matchFalse() : Digest.isFull(digests) ? matchTrue() : new DigestCipherSuitePredicate(digests);
    }

    /**
     * Return a predicate which matches the given protocol.
     *
     * @param protocol the protocol
     * @return the predicate
     */
    public static CipherSuitePredicate matchProtocol(Protocol protocol) {
        return protocol == null ? matchFalse() : new ProtocolCipherSuitePredicate(EnumSet.of(protocol));
    }

    /**
     * Return a predicate which matches any of the given protocols.
     *
     * @param protocols the protocols
     * @return the predicate
     */
    public static CipherSuitePredicate matchProtocol(Protocol... protocols) {
        protocols = withoutNulls(protocols);
        return protocols == null || protocols.length == 0 ? matchFalse() : protocols.length == Protocol.fullSize ? matchTrue() : new ProtocolCipherSuitePredicate(EnumSet.of(protocols[0], protocols));
    }

    /**
     * Return a predicate which matches any of the given protocols.
     *
     * @param protocols the protocols
     * @return the predicate
     */
    public static CipherSuitePredicate matchProtocol(EnumSet<Protocol> protocols) {
        return protocols == null || protocols.isEmpty() ? matchFalse() : Protocol.isFull(protocols) ? matchTrue() : new ProtocolCipherSuitePredicate(protocols);
    }

    /**
     * Return a predicate which matches the given security level.
     *
     * @param level the security level
     * @return the predicate
     */
    public static CipherSuitePredicate matchLevel(SecurityLevel level) {
        return level == null ? matchFalse() : new LevelCipherSuitePredicate(EnumSet.of(level));
    }

    /**
     * Return a predicate which matches any of the given security levels.
     *
     * @param levels the security levels
     * @return the predicate
     */
    public static CipherSuitePredicate matchLevel(SecurityLevel... levels) {
        levels = withoutNulls(levels);
        return levels == null || levels.length == 0 ? matchFalse() : levels.length == SecurityLevel.fullSize ? matchTrue() : new LevelCipherSuitePredicate(EnumSet.of(levels[0], levels));
    }

    /**
     * Return a predicate which matches any of the given security levels.
     *
     * @param levels the security levels
     * @return the predicate
     */
    public static CipherSuitePredicate matchLevel(EnumSet<SecurityLevel> levels) {
        return levels == null || levels.isEmpty() ? matchFalse() : SecurityLevel.isFull(levels) ? matchTrue() : new LevelCipherSuitePredicate(levels);
    }

    /**
     * Return a predicate which matches all security levels less than the given level.
     *
     * @param level the security level to compare against
     * @return the predicate
     */
    public static CipherSuitePredicate matchLevelLessThan(final SecurityLevel level) {
        return level == null || level == SecurityLevel.NONE ? matchFalse() : new CipherSuitePredicate() {
            void toString(final StringBuilder b) {
                b.append("security level is less than ").append(level);
            }

            boolean test(final MechanismDatabase.Entry entry) {
                return entry.getLevel().compareTo(level) < 0;
            }
        };
    }

    /**
     * Return a predicate which matches all FIPS cipher suites.
     *
     * @return the predicate
     */
    public static CipherSuitePredicate matchFips() {
        return FipsCipherSuitePredicate.TRUE;
    }

    /**
     * Return a predicate which matches all non-FIPS cipher suites.
     *
     * @return the predicate
     */
    public static CipherSuitePredicate matchNonFips() {
        return FipsCipherSuitePredicate.FALSE;
    }

    /**
     * Return a predicate which matches all exportable cipher suites.
     *
     * @return the predicate
     */
    public static CipherSuitePredicate matchExport() {
        return ExportCipherSuitePredicate.TRUE;
    }

    /**
     * Return a predicate which matches all non-exportable cipher suites.
     *
     * @return the predicate
     */
    public static CipherSuitePredicate matchNonExport() {
        return ExportCipherSuitePredicate.FALSE;
    }

    /**
     * Return a predicate which matches a cipher suite with the given name.  The cipher suite name must be a
     * standard or OpenSSL-style mechanism name identifying a single mechanism.
     *
     * @return the predicate
     */
    public static CipherSuitePredicate matchName(final String name) {
        return name == null ? matchFalse() : new CipherSuitePredicate() {
            void toString(final StringBuilder b) {
                b.append("cipher name is \"").append(name).append("\"");
            }

            boolean test(final MechanismDatabase.Entry entry) {
                return entry.getOpenSslName().equals(name) || entry.getAliases().contains(name) || entry.getName().equals(name);
            }
        };
    }

    /* -- Our defaults -- */

    /**
     * Return a predicate which matches all cipher suites that would be fully deleted in the default selector
     * configuration.
     *
     * @return the predicate
     */
    public static CipherSuitePredicate matchDefaultDeletes() {
        return DEFAULTS_PREDICATE;
    }

    /* -- OpenSSL specials -- */

    /**
     * Match all anonymous ciphers which use Diffie-Hellman key exchange.
     *
     * @return the predicate
     */
    public static CipherSuitePredicate matchAnonDH() {
        return ANON_DH_PREDICATE;
    }

    /**
     * Match all cipher suites except for anonymous and encryptionless suites, which must be explicitly enabled.
     *
     * @return the predicate
     */
    public static CipherSuitePredicate matchOpenSslAll() {
        return OPENSSL_ALL;
    }

    /**
     * Match all cipher suites included by {@link #matchOpenSslAll()} but are disabled by default (generally,
     * anonymous Diffie-Hellman suites including elliptic curve suites).
     *
     * @return the predicate
     */
    public static CipherSuitePredicate matchOpenSslComplementOfAll() {
        return OPENSSL_COMPLEMENT_OF_ALL;
    }

    /**
     * Match all of the cipher suites which are automatically deleted by OpenSSL when using the special {@code DEFAULT}
     * rule.
     *
     * @return the predicate
     */
    public static CipherSuitePredicate matchOpenSslDefaultDeletes() {
        return OPENSSL_DEFAULT_DELETES;
    }

    /**
     * Match all of the cipher suites which are added by OpenSSL when using the special {@code COMPLEMENTOFDEFAULT}
     * rule.
     *
     * @return the predicate
     */
    public static CipherSuitePredicate matchOpenSslComplementOfDefault() {
        return OPENSSL_COMPLEMENT_OF_DEFAULT;
    }

    abstract void toString(StringBuilder b);

    /**
     * Get the string representation of this predicate.
     *
     * @return the string representation of this predicate
     */
    public final String toString() {
        StringBuilder b = new StringBuilder();
        toString(b);
        return b.toString();
    }

    abstract boolean test(MechanismDatabase.Entry entry);

    boolean isAlwaysTrue() {
        return false;
    }
    boolean isAlwaysFalse() {
        return false;
    }
}
