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
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.wildfly.common.iteration.CodePointIterator;
import org.wildfly.security._private.ElytronMessages;

/**
 * An immutable filter for SSL/TLS cipher suites.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public abstract class CipherSuiteSelector {

    final CipherSuiteSelector prev;

    CipherSuiteSelector(final CipherSuiteSelector prev) {
        this.prev = prev;
    }

    /* -- predicates -- */

    private static final CipherSuiteSelector EMPTY = new CipherSuiteSelector(null) {
        void applyFilter(final Set<String> enabled, final Map<MechanismDatabase.Entry, String> supported) {
        }

        void toString(final StringBuilder b) {
            b.append("(empty)");
        }
    };

    /**
     * Get the basic empty SSL cipher suite selector.
     *
     * @return the empty selector
     */
    public static CipherSuiteSelector empty() {
        return EMPTY;
    }

    static final CipherSuiteSelector OPENSSL_ALL = empty().add(CipherSuitePredicate.matchOpenSslAll());
    static final CipherSuiteSelector OPENSSL_DEFAULT = openSslAll().deleteFully(CipherSuitePredicate.matchOpenSslDefaultDeletes());

    /**
     * Get the cipher selector which OpenSSL defines as {@code DEFAULT}.
     *
     * @return the selector
     * @see CipherSuitePredicate#matchOpenSslDefaultDeletes()
     */
    public static CipherSuiteSelector openSslDefault() {
        return OPENSSL_DEFAULT;
    }

    /**
     * Get the cipher selector which OpenSSL defines as {@code ALL}.
     *
     * @return the selector
     * @see CipherSuitePredicate#matchOpenSslAll()
     */
    public static CipherSuiteSelector openSslAll() {
        return OPENSSL_ALL;
    }

    /* -- delete -- */

    /**
     * Permanently delete all cipher suites which are matched by the given predicate.  Matching ciphers cannot
     * be re-added by a later rule (such rules will be ignored).
     *
     * @param predicate the predicate to match
     * @return a new selector which includes the new rule
     */
    public CipherSuiteSelector deleteFully(final CipherSuitePredicate predicate) {
        return predicate == null ? this : new FullyDeletingCipherSuiteSelector(this, predicate);
    }

    /**
     * A convenience method to permanently delete a cipher suite by name.  This is a shortcut for calling
     * {@code deleteFully(Predicate.matchName(cipherSuiteName))}.  The cipher suite name must be a standard or OpenSSL-style
     * mechanism name identifying a single mechanism.
     *
     * @param cipherSuiteName the cipher suite name
     * @return a new selector which includes the new rule
     */
    public CipherSuiteSelector deleteFully(final String cipherSuiteName) {
        return deleteFully(CipherSuitePredicate.matchName(cipherSuiteName));
    }

    /* -- remove -- */

    /**
     * Remove all cipher suites which are matched by the given predicate.  Matching ciphers may be re-added by a later
     * rule.
     *
     * @param predicate the predicate to match
     * @return a new selector which includes the new rule
     */
    public CipherSuiteSelector remove(final CipherSuitePredicate predicate) {
        return predicate == null || predicate.isAlwaysFalse() ? this : new RemovingCipherSuiteSelector(this, predicate);
    }

    /**
     * A convenience method to remove a cipher suite by name.  This is a shortcut for calling
     * {@code remove(Predicate.matchName(cipherSuiteName))}.  The cipher suite name must be a standard or OpenSSL-style
     * mechanism name identifying a single mechanism.
     *
     * @param cipherSuiteName the cipher suite name
     * @return a new selector which includes the new rule
     */
    public CipherSuiteSelector remove(final String cipherSuiteName) {
        return remove(CipherSuitePredicate.matchName(cipherSuiteName));
    }

    /* -- add -- */

    /**
     * Add all cipher suites which are matched by the given predicate.  The cipher suites are added in a reasonably
     * logical order.  Any suites which are not supported by the underlying socket layer will not be added.
     *
     * @param predicate the predicate to match
     * @return a new selector which includes the new rule
     */
    public CipherSuiteSelector add(final CipherSuitePredicate predicate) {
        return predicate == null || predicate.isAlwaysFalse() ? this : new AddingCipherSuiteSelector(this, predicate);
    }

    /**
     * A convenience method to add a cipher suite by name.  If the underlying socket layer does not support the named
     * cipher suite, or if the cipher suite is invalid, it will not be added.  This is a shortcut for calling
     * {@code add(Predicate.matchName(cipherSuiteName))}.  The cipher suite name must be a standard or OpenSSL-style
     * mechanism name identifying a single mechanism.
     *
     * @param cipherSuiteName the cipher suite name
     * @return a new selector which includes the new rule
     */
    public CipherSuiteSelector add(final String cipherSuiteName) {
        return add(CipherSuitePredicate.matchName(cipherSuiteName));
    }

    /* -- push to end -- */

    /**
     * Push all cipher suites which are matched by the given predicate to the end of the enabled ciphers list.  Only
     * cipher suites which are already enabled will be moved; no cipher suites are added by this transformation.
     *
     * @param predicate the predicate to match
     * @return a new selector which includes the new rule
     */
    public CipherSuiteSelector pushToEnd(final CipherSuitePredicate predicate) {
        return predicate == null || predicate.isAlwaysFalse() || predicate.isAlwaysTrue() ? this : new PushToEndCipherSuiteSelector(this, predicate);
    }

    /**
     * A convenience method to push a cipher suite by name to the end of the enabled ciphers list.  This is a shortcut
     * for calling {@code pushToEnd(Predicate.matchName(cipherSuiteName))}.  In particular, no cipher suites are added
     * by this transformation.  The cipher suite name must be a standard or OpenSSL-style mechanism name identifying a
     * single mechanism.
     *
     * @param cipherSuiteName the cipher suite name
     * @return a new selector which includes the new rule
     */
    public CipherSuiteSelector pushToEnd(final String cipherSuiteName) {
        return pushToEnd(CipherSuitePredicate.matchName(cipherSuiteName));
    }

    /**
     * Sort all of the enabled ciphers by decreasing key length.  Only the ciphers which were added by previous rules
     * will be sorted.
     *
     * @return a new selector which includes the sort
     */
    public CipherSuiteSelector sortByAlgorithmKeyLength() {
        return new SortByAlgorithmKeyLengthCipherSuiteSelector(this);
    }

    public final String toString() {
        StringBuilder b = new StringBuilder();
        toString(b);
        return b.toString();
    }

    abstract void toString(StringBuilder b);

    /* -- selector implementation -- */

    abstract void applyFilter(Set<String> enabled, Map<MechanismDatabase.Entry, String> supported);

    private void doEvaluate(Set<String> enabled, Map<MechanismDatabase.Entry, String> supported) {
        if (prev != null) {
            prev.doEvaluate(enabled, supported);
        }
        applyFilter(enabled, supported);
    }

    /**
     * Evaluate this selector against the given list of JSSE supported mechanisms.
     *
     * @param supportedMechanisms the supported mechanisms
     * @return the enabled mechanisms (not {@code null})
     */
    public final String[] evaluate(String[] supportedMechanisms) {
        if (ElytronMessages.tls.isTraceEnabled()) {
            StringBuilder b = new StringBuilder(supportedMechanisms.length * 16);
            b.append("Evaluating filter \"").append(this).append("\" on supported mechanisms:");
            for (String s : supportedMechanisms) {
                b.append("\n    ").append(s);
            }
            ElytronMessages.tls.trace(b);
        }
        final MechanismDatabase database = MechanismDatabase.getInstance();
        final LinkedHashMap<MechanismDatabase.Entry, String> supportedMap = new LinkedHashMap<>(supportedMechanisms.length);
        for (String supportedMechanism : supportedMechanisms) {
            final MechanismDatabase.Entry entry = database.getCipherSuite(supportedMechanism);
            if (entry != null) {
                ElytronMessages.tls.tracef("Found supported mechanism %s", supportedMechanism);
                supportedMap.put(entry, supportedMechanism);
            } else {
                ElytronMessages.tls.tracef("Dropping unknown mechanism %s", supportedMechanism);
            }
        }
        final LinkedHashSet<String> enabledSet = new LinkedHashSet<String>(supportedMap.size());
        doEvaluate(enabledSet, supportedMap);
        return enabledSet.toArray(new String[enabledSet.size()]);
    }

    /**
     * Create a cipher suite selector from the given OpenSSL-style cipher list string.  The rules of the string are as
     * follows:
     * <ul>
     *     <li>Each item is separated from the other items by a colon (":"), though for compatibility, commas (",") or
     *          spaces (" ") are allowed delimiters as well.</li>
     *     <li>The items are evaluated in order from left to right.</li>
     *     <li>
     *         Each item may consist of one of the following:
     *         <ul>
     *             <li>An OpenSSL-style cipher suite name like {@code DH-RSA-AES256-SHA256}, which adds the named cipher suite to the end of the list (if it is supported and not already present).</li>
     *             <li>A standard SSL/TLS cipher suite name like {@code TLS_DH_RSA_WITH_AES_256_CBC_SHA256}, which adds the named cipher suite to the end of the list (if it is supported and not already present).</li>
     *             <li>
     *                 Any of the following special keywords:
     *                 <ul>
     *                     <li>{@code HIGH}, which matches all supported cipher suites with "high" encryption, presently defined
     *                          as all cipher suites with key lengths larger than 128 bits, and some with key lengths
     *                          of exactly 128 bits (see {@link SecurityLevel#HIGH}).</li>
     *                     <li>{@code MEDIUM}, which matches all supported cipher suites with "medium" encryption, presently
     *                          defined as some cipher suites with 128 bit keys (see {@link SecurityLevel#MEDIUM}).</li>
     *                     <li>{@code LOW}, which matches all supported cipher suites with "low" encryption, presently defined
     *                          as cipher suites which use 64- or 56-bit encryption but excluding export cipher suites
     *                          (see {@link SecurityLevel#LOW}).</li>
     *                     <li>{@code EXP} or {@code EXPORT}, which matches supported cipher suites using export algorithms, presently defined as
     *                          cipher suites which include those that use 56- or 40-bit encryption algorithms (see
     *                          {@link SecurityLevel#EXP40} and {@link SecurityLevel#EXP56})</li>.
     *                     <li>{@code EXPORT40}, which matches supported cipher suites using export algorithms with 40-bit encryption (see {@link SecurityLevel#EXP40}).</li>
     *                     <li>{@code EXPORT56}, which matches supported cipher suites using export algorithms with 56-bit encryption (see {@link SecurityLevel#EXP56}).</li>
     *                     <li>{@code eNULL} or {@code NULL}, which matches supported cipher suites without encryption (see {@link Encryption#NULL}).</li>
     *                     <li>{@code aNULL}, which matches supported cipher suites without authentication (i.e. they are anonymous) (see {@link Authentication#NULL}).</li>
     *                     <li>{@code kRSA}, which matches supported cipher suites using RSA key exchange (see {@link KeyAgreement#RSA}).</li>
     *                     <li>{@code aRSA}, which matches supported cipher suites using RSA authentication (see {@link Authentication#RSA}).</li>
     *                     <li>{@code RSA}, which matches supported cipher suites using either RSA key exchange or RSA authentication.</li>
     *                     <li>{@code kDHr}, which matches supported cipher suites using DH key agreement with DH certificates signed with a RSA key (see {@link KeyAgreement#DHr}).</li>
     *                     <li>{@code kDHd}, which matches supported cipher suites using DH key agreement with DH certificates signed with a DSS key (see {@link KeyAgreement#DHd}).</li>
     *                     <li>{@code kDH}, which matches any supported cipher suite using DH key agreement.</li>
     *                     <li>{@code kDHE} or {@code kEDH}, which matches supported cipher suites using ephemeral DH key agreement (including anonymous cipher suites; see {@link KeyAgreement#DHE}).</li>
     *                     <li>{@code DHE} or {@code EDH}, which matches supported cipher suites using non-anonymous ephemeral DH key agreement.</li>
     *                     <li>{@code ADH}, which matches supported cipher suites using anonymous DH, not including anonymous elliptic curve suites.</li>
     *                     <li>{@code DH}, which matches any supported cipher suite using DH.</li>
     *                     <li>{@code kECDHr}, which matches supported cipher suites using fixed ECDH key agreement signed using RSA keys (see {@link KeyAgreement#ECDHr}).</li>
     *                     <li>{@code kECDHe}, which matches supported cipher suites using fixed ECDH key agreement signed by ECDSA keys (see {@link KeyAgreement#ECDHe}).</li>
     *                     <li>{@code kECDH}, which matches supported cipher suites using fixed ECDH key agreement.</li>
     *                     <li>{@code kEECDH} or {@code kECDHE}, which matches supported cipher suites using ephemeral ECDH key agreement (including anonymous cipher suites; see {@link KeyAgreement#ECDHE}).</li>
     *                     <li>{@code ECDHE} or {@code EECDHE}, which matches supported cipher suites using authenticated (non-anonymous) ephemeral ECDH key agreement.</li>
     *                     <li>{@code AECDH}, which matches supported cipher suites using anonymous ephemeral ECDH key agreement.</li>
     *                     <li>{@code ECDH}, which matches all supported cipher suites using ECDH key agreement.</li>
     *                     <li>{@code aDSS} or {@code DSS}, which matches supported cipher suites using DSS authentication (see {@link Authentication#DSS}).</li>
     *                     <li>{@code aDH}, which matches supported cipher suites using DH authentication (see {@link Authentication#DH}).</li>
     *                     <li>{@code aECDH}, which matches supported cipher suites using ECDH authentication (see {@link Authentication#ECDH}).</li>
     *                     <li>{@code aECDSA} or {@code ECDSA}, which matches supported cipher suites using ECDSA authentication (see {@link Authentication#ECDSA}).</li>
     *                     <li>{@code kFZA}, which matches supported cipher suites using Fortezza key agreement (see {@link KeyAgreement#FZA}).</li>
     *                     <li>{@code aFZA}, which matches supported cipher suites using Fortezza authentication (see {@link Authentication#FZA}).</li>
     *                     <li>{@code eFZA}, which matches supported cipher suites using Fortezza encryption (see {@link Encryption#FZA}).</li>
     *                     <li>{@code FZA}, which matches all supported cipher suites using any Fortezza algorithm.</li>
     *                     <li>{@code TLSv1.2}, which matches supported cipher suites defined in TLS v1.2 (see {@link Protocol#TLSv1_2}).</li>
     *                     <li>{@code TLSv1}, which matches supported cipher suites defined in TLS v1 (see {@link Protocol#TLSv1}).</li>
     *                     <li>{@code SSLv3}, which matches supported cipher suites defined in SSL v3.0 (see {@link Protocol#SSLv3}).</li>
     *                     <li>{@code SSLv2}, which matches supported cipher suites defined in SSL v2.0 (see {@link Protocol#SSLv2}).</li>
     *                     <li>{@code AES256}, which matches supported cipher suites using 256-bit AES (see {@link Encryption#AES256}).</li>
     *                     <li>{@code AES128}, which matches supported cipher suites using 128-bit AES (see {@link Encryption#AES128}).</li>
     *                     <li>{@code AES}, which matches all supported cipher suites using AES.</li>
     *                     <li>{@code AESGCM}, which matches supported cipher suites using AES in Galois Counter Mode (GCM) (see {@link Encryption#AES256GCM} and {@link Encryption#AES128GCM}).</li>
     *                     <li>{@code CAMELLIA256}, which matches supported cipher suites using 256-bit Camellia encryption (see {@link Encryption#CAMELLIA256}).</li>
     *                     <li>{@code CAMELLIA128}, which matches supported cipher suites using 128-bit Camellia encryption (see {@link Encryption#CAMELLIA128}).</li>
     *                     <li>{@code CAMELLIA}, which matches all supported cipher suites using any Camellia encryption.</li>
     *                     <li>{@code 3DES}, which matches supported cipher suites using triple DES encryption (see {@link Encryption#_3DES}).</li>
     *                     <li>{@code DES}, which matches supported cipher suites using plain DES encryption (see {@link Encryption#DES}).</li>
     *                     <li>{@code RC4}, which matches supported cipher suites using RC4 encryption (see {@link Encryption#RC4}).</li>
     *                     <li>{@code RC2}, which matches supported cipher suites using RC2 encryption (see {@link Encryption#RC2}).</li>
     *                     <li>{@code IDEA}, which matches supported cipher suites using IDEA encryption (see {@link Encryption#IDEA}).</li>
     *                     <li>{@code SEED}, which matches supported cipher suites using SEED encryption (see {@link Encryption#SEED}).</li>
     *                     <li>{@code MD5}, which matches supported cipher suites using the MD5 digest algorithm (see {@link Digest#MD5}).</li>
     *                     <li>{@code SHA1} or {@code SHA}, which matches supported cipher suites using the SHA-1 digest algorithm (see {@link Digest#SHA1}).</li>
     *                     <li>{@code SHA256}, which matches supported cipher suites using the SHA-256 digest algorithm (see {@link Digest#SHA256}).</li>
     *                     <li>{@code SHA384}, which matches supported cipher suites using the SHA-384 digest algorithm (see {@link Digest#SHA384}).</li>
     *                     <li>{@code aGOST}, which matches supported cipher suites using GOST authentication.</li>
     *                     <li>{@code aGOST01}, which matches supported cipher suites using GOST R 34.10-2001 authentication (see {@link Authentication#GOST01}).</li>
     *                     <li>{@code aGOST94}, which matches supported cipher suites using GOST R 34.10-94 authentication (see {@link Authentication#GOST94}).</li>
     *                     <li>{@code kGOST}, which matches supported cipher suites using VKO 34.10 key exchange (see {@link KeyAgreement#GOST}).</li>
     *                     <li>{@code GOST94}, which matches supported cipher suites using GOST R 34.11-94 based HMAC (see {@link Digest#GOST94}).</li>
     *                     <li>{@code GOST89MAC}, which matches supported cipher suites using GOST 28147-89 based MAC (not HMAC) (see {@link Digest#GOST89MAC}).</li>
     *                     <li>{@code kPSK}, which matches supported cipher suites using pre-shared keys key agreement (see {@link KeyAgreement#PSK}).</li>
     *                     <li>{@code aPSK}, which matches supported cipher suites using pre-shared keys authentication (see {@link Authentication#PSK}).</li>
     *                     <li>{@code PSK}, which matches supported cipher suites using pre-shared keys (see {@link Authentication#PSK} and {@link KeyAgreement#PSK}).</li>
     *                     <li>{@code RSAPSK} or {@code kRSAPSK}, which matches supported cipher suites using RSA-based pre-shared keys (see {@link KeyAgreement#RSAPSK}).</li>
     *                     <li>{@code kEDHPSK}, {@code kDHEPSK}, {@code EDHPSK} or {@code DHEPSK}, which matches supported cipher suites using ephemeral DH-based pre-shared keys (see {@link KeyAgreement#DHEPSK}).</li>
     *                     <li>{@code kEECDHPSK}, {@code EECDHPSK}, {@code kECDHEPSK} or {@code ECDHEPSK}, which matches supported cipher suites using ephemeral elliptic-curve DH-based pre-shared keys (see {@link KeyAgreement#ECDHEPSK}).</li>
     *                 </ul>
     *             </li>
     *             <li>More than one of any of the above keywords or cipher suite names joined by {@code +} symbols, which
     *                  indicates that all of the items must be matched (i.e. a logical "and" operation).</li>
     *             <li>The special unary {@code !} operator followed by any of the above keywords or cipher
     *                  names, which removes the matching cipher suite(s) from the enabled list and also deletes it from the
     *                  supported list, preventing any matching cipher suites from being re-added by a later rule.</li>
     *             <li>The special unary {@code -} operator followed by any of the above keywords or cipher
     *                  names, which removes the matching cipher suite(s) from the enabled list (though they may still
     *                  be re-added).</li>
     *             <li>The special unary {@code +} operator followed by any of the above keywords or cipher
     *                  names, which causes any of the matching cipher suite(s) to be moved to the end of the list
     *                  of enabled cipher suites.</li>
     *             <li>The special {@code ALL} keyword, which includes all cipher suites (except for encryptionless
     *                  suites; in other words, this keyword implies {@code -eNULL}).</li>
     *             <li>The special {@code COMPLEMENTOFALL} keyword, which is presently equivalent to {@code eNULL}.</li>
     *             <li>The special {@code DEFAULT} keyword, which is equivalent to {@code ALL:!EXPORT:!LOW:!aNULL:!eNULL:!SSLv2}.</li>
     *             <li>The special {@code COMPLEMENTOFDEFAULT} keyword, which presently includes any anonymous cipher
     *                  suites (but excludes those without encryption, which must always be enabled manually).</li>
     *             <li>The special {@code @STRENGTH} keyword, which causes all the mechanisms enabled thus far to be
     *                  automatically sorted by encryption algorithm key length.</li>
     *         </ul>
     *     </li>
     * </ul>
     *
     * @param string the string to parse
     * @return the parsed cipher suite selector
     * @throws IllegalArgumentException if the given string is not valid
     */
    public static CipherSuiteSelector fromString(String string) throws IllegalArgumentException {
        final CodePointIterator i = CodePointIterator.ofString(string);
        CipherSuiteSelector current = empty();
        CipherSuitePredicate predicate;
        String name;
        int cp;
        while (i.hasNext()) {
            cp = i.next();
            switch (cp) {
                case '+': {
                    current = parseMoveToEnd(current, i);
                    break;
                }
                case '-': {
                    current = parseRemove(current, i);
                    break;
                }
                case '!': {
                    current = parseDelete(current, i);
                    break;
                }
                case '@': {
                    current = parseSpecial(current, i);
                    break;
                }
                case '=': {
                    throw ElytronMessages.log.mechSelectorTokenNotAllowed("=", i.getIndex(), string);
                }
                case ',':
                case ':': {
                    // skip empty
                    break;
                }
                default: {
                    if (Character.isWhitespace(cp)) {
                        // skip whitespace
                        break;
                    }
                    if (Character.isLetterOrDigit(cp)) {
                        i.previous();
                        name = i.delimitedBy('+', ':', ',', ' ').drainToString();
                        predicate = parsePredicate(i, name);
                        if (predicate != null) {
                            current = current.add(predicate);
                        } else {
                            switch (name) {
                                /* -- openssl special -- */
                                case "DEFAULT":             current = current.add(CipherSuitePredicate.matchOpenSslAll())
                                                                             .deleteFully(CipherSuitePredicate.matchOpenSslDefaultDeletes()); break;
                                case "COMPLEMENTOFDEFAULT": current = current.add(CipherSuitePredicate.matchAnonDH()); break;
                                case "ALL":                 current = current.add(CipherSuitePredicate.matchOpenSslAll()); break;
                                case "COMPLEMENTOFALL":     current = current.add(CipherSuitePredicate.matchOpenSslComplementOfAll()); break;
                                // SUITEB not yet supported
//                                case "SUITEB128":           return null;
//                                case "SUITEB128ONLY":       return null;
//                                case "SUITEB192":           return null;
                                default: {
                                    throw ElytronMessages.log.mechSelectorUnknownToken(name, string);
                                }
                            }
                        }
                        break;
                    }
                    throw ElytronMessages.log.mechSelectorUnexpectedChar(cp, i.getIndex(), string);
                }
            }
            // current character should be : or EOS after parse* methods
        }
        return current;
    }

    private static CipherSuiteSelector parseMoveToEnd(final CipherSuiteSelector current, final CodePointIterator i) {
        return current.pushToEnd(parsePredicate(i));
    }

    private static CipherSuiteSelector parseRemove(final CipherSuiteSelector current, final CodePointIterator i) {
        return current.remove(parsePredicate(i));
    }

    private static CipherSuiteSelector parseDelete(final CipherSuiteSelector current, final CodePointIterator i) {
        return current.deleteFully(parsePredicate(i));
    }

    private static CipherSuiteSelector parseSpecial(final CipherSuiteSelector current, final CodePointIterator i) {
        String word = i.delimitedBy('=', ':').drainToString();
        switch (word) {
            case "STRENGTH": {
                if (i.hasNext() && i.next() == '=') {
                    throw ElytronMessages.log.mechSelectorTokenNotAllowed("=", i.getIndex(), i.drainToString());
                }
                return current.sortByAlgorithmKeyLength();
            }
            default: {
                throw ElytronMessages.log.mechSelectorUnknownToken(word, i.drainToString());
            }
        }
    }

    private static CipherSuitePredicate parsePredicate(final CodePointIterator i) {
        return parsePredicate(i, i.delimitedBy('+', ':', ',', ' ').drainToString());
    }

    private static CipherSuitePredicate parsePredicate(final CodePointIterator i, final String word) {
        CipherSuitePredicate item = getSimplePredicateByName(word);
        if (i.hasNext() && i.next() == '+') {
            if (item == null) {
                throw ElytronMessages.log.mechSelectorTokenNotAllowed("+", i.getIndex(), i.drainToString());
            }
            return parseAndPredicate(item, i);
        } else {
            return item;
        }
    }

    private static CipherSuitePredicate parseAndPredicate(CipherSuitePredicate item, final CodePointIterator i) {
        final ArrayList<CipherSuitePredicate> list = new ArrayList<>();
        list.add(item);
        do {
            list.add(getSimplePredicateByName(i.delimitedBy('+', ':', ',', ' ').drainToString()));
        } while (i.hasNext() && i.next() == '+');
        return CipherSuitePredicate.matchAll(list.toArray(new CipherSuitePredicate[list.size()]));
    }

    private static CipherSuitePredicate getSimplePredicateByName(final String word) {
        switch (word) {
            /* -- openssl standard -- */
            case "HIGH":        return CipherSuitePredicate.matchLevel(SecurityLevel.HIGH);
            case "MEDIUM":      return CipherSuitePredicate.matchLevel(SecurityLevel.MEDIUM);
            case "LOW":         return CipherSuitePredicate.matchLevel(SecurityLevel.LOW);
            case "EXP":         // synonym
            case "EXPORT":      return CipherSuitePredicate.matchLevel(SecurityLevel.EXP40, SecurityLevel.EXP56);
            case "EXPORT40":    return CipherSuitePredicate.matchLevel(SecurityLevel.EXP40);
            case "EXPORT56":    return CipherSuitePredicate.matchLevel(SecurityLevel.EXP56);
            case "NULL":        // synonym
            case "eNULL":       return CipherSuitePredicate.matchEncryption(Encryption.NULL);
            case "aNULL":       return CipherSuitePredicate.matchAuthentication(Authentication.NULL);
            case "kRSA":        return CipherSuitePredicate.matchKeyAgreement(KeyAgreement.RSA);
            case "aRSA":        return CipherSuitePredicate.matchAuthentication(Authentication.RSA);
            case "RSA":         return CipherSuitePredicate.matchAny(CipherSuitePredicate.matchKeyAgreement(KeyAgreement.RSA), CipherSuitePredicate.matchAuthentication(Authentication.RSA));
            case "kDHr":        return CipherSuitePredicate.matchKeyAgreement(KeyAgreement.DHr);
            case "kDHd":        return CipherSuitePredicate.matchKeyAgreement(KeyAgreement.DHd);
            case "kDH":         return CipherSuitePredicate.matchKeyExchange(KeyAgreement.DHr, KeyAgreement.DHd);
            case "kDHE":        // synonym
            case "kEDH":        return CipherSuitePredicate.matchKeyAgreement(KeyAgreement.DHE);
            case "DHE":         // synonym
            case "EDH":         return CipherSuitePredicate.matchAll(CipherSuitePredicate.matchKeyAgreement(KeyAgreement.DHE), CipherSuitePredicate.matchNot(CipherSuitePredicate.matchAuthentication(Authentication.NULL)));
            case "ADH":         return CipherSuitePredicate.matchAnonDH();
            case "DH":          return CipherSuitePredicate.matchAll(CipherSuitePredicate.matchKeyExchange(KeyAgreement.DHE, KeyAgreement.DHd, KeyAgreement.DHr, KeyAgreement.ECDHe, KeyAgreement.ECDHr, KeyAgreement.ECDHE), CipherSuitePredicate.matchAuthentication(Authentication.DH, Authentication.ECDH, Authentication.NULL));
            case "kECDHr":      return CipherSuitePredicate.matchKeyAgreement(KeyAgreement.ECDHr);
            case "kECDHe":      return CipherSuitePredicate.matchKeyAgreement(KeyAgreement.ECDHe);
            case "kECDH":       return CipherSuitePredicate.matchKeyExchange(KeyAgreement.ECDHe, KeyAgreement.ECDHr);
            case "kEECDH":      // synonym
            case "kECDHE":      return CipherSuitePredicate.matchKeyAgreement(KeyAgreement.ECDHE);
            case "ECDHE":       // synonym
            case "EECDHE":      return CipherSuitePredicate.matchAll(CipherSuitePredicate.matchKeyAgreement(KeyAgreement.ECDHE), CipherSuitePredicate.matchNot(CipherSuitePredicate.matchAuthentication(Authentication.NULL)));
            case "AECDH":       return CipherSuitePredicate.matchAll(CipherSuitePredicate.matchKeyExchange(KeyAgreement.ECDHe, KeyAgreement.ECDHr, KeyAgreement.ECDHE), CipherSuitePredicate.matchAuthentication(Authentication.NULL));
            case "ECDH":        return CipherSuitePredicate.matchKeyExchange(KeyAgreement.ECDHe, KeyAgreement.ECDHr, KeyAgreement.ECDHE);
            case "DSS":         // synonym
            case "aDSS":        return CipherSuitePredicate.matchAuthentication(Authentication.DSS);
            case "aDH":         return CipherSuitePredicate.matchAuthentication(Authentication.DH);
            case "aECDH":       return CipherSuitePredicate.matchAuthentication(Authentication.ECDH);
            case "ECDSA":       // synonym
            case "aECDSA":      return CipherSuitePredicate.matchAuthentication(Authentication.ECDSA);
            case "kFZA":        return CipherSuitePredicate.matchKeyAgreement(KeyAgreement.FZA);
            case "aFZA":        return CipherSuitePredicate.matchAuthentication(Authentication.FZA);
            case "eFZA":        return CipherSuitePredicate.matchEncryption(Encryption.FZA);
            case "FZA":         return CipherSuitePredicate.matchAny(CipherSuitePredicate.matchKeyAgreement(KeyAgreement.FZA), CipherSuitePredicate.matchAuthentication(Authentication.FZA), CipherSuitePredicate.matchEncryption(Encryption.FZA));
            case "TLSv1.2":     return CipherSuitePredicate.matchProtocol(Protocol.TLSv1_2);
            case "TLSv1":       return CipherSuitePredicate.matchProtocol(Protocol.TLSv1);
            case "SSLv3":       return CipherSuitePredicate.matchProtocol(Protocol.SSLv3);
            case "SSLv2":       return CipherSuitePredicate.matchProtocol(Protocol.SSLv2);
            case "AES128":      return CipherSuitePredicate.matchEncryption(Encryption.AES128, Encryption.AES128GCM);
            case "AES256":      return CipherSuitePredicate.matchEncryption(Encryption.AES256, Encryption.AES256GCM);
            case "AES":         return CipherSuitePredicate.matchEncryption(Encryption.AES128, Encryption.AES128GCM, Encryption.AES256, Encryption.AES256GCM);
            case "AESGCM":      return CipherSuitePredicate.matchEncryption(Encryption.AES128GCM, Encryption.AES256GCM);
            case "CAMELLIA128": return CipherSuitePredicate.matchEncryption(Encryption.CAMELLIA128);
            case "CAMELLIA256": return CipherSuitePredicate.matchEncryption(Encryption.CAMELLIA256);
            case "CAMELLIA":    return CipherSuitePredicate.matchEncryption(Encryption.CAMELLIA128, Encryption.CAMELLIA256);
            case "3DES":        return CipherSuitePredicate.matchEncryption(Encryption._3DES);
            case "DES":         return CipherSuitePredicate.matchEncryption(Encryption.DES);
            case "RC4":         return CipherSuitePredicate.matchEncryption(Encryption.RC4);
            case "RC2":         return CipherSuitePredicate.matchEncryption(Encryption.RC2);
            case "IDEA":        return CipherSuitePredicate.matchEncryption(Encryption.IDEA);
            case "SEED":        return CipherSuitePredicate.matchEncryption(Encryption.SEED);
            case "MD5":         return CipherSuitePredicate.matchDigest(Digest.MD5);
            case "SHA":         // synonym
            case "SHA1":        return CipherSuitePredicate.matchDigest(Digest.SHA1);
            case "SHA256":      return CipherSuitePredicate.matchDigest(Digest.SHA256);
            case "SHA384":      return CipherSuitePredicate.matchDigest(Digest.SHA384);
            case "aGOST":       return CipherSuitePredicate.matchAuthentication(Authentication.GOST01, Authentication.GOST94);
            case "aGOST01":     return CipherSuitePredicate.matchAuthentication(Authentication.GOST01);
            case "aGOST94":     return CipherSuitePredicate.matchAuthentication(Authentication.GOST94);
            case "kGOST":       return CipherSuitePredicate.matchKeyAgreement(KeyAgreement.GOST);
            case "GOST94":      return CipherSuitePredicate.matchDigest(Digest.GOST94);
            case "GOST89MAC":   return CipherSuitePredicate.matchDigest(Digest.GOST89MAC);
            case "kPSK":        return CipherSuitePredicate.matchKeyAgreement(KeyAgreement.PSK);
            case "aPSK":        return CipherSuitePredicate.matchAuthentication(Authentication.PSK);
            case "PSK":         return CipherSuitePredicate.matchAny(CipherSuitePredicate.matchAuthentication(Authentication.PSK), CipherSuitePredicate.matchKeyAgreement(KeyAgreement.PSK));
            case "kRSAPSK":     // synonym
            case "RSAPSK":      return CipherSuitePredicate.matchKeyAgreement(KeyAgreement.RSAPSK);
            case "DHEPSK":      // synonym
            case "EDHPSK":      // synonym
            case "kDHEPSK":     // synonym
            case "kEDHPSK":     return CipherSuitePredicate.matchKeyAgreement(KeyAgreement.DHEPSK);
            case "EECDHPSK":    // synonym
            case "kEECDHPSK":   // synonym
            case "ECDHEPSK":    // synonym
            case "kECDEHPSK":   return CipherSuitePredicate.matchKeyAgreement(KeyAgreement.ECDHEPSK);

            default: {
                final MechanismDatabase database = MechanismDatabase.getInstance();
                MechanismDatabase.Entry entry = database.getCipherSuiteOpenSSLName(word);
                if (entry == null) {
                    entry = database.getCipherSuite(word);
                }
                if (entry == null) {
                    return null;
                }
                return CipherSuitePredicate.matchName(word);
            }
        }
    }

    /* -- selector impls -- */

    static final class AddingCipherSuiteSelector extends CipherSuiteSelector {
        private final CipherSuitePredicate predicate;

        AddingCipherSuiteSelector(final CipherSuiteSelector next, final CipherSuitePredicate predicate) {
            super(next);
            this.predicate = predicate;
        }

        void applyFilter(final Set<String> enabled, final Map<MechanismDatabase.Entry, String> supported) {
            for (Map.Entry<MechanismDatabase.Entry, String> item : supported.entrySet()) {
                final MechanismDatabase.Entry entry = item.getKey();
                if (predicate.test(entry)) {
                    if (enabled.add(item.getValue())) {
                        ElytronMessages.tls.tracef("Adding cipher suite %s due to add rule", entry);
                    } else {
                        ElytronMessages.tls.tracef("Would have added cipher suite %s due to add rule, but it was already added previously", entry);
                    }
                }
            }
        }

        void toString(final StringBuilder b) {
            if (prev != null && prev != EMPTY) {
                prev.toString(b);
                b.append(", then ");
            }
            b.append("add ");
            predicate.toString(b);
        }
    }

    static final class RemovingCipherSuiteSelector extends CipherSuiteSelector {
        private final CipherSuitePredicate predicate;

        RemovingCipherSuiteSelector(final CipherSuiteSelector next, final CipherSuitePredicate predicate) {
            super(next);
            this.predicate = predicate;
        }

        void applyFilter(final Set<String> enabled, final Map<MechanismDatabase.Entry, String> supported) {
            for (Map.Entry<MechanismDatabase.Entry, String> item : supported.entrySet()) {
                final MechanismDatabase.Entry entry = item.getKey();
                if (predicate.test(entry)) {
                    if (enabled.remove(item.getValue())) {
                        ElytronMessages.tls.tracef("Removing cipher suite %s due to remove rule", entry);
                    } else {
                        ElytronMessages.tls.tracef("Would have removed cipher suite %s due to remove rule, but it already wasn't present", entry);
                    }
                }
            }
        }

        void toString(final StringBuilder b) {
            if (prev != null && prev != EMPTY) {
                prev.toString(b);
                b.append(", then ");
            }
            b.append("remove ");
            predicate.toString(b);
        }
    }

    static final class FullyDeletingCipherSuiteSelector extends CipherSuiteSelector {
        private final CipherSuitePredicate predicate;

        FullyDeletingCipherSuiteSelector(final CipherSuiteSelector next, final CipherSuitePredicate predicate) {
            super(next);
            this.predicate = predicate;
        }

        void applyFilter(final Set<String> enabled, final Map<MechanismDatabase.Entry, String> supported) {
            Iterator<Map.Entry<MechanismDatabase.Entry, String>> iterator = supported.entrySet().iterator();
            while (iterator.hasNext()) {
                final Map.Entry<MechanismDatabase.Entry, String> item = iterator.next();
                final MechanismDatabase.Entry entry = item.getKey();
                if (predicate.test(entry)) {
                    iterator.remove();
                    enabled.remove(item.getValue());
                    ElytronMessages.tls.tracef("Fully removing cipher suite %s due to full remove rule", entry);
                }
            }
        }

        void toString(final StringBuilder b) {
            if (prev != null && prev != EMPTY) {
                prev.toString(b);
                b.append(", then ");
            }
            b.append("remove fully ");
            predicate.toString(b);
        }
    }

    static final class PushToEndCipherSuiteSelector extends CipherSuiteSelector {
        private final CipherSuitePredicate predicate;

        PushToEndCipherSuiteSelector(final CipherSuiteSelector next, final CipherSuitePredicate predicate) {
            super(next);
            this.predicate = predicate;
        }

        void applyFilter(final Set<String> enabled, final Map<MechanismDatabase.Entry, String> supported) {
            final MechanismDatabase database = MechanismDatabase.getInstance();
            final Iterator<String> iterator = enabled.iterator();
            List<String> pushed = null;
            while (iterator.hasNext()) {
                final String name = iterator.next();
                final MechanismDatabase.Entry entry = database.getCipherSuite(name);
                if (predicate.test(entry)) {
                    if (pushed == null) pushed = new ArrayList<>();
                    pushed.add(name);
                    iterator.remove();
                    ElytronMessages.tls.tracef("Pushing cipher suite %s to end due to push rule", entry);
                }
            }
            if (pushed != null) {
                // add back in order
                enabled.addAll(pushed);
            }
        }

        void toString(final StringBuilder b) {
            if (prev != null && prev != EMPTY) {
                prev.toString(b);
                b.append(", then ");
            }
            b.append("push to end ");
            predicate.toString(b);
        }
    }

    static final class SortByAlgorithmKeyLengthCipherSuiteSelector extends CipherSuiteSelector {

        SortByAlgorithmKeyLengthCipherSuiteSelector(final CipherSuiteSelector prev) {
            super(prev);
        }

        void applyFilter(final Set<String> enabled, final Map<MechanismDatabase.Entry, String> supported) {
            if (! enabled.isEmpty()) {
                final ArrayList<String> list = new ArrayList<>(enabled);
                // stable sort
                Collections.sort(list, (o1, o2) -> {
                    final MechanismDatabase database = MechanismDatabase.getInstance();
                    final MechanismDatabase.Entry e1 = database.getCipherSuite(o1);
                    final MechanismDatabase.Entry e2 = database.getCipherSuite(o2);
                    return Integer.signum(e1.getAlgorithmBits() - e2.getAlgorithmBits());
                });
                enabled.clear();
                enabled.addAll(list);
                if (ElytronMessages.tls.isTraceEnabled()) {
                    StringBuilder b = new StringBuilder(list.size() * 16);
                    b.append("Sorted ciphers by algorithm key length, result is:");
                    for (String s : list) {
                        b.append("\n    ").append(s);
                    }
                    ElytronMessages.tls.trace(b);
                }
            }
        }

        void toString(final StringBuilder b) {
            if (prev != null && prev != EMPTY) {
                prev.toString(b);
                b.append(", then ");
            }
            b.append("sort by key length");
        }
    }
}
