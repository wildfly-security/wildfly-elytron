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

package org.wildfly.security.sasl;

import static org.wildfly.security._private.ElytronMessages.sasl;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.function.Supplier;

import javax.net.ssl.SSLSession;

import org.wildfly.common.Assert;
import org.wildfly.common.iteration.CodePointIterator;

/**
 * A selection specification for SASL client or server mechanisms.  The specification can be used to define the types,
 * behavior, and order of SASL mechanisms.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public abstract class SaslMechanismSelector {

    private static final SaslMechanismPredicate[] NO_PREDICATES = new SaslMechanismPredicate[0];
    final SaslMechanismSelector prev;

    private int hashCode;

    SaslMechanismSelector(final SaslMechanismSelector prev) {
        this.prev = prev;
    }

    /**
     * Create a supplier of mechanism names that provides the names of the mechanisms which are matched by
     * this selector in the preferential order that the selector specifies.  When no preference between two mechanisms
     * is specified, the original order is used.
     *
     * @param mechNames the mechanism names (must not be {@code null})
     * @return the supplier of mechanisms (not {@code null})
     */
    public Supplier<String> createMechanismSupplier(String[] mechNames) {
        return createMechanismSupplier(mechNames, null);
    }

    /**
     * Create a supplier of mechanism names that provides the names of the mechanisms which are matched by
     * this selector in the preferential order that the selector specifies.  When no preference between two mechanisms
     * is specified, the original order is used.
     *
     * @param mechNames the mechanism names (must not be {@code null})
     * @param sslSession the SSL session, if any is active, or {@code null} if SSL is not active
     * @return the supplier of mechanisms (not {@code null})
     */
    public Supplier<String> createMechanismSupplier(String[] mechNames, SSLSession sslSession) {
        Assert.checkNotNullParam("mechNames", mechNames);
        final LinkedHashSet<String> set = new LinkedHashSet<>(mechNames.length);
        Collections.addAll(set, mechNames);
        preprocess(set, sslSession);
        return doCreateSupplier(set, sslSession);
    }

    /**
     * Create a supplier of mechanism names that provides the names of the mechanisms which are matched by
     * this selector in the preferential order that the selector specifies.  When no preference between two mechanisms
     * is specified, the original order is used.
     *
     * @param mechNames the mechanism names (must not be {@code null})
     * @return the supplier of mechanisms (not {@code null})
     */
    public Supplier<String> createMechanismSupplier(Collection<String> mechNames) {
        Assert.checkNotNullParam("mechNames", mechNames);
        return createMechanismSupplier(mechNames, null);
    }

    /**
     * Create a supplier of mechanism names that provides the names of the mechanisms which are matched by
     * this selector in the preferential order that the selector specifies.  When no preference between two mechanisms
     * is specified, the original order is used.
     *
     * @param mechNames the mechanism names (must not be {@code null})
     * @param sslSession the SSL session, if any is active, or {@code null} if SSL is not active
     * @return the supplier of mechanisms (not {@code null})
     */
    public Supplier<String> createMechanismSupplier(Collection<String> mechNames, SSLSession sslSession) {
        Assert.checkNotNullParam("mechNames", mechNames);
        final LinkedHashSet<String> set = new LinkedHashSet<>(mechNames);
        preprocess(set, sslSession);
        return doCreateSupplier(set, sslSession);
    }

    /**
     * Get a list of mechanism names which are matched by this selector in the preferential order that the selector
     * specifies.  When no preference between two mechanisms is specified, the original order is used.
     *
     * @param mechNames the mechanism names (must not be {@code null})
     * @param sslSession the SSL session, if any is active, or {@code null} if SSL is not active
     * @return the list of mechanisms (not {@code null})
     */
    public List<String> apply(Collection<String> mechNames, SSLSession sslSession) {
        Assert.checkNotNullParam("mechNames", mechNames);
        final Supplier<String> supplier = createMechanismSupplier(mechNames, sslSession);
        final String first = supplier.get();
        if (first == null) {
            return Collections.emptyList();
        }
        final String second = supplier.get();
        if (second == null) {
            return Collections.singletonList(first);
        }
        ArrayList<String> list = new ArrayList<>();
        list.add(first);
        list.add(second);
        for (;;) {
            final String name = supplier.get();
            if (name == null) {
                return list;
            }
            list.add(name);
        }
    }

    abstract Supplier<String> doCreateSupplier(LinkedHashSet<String> set, SSLSession sslSession);

    void preprocess(Set<String> mechNames, SSLSession sslSession) {
        if (prev != null) {
            prev.preprocess(mechNames, sslSession);
        }
    }

    public SaslMechanismSelector addMechanism(String mechName) {
        Assert.checkNotNullParam("mechName", mechName);
        return new AddSelector(this, mechName);
    }

    public SaslMechanismSelector addMechanisms(String... mechNames) {
        Assert.checkNotNullParam("mechNames", mechNames);
        SaslMechanismSelector selector = this;
        for (String mechName : mechNames) {
            selector = new AddSelector(selector, mechName);
        }
        return selector;
    }

    public SaslMechanismSelector forbidMechanism(String mechName) {
        Assert.checkNotNullParam("mechName", mechName);
        return new ForbidSelector(this, mechName);
    }

    public SaslMechanismSelector forbidMechanisms(String... mechNames) {
        Assert.checkNotNullParam("mechNames", mechNames);
        SaslMechanismSelector selector = this;
        for (String mechName : mechNames) {
            selector = new ForbidSelector(selector, mechName);
        }
        return selector;
    }

    public SaslMechanismSelector addMatching(SaslMechanismPredicate predicate) {
        Assert.checkNotNullParam("predicate", predicate);
        return new AddMatchingSelector(this, predicate);
    }

    public SaslMechanismSelector forbidMatching(SaslMechanismPredicate predicate) {
        Assert.checkNotNullParam("predicate", predicate);
        return new ForbidMatchingSelector(this, predicate);
    }

    public SaslMechanismSelector addAllRemaining() {
        return addMatching(SaslMechanismPredicate.matchTrue());
    }

    public final String toString() {
        final StringBuilder b = new StringBuilder();
        toString(b);
        return b.toString();
    }

    public int hashCode() {
        int hashCode = this.hashCode;
        if (hashCode == 0) {
            hashCode = forbidHashCode() * 19 + addHashCode();
            return this.hashCode = hashCode == 0 ? 1 : hashCode;
        }
        return hashCode;
    }

    public final boolean equals(final Object obj) {
        return obj instanceof SaslMechanismSelector && equals((SaslMechanismSelector) obj);
    }

    public final boolean equals(final SaslMechanismSelector selector) {
        return this == selector || selector != null && hashCode() == selector.hashCode() && forbidHalfEquals(selector) && selector.forbidHalfEquals(this) && addHalfEquals(selector) && selector.addHalfEquals(this);
    }

    public static final SaslMechanismSelector NONE = new EmptySelector();

    public static final SaslMechanismSelector ALL = NONE.addAllRemaining();

    public static final SaslMechanismSelector DEFAULT = ALL.forbidMatching(
        SaslMechanismPredicate.matchAny(
            SaslMechanismPredicate.matchFamily("IEC-ISO-9798"),
            SaslMechanismPredicate.matchExact("OTP"),
            SaslMechanismPredicate.matchExact("NTLM"),
            SaslMechanismPredicate.matchExact("CRAM-MD5")
        )
    );

    private static final int TOK_INVALID = 0;
    private static final int TOK_FAMILY = 1;
    private static final int TOK_TLS = 2;
    private static final int TOK_PLUS = 3;
    private static final int TOK_MUTUAL = 4;
    private static final int TOK_HASH = 5;
    private static final int TOK_MINUS = 6;
    private static final int TOK_ALL = 7;
    private static final int TOK_LPAREN = 8;
    private static final int TOK_RPAREN = 9;
    private static final int TOK_OR = 10;
    private static final int TOK_AND = 11;
    private static final int TOK_EQ = 12;
    private static final int TOK_Q = 13;
    private static final int TOK_COLON = 14;
    private static final int TOK_NOT = 15;
    private static final int TOK_NAME = 16;
    private static final int TOK_END = -1;

    static final class Tokenizer {
        private final String string;
        private final CodePointIterator i;
        private int current = TOK_INVALID;
        private int next;
        private long offs;
        private String stringVal;
        private String nextStringVal;

        Tokenizer(final String string) {
            this.string = string;
            this.i = CodePointIterator.ofString(string);
        }

        private static boolean isNameChar(int cp) {
            return Character.isLetterOrDigit(cp) || cp == '-' || cp == '_';
        }

        @SuppressWarnings("SpellCheckingInspection")
        boolean hasNext() {
            if (next == TOK_INVALID) {
                int cp;
                while (i.hasNext()) {
                    long offs = i.getIndex();
                    cp = i.next();
                    if (! Character.isWhitespace(cp)) {
                        // determine the token type, if valid
                        switch (cp) {
                            case '#': {
                                // special of some sort
                                if (! i.hasNext()) {
                                    throw sasl.mechSelectorUnexpectedChar(cp, i.getIndex(), string);
                                }
                                offs = i.getIndex();
                                cp = i.next();
                                switch (cp) {
                                    case 'F': {
                                        // FAMILY or nothing
                                        if (! i.limitedTo(5).contentEquals("AMILY")) {
                                            throw sasl.mechSelectorUnexpectedChar(cp, i.getIndex(), string);
                                        }
                                        if (i.hasNext() && isNameChar(i.peekNext())) {
                                            throw sasl.mechSelectorUnexpectedChar(cp, i.getIndex(), string);
                                        }
                                        this.offs = offs;
                                        this.next = TOK_FAMILY;
                                        return true;
                                    }
                                    case 'T': {
                                        // TLS
                                        if (! i.limitedTo(2).contentEquals("LS")) {
                                            throw sasl.mechSelectorUnexpectedChar(cp, i.getIndex(), string);
                                        }
                                        if (i.hasNext() && isNameChar(i.peekNext())) {
                                            throw sasl.mechSelectorUnexpectedChar(cp, i.getIndex(), string);
                                        }
                                        this.offs = offs;
                                        this.next = TOK_TLS;
                                        return true;
                                    }
                                    case 'P': {
                                        // PLUS
                                        if (! i.limitedTo(3).contentEquals("LUS")) {
                                            throw sasl.mechSelectorUnexpectedChar(cp, i.getIndex(), string);
                                        }
                                        if (i.hasNext() && isNameChar(i.peekNext())) {
                                            throw sasl.mechSelectorUnexpectedChar(cp, i.getIndex(), string);
                                        }
                                        this.offs = offs;
                                        this.next = TOK_PLUS;
                                        return true;
                                    }
                                    case 'M': {
                                        // MUTUAL
                                        if (! i.limitedTo(5).contentEquals("UTUAL")) {
                                            throw sasl.mechSelectorUnexpectedChar(cp, i.getIndex(), string);
                                        }
                                        if (i.hasNext() && isNameChar(i.peekNext())) {
                                            throw sasl.mechSelectorUnexpectedChar(cp, i.getIndex(), string);
                                        }
                                        this.offs = offs;
                                        this.next = TOK_MUTUAL;
                                        return true;
                                    }
                                    case 'H': {
                                        // HASH
                                        if (! i.limitedTo(3).contentEquals("ASH")) {
                                            throw sasl.mechSelectorUnexpectedChar(cp, i.getIndex(), string);
                                        }
                                        if (i.hasNext() && isNameChar(i.peekNext())) {
                                            throw sasl.mechSelectorUnexpectedChar(cp, i.getIndex(), string);
                                        }
                                        this.offs = offs;
                                        this.next = TOK_HASH;
                                        return true;
                                    }
                                    case 'A': {
                                        // ALL
                                        if (! i.limitedTo(2).contentEquals("LL")) {
                                            throw sasl.mechSelectorUnexpectedChar(cp, i.getIndex(), string);
                                        }
                                        if (i.hasNext() && isNameChar(i.peekNext())) {
                                            throw sasl.mechSelectorUnexpectedChar(cp, i.getIndex(), string);
                                        }
                                        this.offs = offs;
                                        this.next = TOK_ALL;
                                        return true;
                                    }
                                    default: {
                                        throw sasl.mechSelectorUnexpectedChar(cp, i.getIndex(), string);
                                    }
                                }
                                //throw Assert.unreachableCode();
                            }
                            case '-': {
                                this.offs = offs;
                                this.next = TOK_MINUS;
                                return true;
                            }
                            case '(': {
                                this.offs = offs;
                                this.next = TOK_LPAREN;
                                return true;
                            }
                            case ')': {
                                this.offs = offs;
                                this.next = TOK_RPAREN;
                                return true;
                            }
                            case '?': {
                                this.offs = offs;
                                this.next = TOK_Q;
                                return true;
                            }
                            case ':': {
                                this.offs = offs;
                                this.next = TOK_COLON;
                                return true;
                            }
                            case '!': {
                                this.offs = offs;
                                this.next = TOK_NOT;
                                return true;
                            }
                            case '|': {
                                cp = i.next();
                                if (cp != '|') {
                                    throw sasl.mechSelectorUnexpectedChar(cp, i.getIndex(), string);
                                }
                                this.offs = offs;
                                this.next = TOK_OR;
                                return true;
                            }
                            case '&': {
                                cp = i.next();
                                if (cp != '&') {
                                    throw sasl.mechSelectorUnexpectedChar(cp, i.getIndex(), string);
                                }
                                this.offs = offs;
                                this.next = TOK_AND;
                                return true;
                            }
                            case '=': {
                                cp = i.next();
                                if (cp != '=') {
                                    throw sasl.mechSelectorUnexpectedChar(cp, i.getIndex(), string);
                                }
                                this.offs = offs;
                                this.next = TOK_EQ;
                                return true;
                            }
                            default: {
                                if (Character.isLetterOrDigit(cp) || cp == '_') {
                                    // name, probably
                                    final long start = i.getIndex() - 1;
                                    for (;;) {
                                        if (! i.hasNext()) {
                                            nextStringVal = string.substring((int) start);
                                            this.offs = offs;
                                            next = TOK_NAME;
                                            return true;
                                        }
                                        cp = i.next();
                                        if (! isNameChar(cp)) {
                                            switch (nextStringVal = string.substring((int) start, (int) i.getIndex() - 1)) {}
                                            i.previous();
                                            this.offs = offs;
                                            next = TOK_NAME;
                                            return true;
                                        }
                                    }
                                    //throw Assert.unreachableCode();
                                } else {
                                    throw sasl.mechSelectorUnexpectedChar(cp, i.getIndex(), string);
                                }
                            }
                        }
                    }
                }
                this.next = TOK_END;
                return false;
            }
            return next != TOK_END;
        }

        int peekNext() {
            if (! hasNext()) {
                throw new NoSuchElementException();
            }
            return next;
        }

        int next() {
            if (! hasNext()) {
                throw new NoSuchElementException();
            }
            try {
                return next;
            } finally {
                current = next;
                stringVal = nextStringVal;
                next = TOK_INVALID;
                nextStringVal = null;
            }
        }

        int current() {
            return current;
        }

        int offset() {
            return (int) offs;
        }

        String getStringVal() {
            return stringVal;
        }
    }

    static String tokToString(Tokenizer t) {
        switch (t.current()) {
            case TOK_INVALID: return "<<invalid>>";
            case TOK_FAMILY: return "#FAMILY";
            case TOK_TLS: return "#TLS";
            case TOK_PLUS: return "#PLUS";
            case TOK_MUTUAL: return "#MUTUAL";
            case TOK_HASH: return "#HASH";
            case TOK_MINUS: return "-";
            case TOK_ALL: return "#ALL";
            case TOK_LPAREN: return "(";
            case TOK_RPAREN: return ")";
            case TOK_OR: return "||";
            case TOK_AND: return "&&";
            case TOK_EQ: return "==";
            case TOK_Q: return "?";
            case TOK_COLON: return ":";
            case TOK_NOT: return "!";
            case TOK_NAME: return "<name>";
            case TOK_END: return "<<end>>";
            default: return "<<unknown>>";
        }
    }

    /*
     * Pure grammar (right-recursive, left-to-right, top-down (LL(1)) rec-descent):
     *
     *     selector ::= ( name | top-level-predicate | '-' name | '-' top-level-predicate \ '#ALL' )*
     *
     *     name ::= [A-Za-z0-9_][-A-Za-z0-9_]*
     *
     *     special ::= '#FAMILY' '(' name ')' |
     *              '#TLS' |
     *              '#PLUS' |
     *              '#MUTUAL' |
     *              '#HASH' '(' name ')'
     *
     *     top-level-predicate ::= '(' if-predicate ')' |
     *                   special |
     *                   name |
     *                   '!' top-level-predicate
     *
     *     and-predicate ::= top-level-predicate '&&' and-predicate |
     *                       top-level-predicate
     *
     *     or-predicate ::= and-predicate '||' or-predicate |
     *                      and-predicate
     *
     *     eq-predicate ::= or-predicate '==' eq-predicate |
     *                      or-predicate
     *
     *     if-predicate ::= eq-predicate '?' if-predicate ':' if-predicate |
     *                      eq-predicate
     *
     * Note that the or-, eq-, and if-predicates rules are really implemented as a repeating loop for efficiency.
     */
    public static SaslMechanismSelector fromString(String string) {
        Assert.checkNotNullParam("string", string);
        final Tokenizer t = new Tokenizer(string);
        SaslMechanismSelector current = NONE;
        int tok;
        while (t.hasNext()) {
            tok = t.next();
            switch (tok) {
                case TOK_NAME: {
                    current = current.addMechanism(t.getStringVal());
                    break;
                }
                case TOK_ALL: {
                    current = current.addAllRemaining();
                    break;
                }
                case TOK_MINUS: {
                    if (! t.hasNext()) {
                        throw sasl.mechSelectorTokenNotAllowed(tokToString(t), t.offset(), string);
                    }
                    tok = t.next();
                    switch (tok) {
                        case TOK_NAME: {
                            current = current.forbidMechanism(t.getStringVal());
                            break;
                        }
                        default: {
                            // try a predicate
                            current = current.forbidMatching(parseTopLevelPredicate(t, string, tok));
                            break;
                        }
                    }
                    break;
                }
                default: {
                    // try a predicate
                    current = current.addMatching(parseTopLevelPredicate(t, string, tok));
                    break;
                }
            }
        }
        return current;
    }

    private static SaslMechanismPredicate parseTopLevelPredicate(final Tokenizer t, final String string, final int tok) {
        switch (tok) {
            case TOK_LPAREN: {
                if (! t.hasNext()) {
                    throw sasl.mechSelectorUnexpectedEnd(string);
                }
                final SaslMechanismPredicate result = parseIfPredicate(t, string);
                if (! t.hasNext()) {
                    throw sasl.mechSelectorUnexpectedEnd(string);
                }
                if (t.next() != TOK_RPAREN) {
                    throw sasl.mechSelectorTokenNotAllowed(tokToString(t), t.offset(), string);
                }
                return result;
            }
            case TOK_FAMILY: {
                return SaslMechanismPredicate.matchFamily(parseSpecialWithName(string, t));
            }
            case TOK_HASH: {
                return SaslMechanismPredicate.matchHashFunction(parseSpecialWithName(string, t));
            }
            case TOK_PLUS: {
                return SaslMechanismPredicate.matchPlus();
            }
            case TOK_TLS: {
                return SaslMechanismPredicate.matchTLSActive();
            }
            case TOK_MUTUAL: {
                return SaslMechanismPredicate.matchMutual();
            }
            case TOK_NAME: {
                return SaslMechanismPredicate.matchExact(t.getStringVal());
            }
            case TOK_NOT: {
                return parseTopLevelPredicate(t, string).not();
            }
            default: {
                throw sasl.mechSelectorTokenNotAllowed(tokToString(t), t.offset(), string);
            }
        }
    }

    private static SaslMechanismPredicate parseIfPredicate(final Tokenizer t, final String string) {
        SaslMechanismPredicate query = parseEqPredicate(t, string);
        if (! t.hasNext() || t.peekNext() != TOK_Q) {
            return query;
        }
        t.next(); // consume
        SaslMechanismPredicate ifTrue = parseIfPredicate(t, string);
        if (! t.hasNext()) {
            throw sasl.mechSelectorUnexpectedEnd(string);
        }
        if (t.next() != TOK_COLON) {
            throw sasl.mechSelectorTokenNotAllowed(tokToString(t), t.offset(), string);
        }
        SaslMechanismPredicate ifFalse = parseIfPredicate(t, string);
        return SaslMechanismPredicate.matchIf(query, ifTrue, ifFalse);
    }

    private static SaslMechanismPredicate parseEqPredicate(final Tokenizer t, final String string) {
        SaslMechanismPredicate first = parseOrPredicate(t, string);
        if (! t.hasNext() || t.peekNext() != TOK_EQ) {
            return first;
        }
        ArrayList<SaslMechanismPredicate> list = new ArrayList<>();
        list.add(first);
        t.next(); // consume
        for (;;) {
            list.add(parseOrPredicate(t, string));
            if (! t.hasNext() || t.peekNext() != TOK_EQ) {
                return SaslMechanismPredicate.matchAllOrNone(list.toArray(NO_PREDICATES));
            }
        }
    }

    private static SaslMechanismPredicate parseOrPredicate(final Tokenizer t, final String string) {
        SaslMechanismPredicate first = parseAndPredicate(t, string);
        if (! t.hasNext() || t.peekNext() != TOK_OR) {
            return first;
        }
        ArrayList<SaslMechanismPredicate> list = new ArrayList<>();
        list.add(first);
        t.next(); // consume
        for (;;) {
            list.add(parseAndPredicate(t, string));
            if (! t.hasNext() || t.peekNext() != TOK_OR) {
                return SaslMechanismPredicate.matchAny(list.toArray(NO_PREDICATES));
            }
        }
    }

    private static SaslMechanismPredicate parseAndPredicate(final Tokenizer t, final String string) {
        SaslMechanismPredicate first = parseTopLevelPredicate(t, string);
        if (! t.hasNext() || t.peekNext() != TOK_AND) {
            return first;
        }
        ArrayList<SaslMechanismPredicate> list = new ArrayList<>();
        list.add(first);
        t.next(); // consume
        for (;;) {
            list.add(parseTopLevelPredicate(t, string));
            if (! t.hasNext() || t.peekNext() != TOK_OR) {
                return SaslMechanismPredicate.matchAll(list.toArray(NO_PREDICATES));
            }
        }
    }

    private static SaslMechanismPredicate parseTopLevelPredicate(final Tokenizer t, final String string) {
        if (! t.hasNext()) {
            throw sasl.mechSelectorUnexpectedEnd(string);
        }
        return parseTopLevelPredicate(t, string, t.next());
    }

    private static String parseSpecialWithName(final String string, final Tokenizer t) {
        if (! t.hasNext()) {
            throw sasl.mechSelectorTokenNotAllowed(tokToString(t), t.offset(), string);
        }
        if (t.next() != TOK_LPAREN) {
            throw sasl.mechSelectorTokenNotAllowed(tokToString(t), t.offset(), string);
        }
        if (! t.hasNext()) {
            throw sasl.mechSelectorTokenNotAllowed(tokToString(t), t.offset(), string);
        }
        if (t.next() != TOK_NAME) {
            throw sasl.mechSelectorTokenNotAllowed(tokToString(t), t.offset(), string);
        }
        String familyName = t.getStringVal();
        if (! t.hasNext()) {
            throw sasl.mechSelectorTokenNotAllowed(tokToString(t), t.offset(), string);
        }
        if (t.next() != TOK_RPAREN) {
            throw sasl.mechSelectorTokenNotAllowed(tokToString(t), t.offset(), string);
        }
        return familyName;
    }

    // ============= private =============

    int addHashCode() {
        return prev == null ? 0 : prev.addHashCode();
    }

    int forbidHashCode() {
        return prev == null ? 0 : prev.forbidHashCode();
    }

    boolean forbidHalfEquals(final SaslMechanismSelector selector) {
        final SaslMechanismSelector prev = this.prev;
        return prev == null || prev.forbidHalfEquals(selector);
    }

    boolean addHalfEquals(final SaslMechanismSelector selector) {
        final SaslMechanismSelector prev = this.prev;
        return prev == null || prev.addHalfEquals(selector);
    }

    abstract void toString(StringBuilder b);

    boolean adds(final String mechName) {
        final SaslMechanismSelector prev = this.prev;
        return prev != null && prev.adds(mechName);
    }

    boolean adds(final SaslMechanismPredicate predicate) {
        final SaslMechanismSelector prev = this.prev;
        return prev != null && prev.adds(predicate);
    }

    boolean forbids(final String mechName) {
        final SaslMechanismSelector prev = this.prev;
        return prev != null && prev.forbids(mechName);
    }

    boolean forbids(final SaslMechanismPredicate predicate) {
        final SaslMechanismSelector prev = this.prev;
        return prev != null && prev.forbids(predicate);
    }

    static class EmptySelector extends SaslMechanismSelector {
        private static final Supplier<String> empty = () -> null;

        EmptySelector() {
            super(null);
        }

        protected Supplier<String> doCreateSupplier(final LinkedHashSet<String> set, final SSLSession sslSession) {
            return empty;
        }

        void toString(final StringBuilder b) {
        }
    }

    static class AddSelector extends SaslMechanismSelector {
        private final String mechName;

        AddSelector(final SaslMechanismSelector prev, final String mechName) {
            super(prev);
            this.mechName = mechName;
        }

        Supplier<String> doCreateSupplier(final LinkedHashSet<String> set, final SSLSession sslSession) {
            final Supplier<String> prevSupplier = prev.doCreateSupplier(set, sslSession);
            return () -> {
                final String name = prevSupplier.get();
                if (name != null) {
                    return name;
                }
                if (set.remove(mechName)) {
                    return mechName;
                }
                return null;
            };
        }

        int addHashCode() {
            return super.addHashCode() * 19 + mechName.hashCode();
        }

        boolean addHalfEquals(final SaslMechanismSelector selector) {
            return super.addHalfEquals(selector) && selector.adds(mechName);
        }

        boolean adds(final String mechName) {
            return this.mechName.equals(mechName) || super.adds(mechName);
        }

        void toString(final StringBuilder b) {
            prev.toString(b);
            if (b.length() > 0) b.append(' ');
            b.append(mechName);
        }
    }

    static class ForbidSelector extends SaslMechanismSelector {
        private final String mechName;

        ForbidSelector(final SaslMechanismSelector prev, final String mechName) {
            super(prev);
            this.mechName = mechName;
        }

        void preprocess(final Set<String> mechNames, final SSLSession sslSession) {
            prev.preprocess(mechNames, sslSession);
            mechNames.remove(mechName);
        }

        Supplier<String> doCreateSupplier(final LinkedHashSet<String> set, final SSLSession sslSession) {
            return prev.doCreateSupplier(set, sslSession);
        }

        int forbidHashCode() {
            return super.forbidHashCode() * 19 + mechName.hashCode();
        }

        boolean forbidHalfEquals(final SaslMechanismSelector selector) {
            return super.forbidHalfEquals(selector) && selector.forbids(mechName);
        }

        boolean forbids(final String mechName) {
            return this.mechName.equals(mechName) || super.forbids(mechName);
        }

        void toString(final StringBuilder b) {
            prev.toString(b);
            if (b.length() > 0) b.append(' ');
            b.append('-').append(mechName);
        }
    }

    static class AddMatchingSelector extends SaslMechanismSelector {
        private final SaslMechanismPredicate predicate;

        AddMatchingSelector(final SaslMechanismSelector prev, final SaslMechanismPredicate predicate) {
            super(prev);
            this.predicate = predicate;
        }

        Supplier<String> doCreateSupplier(final LinkedHashSet<String> set, final SSLSession sslSession) {
            final Supplier<String> prevSupplier = prev.doCreateSupplier(set, sslSession);
            final Iterator<String> iterator = set.iterator();
            return () -> {
                String name = prevSupplier.get();
                if (name != null) {
                    return name;
                }
                while (iterator.hasNext()) {
                    name = iterator.next();
                    if (predicate.test(name, sslSession)) try {
                        return name;
                    } finally {
                        iterator.remove();
                    }
                }
                return null;
            };
        }

        int addHashCode() {
            return super.addHashCode() * 19 + predicate.calcHashCode();
        }

        boolean addHalfEquals(final SaslMechanismSelector selector) {
            return super.addHalfEquals(selector) && selector.adds(predicate);
        }

        boolean adds(final SaslMechanismPredicate predicate) {
            return this.predicate.equals(predicate) || super.adds(predicate);
        }

        void toString(final StringBuilder b) {
            prev.toString(b);
            if (b.length() > 0) b.append(' ');
            b.append('(').append(predicate).append(')');
        }
    }

    static class ForbidMatchingSelector extends SaslMechanismSelector {
        private final SaslMechanismPredicate predicate;

        ForbidMatchingSelector(final SaslMechanismSelector prev, final SaslMechanismPredicate predicate) {
            super(prev);
            this.predicate = predicate;
        }

        void preprocess(final Set<String> mechNames, final SSLSession sslSession) {
            prev.preprocess(mechNames, sslSession);
            mechNames.removeIf(mechName -> predicate.test(mechName, sslSession));
        }

        Supplier<String> doCreateSupplier(final LinkedHashSet<String> set, final SSLSession sslSession) {
            return prev.doCreateSupplier(set, sslSession);
        }

        int forbidHashCode() {
            return super.forbidHashCode() * 19 + predicate.calcHashCode();
        }

        boolean forbidHalfEquals(final SaslMechanismSelector selector) {
            return super.forbidHalfEquals(selector) && selector.forbids(predicate);
        }

        boolean forbids(final SaslMechanismPredicate predicate) {
            return this.predicate.equals(predicate) || super.forbids(predicate);
        }

        void toString(final StringBuilder b) {
            prev.toString(b);
            if (b.length() > 0) b.append(' ');
            b.append('-').append('(').append(predicate).append(')');
        }
    }
}
