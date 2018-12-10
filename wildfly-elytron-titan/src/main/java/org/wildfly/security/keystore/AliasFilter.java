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
package org.wildfly.security.keystore;

import static org.wildfly.common.Assert.checkNotNullParam;
import static org.wildfly.security._private.ElytronMessages.log;

import java.security.KeyStore;
import java.util.function.Function;
import java.util.function.Predicate;

import org.wildfly.common.iteration.CodePointIterator;

/**
 * A utility to create the {@link Predicate} as used for filtering the aliases in a {@link KeyStore}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public abstract class AliasFilter implements Predicate<String> {

    protected final Predicate<String> previous;

    private AliasFilter(Predicate<String> previous) {
        this.previous = previous;
    }

    public static final AliasFilter ALL = new AliasFilter(null) {

        @Override
        public boolean test(String t) {
            return true;
        }

    };

    public static final AliasFilter NONE = new AliasFilter(null) {

        @Override
        public boolean test(String t) {
            return false;
        }

    };

    public AliasFilter add(final String alias) {
        return new AliasFilter(this) {

            @Override
            public boolean test(String t) {
                if (alias.equals(t)) {
                    return true;
                } else {
                    return previous.test(t);
                }
            }

        };
    }

    public AliasFilter remove(final String alias) {
        return new AliasFilter(this) {

            @Override
            public boolean test(String t) {
                if (alias.equals(t)) {
                    return false;
                } else {
                    return previous.test(t);
                }
            }

        };
    }


    public abstract boolean test(String t);

    /**
     * Create an AliasFilter based on a filterString in one of the following formats: -
     *
     * <ul>
     *   <li> alias1,alais2,alias3         - Only the aliases listed are accepted></li>
     *   <li> ALL:-alias1:-alias2:-alias3  - All aliases allowed except those listed.</li>
     *   <li> NONE:+alias1:+alias2:+alais3 - Only the aliases listed are accepted</li>
     * </ul>
     *
     * Note: For ambiguous definitions aliases are evaluated against the filter string from right to left with the first match winning, e.g.
     *
     * <ul>
     *   <li> ALL:-alias1:+alias1          - alias1 is an accepted alias.</li>
     * </ul>
     * @param filterString
     * @return
     */
    public static AliasFilter fromString(final String filterString) {
        CodePointIterator i = CodePointIterator.ofString(checkNotNullParam("filterString", filterString));
        if (i.hasNext()) {
            String firstWord = i.delimitedBy(',',':').drainToString();
            if (i.hasNext()) {
                AliasFilter current;
                switch (i.next()) {
                    case ',':
                        current = NONE.add(firstWord);
                        while (i.hasNext()) {
                            current = current.add(i.delimitedBy(',').drainToString());
                            if (i.hasNext()) i.next(); // Remove the delimiter.
                        }
                        break;
                    case ':':
                        switch (firstWord) {
                            case "ALL":
                                current = ALL;
                                break;
                            case "NONE":
                                current = NONE;
                                break;
                            default:
                                throw log.invalidFirstWord(firstWord);
                        }

                        while (i.hasNext()) {
                            Function<String, AliasFilter> function;
                            switch (i.next()) {
                                case '+':
                                    function = current::add;
                                    break;
                                case '-':
                                    function = current::remove;
                                    break;
                                default:
                                    throw log.missingPlusMinusAt(i.getIndex());
                            }
                            if (i.hasNext()) {
                                current = function.apply(i.delimitedBy(':').drainToString());
                                if (i.hasNext()) i.next(); // Remove the delimiter.
                            }
                        }
                        break;
                    default:
                        throw new IllegalStateException();
                }
                return current;
            } else {
                // Only a single 'alias' encountered.
                switch (firstWord) {
                    case "ALL":
                        return ALL;
                    case "NONE":
                        return NONE;
                    default:
                        return NONE.add(firstWord);
                }
            }
        } else {
            throw log.emptyFilter();
        }
    }

}
