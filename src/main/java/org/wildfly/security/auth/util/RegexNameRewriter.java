/*
 * JBoss, Home of Professional Open Source
 * Copyright 2013 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.auth.util;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A simple regular expression-based name rewriter.
 */
public final class RegexNameRewriter implements NameRewriter {
    private final Pattern pattern;
    private final String replacement;
    private final boolean replaceAll;

    /**
     * Construct a new instance.
     *
     * @param pattern the substitution pattern
     * @param replacement the replacement string
     * @param replaceAll {@code true} to replace all occurrences of the pattern; {@code false} to replace only the first occurrence
     */
    public RegexNameRewriter(final Pattern pattern, final String replacement, final boolean replaceAll) {
        this.pattern = pattern;
        this.replacement = replacement;
        this.replaceAll = replaceAll;
    }

    /**
     * Rewrite a name.  Must not return {@code null}.
     *
     * @param original the original name
     *
     * @return the rewritten name
     */
    public String rewriteName(final String original) {
        final Matcher matcher = pattern.matcher(original);
        return replaceAll ? matcher.replaceAll(replacement) : matcher.replaceFirst(replacement);
    }

    /**
     * Get the pattern.
     *
     * @return the pattern
     */
    public Pattern getPattern() {
        return pattern;
    }

    /**
     * Get the replacement string.
     *
     * @return the replacement string
     */
    public String getReplacement() {
        return replacement;
    }
}
