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

package org.wildfly.security.auth.util;

import java.util.regex.Pattern;

/**
 * A regular expression-based name validation rewriter.  Always returns the original name
 * if the name is valid.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class RegexNameValidatingRewriter implements NameRewriter {
    private final Pattern pattern;
    private final boolean match;

    /**
     * Construct a new instance.  The pattern is a partial pattern; if the whole string is to be matched, then
     * the appropriate regex anchors should be used.
     *
     * @param pattern the pattern that the name must match (or not match) in order to be considered valid
     * @param match {@code true} if the pattern must match, {@code false} if the pattern must not match
     */
    public RegexNameValidatingRewriter(final Pattern pattern, final boolean match) {
        this.pattern = pattern;
        this.match = match;
    }

    public String rewriteName(final String original) throws IllegalArgumentException {
        if (pattern.matcher(original).find() != match) {
            throw new IllegalArgumentException("Invalid name");
        }
        return original;
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
     * Get the match flag.  If the flag is {@code true}, the pattern must match; if {@code false}, the pattern
     * must not match.
     *
     * @return the match flag
     */
    public boolean isMatch() {
        return match;
    }
}
