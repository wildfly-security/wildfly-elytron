/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
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
