/*
 * JBoss, Home of Professional Open Source
 * Copyright 2020 Red Hat, Inc., and individual contributors
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

import java.util.Locale;
import org.wildfly.security.auth.server.NameRewriter;

/**
 * A case name rewriter adjusts a principal to upper or lower case.
 *
 * @author <a href="mailto:szaldana@redhat.com">Sonia Zaldana Calles</a>
 */
public final class CaseNameRewriter implements NameRewriter {
    private final boolean upperCase;

    /**
     * Construct a new instance which transforms to upper case.
     */
    public CaseNameRewriter() {
        this(true);
    }

    /**
     * Construct a new instance.
     *
     * @param upperCase {@code true} if the principal should be converted to upper case,
     *                  {@code false} if the principal should be converted to lower case.
     */
    public CaseNameRewriter(boolean upperCase) {
        this.upperCase = upperCase;
    }

    /**
     * Rewrite a name.
     *
     * @param original the original name
     *
     * @return the rewritten name
     */
    @Override
    public String rewriteName(String original) {
        if (original == null) {
            return null;
        }

        return (upperCase) ? original.toUpperCase(Locale.ROOT) : original.toLowerCase(Locale.ROOT);
    }
}
