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

import org.wildfly.common.Assert;

/**
 * A name rewriter.  Name rewriters transform names from one form to another for various purposes, including (but
 * not limited to):
 * <ul>
 *     <li>Normalizing case</li>
 *     <li>Trimming extra whitespace</li>
 *     <li>Mapping one naming scheme to another (e.g. "user@realm" to/from "realm/user" or similar)</li>
 *     <li>Removing a realm component (e.g. "user@realm" to "user")</li>
 * </ul>
 * A name rewriter may also be used to perform a validation step on the syntax of the name.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
@FunctionalInterface
public interface NameRewriter {

    /**
     * The simple identity name rewriter, which does no rewriting.
     */
    NameRewriter IDENTITY_REWRITER = original -> original;

    /**
     * Rewrite a name.  Must not return {@code null}.
     *
     * @param original the original name (must not be {@code null})
     * @return the rewritten name (must not be {@code null})
     * @throws IllegalArgumentException if the name is syntactically invalid
     */
    String rewriteName(String original) throws IllegalArgumentException;

    /**
     * Create a name rewriter which aggregates the given name rewriters.
     *
     * @param rewriter1 the first name rewriter (must not be {@code null})
     * @param rewriter2 the second name rewriter (must not be {@code null})
     * @return the name rewriter (not {@code null})
     */
    static NameRewriter aggregate(NameRewriter rewriter1, NameRewriter rewriter2) {
        Assert.checkNotNullParam("rewriter1", rewriter1);
        Assert.checkNotNullParam("rewriter2", rewriter2);
        return (n) -> rewriter2.rewriteName(rewriter1.rewriteName(n));
    }

    /**
     * Create a name rewriter which aggregates the given name rewriters.
     *
     * @param nameRewriters the name rewriters (must not be {@code null}, cannot have {@code null} elements)
     * @return the name rewriter (not {@code null})
     */
    static NameRewriter aggregate(NameRewriter... nameRewriters) {
        Assert.checkNotNullParam("nameRewriters", nameRewriters);
        final NameRewriter[] clone = nameRewriters.clone();
        for (int i = 0; i < clone.length; i++) {
            Assert.checkNotNullArrayParam("nameRewriters", i, clone[i]);
        }
        return (n) -> {
            for (NameRewriter r : clone) n = r.rewriteName(n);
            return n;
        };
    }

    /**
     * Create a name rewriter which always returns the same name.
     *
     * @param name the name to return
     * @return the name
     */
    static NameRewriter constant(String name) {
        return original -> name;
    }
}
