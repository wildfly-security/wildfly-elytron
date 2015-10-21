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

package org.wildfly.security.auth.server;

import org.wildfly.common.Assert;

/**
 * A configuration for a single mechanism realm.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class MechanismRealmConfiguration {
    private final String name;
    private final NameRewriter preRealmRewriter;
    private final NameRewriter postRealmRewriter;
    private final NameRewriter finalRewriter;

    /**
     * Construct a new instance.
     *
     * @param name the name of this realm (may not be {@code null})
     * @param preRealmRewriter the pre-realm rewriter to apply (may not be {@code null})
     * @param postRealmRewriter the post-realm rewriter to apply (may not be {@code null})
     * @param finalRewriter the final rewriter to apply (may not be {@code null})
     */
    public MechanismRealmConfiguration(final String name, final NameRewriter preRealmRewriter, final NameRewriter postRealmRewriter, final NameRewriter finalRewriter) {
        Assert.checkNotNullParam("name", name);
        Assert.checkNotNullParam("preRealmRewriter", preRealmRewriter);
        Assert.checkNotNullParam("postRealmRewriter", postRealmRewriter);
        Assert.checkNotNullParam("finalRewriter", finalRewriter);
        this.name = name;
        this.preRealmRewriter = preRealmRewriter;
        this.postRealmRewriter = postRealmRewriter;
        this.finalRewriter = finalRewriter;
    }

    /**
     * Get the mechanism name.
     *
     * @return the mechanism name (not {@code null})
     */
    public String getName() {
        return name;
    }

    /**
     * Get the pre-realm rewriter for this mechanism realm.
     *
     * @return the pre-realm rewriter for this mechanism realm (not {@code null})
     */
    public NameRewriter getPreRealmRewriter() {
        return preRealmRewriter;
    }

    /**
     * Get the post-realm rewriter for this mechanism realm.
     *
     * @return the post-realm rewriter for this mechanism realm (not {@code null})
     */
    public NameRewriter getPostRealmRewriter() {
        return postRealmRewriter;
    }

    /**
     * Get the final rewriter for this mechanism realm.
     *
     * @return the final rewriter for this mechanism realm (not {@code null})
     */
    public NameRewriter getFinalRewriter() {
        return finalRewriter;
    }

    /**
     * A realm configuration for no particular realm, which does no additional rewriting.
     */
    public static final MechanismRealmConfiguration NO_REALM = new MechanismRealmConfiguration("none", NameRewriter.IDENTITY_REWRITER, NameRewriter.IDENTITY_REWRITER, NameRewriter.IDENTITY_REWRITER);
}
