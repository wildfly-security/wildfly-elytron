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

package org.wildfly.security.auth.client;

import static org.wildfly.common.math.HashMath.multiHashUnordered;

import java.util.function.Function;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class RewriteNameAuthenticationConfiguration extends AuthenticationConfiguration {

    private final Function<String, String> rewriter;

    RewriteNameAuthenticationConfiguration(final AuthenticationConfiguration parent, final Function<String, String> rewriter) {
        super(parent);
        this.rewriter = rewriter;
    }

    String doRewriteUser(final String original) {
        return rewriter.apply(super.doRewriteUser(original));
    }

    AuthenticationConfiguration reparent(final AuthenticationConfiguration newParent) {
        return new RewriteNameAuthenticationConfiguration(newParent, rewriter);
    }

    @Override
    StringBuilder asString(StringBuilder sb) {
        return parentAsString(sb).append("RewriteName,");
    }

    boolean halfEqual(final AuthenticationConfiguration other) {
        return rewriter.equals(other.getNameRewriter()) && parentHalfEqual(other);
    }

    int calcHashCode() {
        return multiHashUnordered(parentHashCode(), 47287, rewriter.hashCode());
    }

    Function<String, String> getNameRewriter() {
        return rewriter;
    }
}
