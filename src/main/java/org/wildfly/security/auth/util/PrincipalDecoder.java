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

package org.wildfly.security.auth.util;

import java.security.Principal;

/**
 * A decoder for extracting a simple name from a principal.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public interface PrincipalDecoder {

    /**
     * Get the name from a principal.  If this decoder cannot understand the given principal type or contents,
     * {@code null} is returned.
     *
     * @param principal the principal to decode
     * @return the name, or {@code null} if this decoder does not understand the principal
     */
    String getName(Principal principal);

    /**
     * Add a name rewriter to this principal decoder.  If the name is decoded, it will then be rewritten with the
     * given rewriter.
     *
     * @param nameRewriter the name rewriter
     * @return the combined decoder
     */
    default PrincipalDecoder withRewriter(NameRewriter nameRewriter) {
        return principal -> {
            final String name = this.getName(principal);
            return name == null ? null : nameRewriter.rewriteName(name);
        };
    }

    /**
     * Create an aggregated credential decoder.  The aggregated decoder will check each credential decoder until one
     * matches the credential; this result will be returned.
     *
     * @param decoders the constituent decoders
     * @return the aggregated decoder
     */
    static PrincipalDecoder aggregate(final PrincipalDecoder... decoders) {
        if (decoders == null) {
            throw new IllegalArgumentException("decoders is null");
        }
        return principal -> {
            String result;
            for (PrincipalDecoder decoder : decoders) {
                result = decoder.getName(principal);
                if (result != null) {
                    return result;
                }
            }
            return null;
        };
    }

    /**
     * The default decoder, which just calls {@link Principal#getName()}.
     */
    PrincipalDecoder DEFAULT = Principal::getName;
}
