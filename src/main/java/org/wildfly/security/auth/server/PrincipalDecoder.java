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

import java.security.Principal;

import org.wildfly.common.Assert;

/**
 * A decoder for extracting a simple name from a principal.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
@FunctionalInterface
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
     * given rewriter.  If the rewriter deems the name invalid, then the name will be considered not decoded.
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
        Assert.checkNotNullParam("decoders", decoders);
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
     * Create a principal decoder which concatenates the results of two principal decoders.  If one decoder is not able
     * to decode the principal, {@code null} is returned.
     *
     * @param former the former decoder
     * @param joinString the string to use to join the results
     * @param latter the latter decoder
     * @return the concatenated result
     */
    static PrincipalDecoder concatenating(final PrincipalDecoder former, final String joinString, final PrincipalDecoder latter) {
        Assert.checkNotNullParam("former", former);
        Assert.checkNotNullParam("joinString", joinString);
        Assert.checkNotNullParam("latter", latter);
        return principal -> {
            final String formerName = former.getName(principal);
            final String latterName = latter.getName(principal);
            if (formerName == null || latterName == null) {
                return null;
            } else {
                return formerName + joinString + latterName;
            }
        };
    }

    /**
     * Create a principal decoder which always returns the same name.
     *
     * @param name the name to return
     * @return the constant decoder
     */
    static PrincipalDecoder constant(String name) {
        return principal -> name;
    }

    /**
     * The default decoder, which just calls {@link Principal#getName()}.
     */
    PrincipalDecoder DEFAULT = Principal::getName;

    /**
     * A principal decoder which cannot decode any principal.
     */
    PrincipalDecoder UNKNOWN = p -> null;
}
