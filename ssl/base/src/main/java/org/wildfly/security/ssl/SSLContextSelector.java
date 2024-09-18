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

package org.wildfly.security.ssl;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;

import org.wildfly.common.Assert;
import org.wildfly.common.array.Arrays2;

/**
 * A selector which chooses an SSL context based on connection information.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
@FunctionalInterface
public interface SSLContextSelector {

    /**
     * Select the SSL context which corresponds to the given connection information.  The selector returns the SSL context
     * that should be used for this connection, or {@code null} if no SSL contexts match, in which case a fallback
     * selector may be used, or a default SSL context selected.  If no selectors match an SSL context, the connection
     * is refused.
     *
     * @param connectionInformation information about the in-progress connection
     * @return the SSL context to use, or {@code null} if the connection is not acceptable to this selector
     */
    SSLContext selectContext(SSLConnectionInformation connectionInformation);

    /**
     * Create an aggregate selector which executes each given selector in order until a match is found.
     *
     * @param selector1 the first selector to test
     * @param selector2 the second selector to test
     * @return the matched selector
     */
    static SSLContextSelector aggregate(SSLContextSelector selector1, SSLContextSelector selector2) {
        return information -> {
            SSLContext sslContext = null;
            if (selector1 != null) sslContext = selector1.selectContext(information);
            if (sslContext == null && selector2 != null) sslContext = selector2.selectContext(information);
            return sslContext;
        };
    }

    /**
     * Create an aggregate selector which executes each given selector in order until a match is found.
     *
     * @param selectors the selectors to test
     * @return the matched selector
     */
    static SSLContextSelector aggregate(SSLContextSelector... selectors) {
        Assert.checkNotNullParam("selectors", selectors);
        final SSLContextSelector[] clone = Arrays2.compactNulls(selectors.clone());
        if (clone.length == 0) {
            return NULL_SELECTOR;
        } else if (clone.length == 1) {
            return clone[0];
        } else if (clone.length == 2) {
            return aggregate(clone[0], clone[1]);
        } else {
            return name -> {
                SSLContext sslContext;
                for (SSLContextSelector selector : clone) {
                    sslContext = selector.selectContext(name);
                    if (sslContext != null) {
                        return sslContext;
                    }
                }
                return null;
            };
        }
    }

    /**
     * Create a selector which returns the given SSL context if the given SNI matcher matches.
     *
     * @param matcher the SNI matcher (must not be {@code null})
     * @param context the SSL context to select (must not be {@code null})
     * @return the context if the name matches, otherwise {@code null}
     * @see SNIHostName#createSNIMatcher(String)
     * @see SSLUtils#createHostNameStringPredicateSNIMatcher(java.util.function.Predicate)
     * @see SSLUtils#createHostNamePredicateSNIMatcher(java.util.function.Predicate)
     * @see SSLUtils#createHostNameStringSNIMatcher(String)
     * @see SSLUtils#createHostNameSuffixSNIMatcher(String)
     */
    static SSLContextSelector sniMatcherSelector(SNIMatcher matcher, SSLContext context) {
        Assert.checkNotNullParam("matcher", matcher);
        Assert.checkNotNullParam("context", context);
        return information -> {
            for (SNIServerName serverName : information.getSNIServerNames()) {
                if (serverName != null && serverName.getType() == matcher.getType() && matcher.matches(serverName)) {
                    return context;
                }
            }
            return null;
        };
    }

    /**
     * Create a selector which always returns the same context.
     *
     * @param context the context to return
     * @return the selector which always returns {@code context}
     */
    static SSLContextSelector constantSelector(SSLContext context) {
        return name -> context;
    }

    /**
     * A selector which always returns {@code null} (no match).
     */
    SSLContextSelector NULL_SELECTOR = constantSelector(null);
}
