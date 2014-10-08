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

package org.wildfly.security.auth;

import java.net.URI;
import java.security.Principal;

import javax.security.auth.callback.CallbackHandler;

/**
 * A client for consuming identity context configurations.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class IdentityContextConfigurationClient {

    /**
     * Construct a new instance.
     *
     * @throws SecurityException if the caller does not have permission to instantiate this class
     */
    public IdentityContextConfigurationClient() throws SecurityException {
        final SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            // todo
            //sm.checkPermission(null);
        }
    }

    /**
     * Get the authentication configuration which matches the given URI, or {@code null} if there is none.
     *
     * @param uri the URI to match
     * @param identityContext the identity context to examine
     * @return the matching configuration
     */
    public AuthenticationConfiguration getAuthenticationConfiguration(URI uri, IdentityContext identityContext) {
        final int idx = identityContext.ruleMatching(uri);
        if (idx == -1) return null;
        return identityContext.getAuthenticationConfiguration(idx);
    }

    /**
     * Get an authentication callback handler for the given configuration.
     *
     * @param configuration the configuration
     * @return the callback handler
     */
    public CallbackHandler getCallbackHandler(AuthenticationConfiguration configuration) {
        return configuration.getCallbackHandler();
    }

    /**
     * Get the actual host to use for the given configuration and URI.
     *
     * @param uri the URI
     * @param configuration the configuration
     * @return the real host to use
     */
    public String getRealHost(URI uri, AuthenticationConfiguration configuration) {
        return configuration.getHost(uri);
    }

    /**
     * Get the actual port to use for the given configuration and URI.
     *
     * @param uri the URI
     * @param configuration the configuration
     * @return the real port to use
     */
    public int getRealPort(URI uri, AuthenticationConfiguration configuration) {
        return configuration.getPort(uri);
    }

    /**
     * Get the principal to use for the given configuration.
     *
     * @param configuration the configuration
     * @return the principal
     */
    public Principal getPrincipal(AuthenticationConfiguration configuration) {
        return configuration.getPrincipal();
    }
}
