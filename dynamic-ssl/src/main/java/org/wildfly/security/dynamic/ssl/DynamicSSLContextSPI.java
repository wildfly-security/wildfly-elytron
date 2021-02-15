/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2021 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.dynamic.ssl;

import javax.net.ssl.SSLContext;
import java.net.URI;
import java.util.List;

/**
 * This interface provides configuration that is used by DynamicSSLContext.
 */
public interface DynamicSSLContextSPI {

    /**
     * Get SSLContext that will be used as a default, eg. when no URI is provided.
     *
     * @return configured default SSLContext
     */
    SSLContext getConfiguredDefault() throws DynamicSSLContextException;

    /**
     * Get list of all configured SSLContexts. This is used to obtain cipher suites supported by all SSLContexts.
     *
     * @return list of all configured SSLContexts
     */
    List<SSLContext> getConfiguredSSLContexts() throws DynamicSSLContextException;

    /**
     * Get the SSLContext that matches the given URI.
     *
     * @return SSLContext that matches the given URI
     */
    SSLContext getSSLContext(URI uri) throws DynamicSSLContextException;
}
