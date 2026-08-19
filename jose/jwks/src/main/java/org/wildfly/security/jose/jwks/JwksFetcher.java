/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2026 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wildfly.security.jose.jwks;

import java.net.URL;

/**
 * HTTP transport abstraction for fetching a JWKS document from a remote endpoint.
 *
 * @author <a href="mailto:rojeda@redhat.com">Raul Ojeda Robles</a>
 */
@FunctionalInterface
public interface JwksFetcher {

    /**
     * Fetch the JWKS document from the given URL.
     *
     * @param url the JWKS endpoint URL
     * @return the raw response body as bytes (expected to be a JSON JWKS document)
     * @throws JwksException if the fetch fails for any reason (I/O error, non-200 status, etc.)
     */
    byte[] fetch(URL url) throws JwksException;
}
