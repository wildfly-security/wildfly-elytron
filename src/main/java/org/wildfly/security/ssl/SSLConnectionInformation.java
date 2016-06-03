/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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

import java.util.Collections;
import java.util.List;

import javax.net.ssl.SNIServerName;

/**
 * Information about the SSL connection currently being built.
 */
public interface SSLConnectionInformation {
    /**
     * Get the SNI server names of this connection (if any)
     *
     * @return the SNI server names of this connection, or an empty list if there are none
     */
    default List<SNIServerName> getSNIServerNames() {
        return Collections.emptyList();
    }

    /**
     * Get the ALPN protocol names of this connection (if any).
     *
     * @return the ALPN protocol names of this connection, or an empty list if there are none
     */
    default List<String> getProtocols() {
        return Collections.emptyList();
    }

    /**
     * Returns the record version of an SSL/TLS connection.
     *
     * @return the record version (not {@code null})
     */
    String getRecordVersion();

    /**
     * Returns the hello version of an SSL/TLS connection.
     *
     * @return the hello version (not {@code null})
     */
    String getHelloVersion();
}
