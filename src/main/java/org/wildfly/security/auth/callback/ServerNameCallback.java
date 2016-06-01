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
package org.wildfly.security.auth.callback;

import java.io.Serializable;

import javax.security.auth.callback.CallbackHandler;

/**
 * A {@link Callback} to pass the current server name from the mechanism to the {@link CallbackHandler}.
 *
 * As an informational {@code Callback} it is optional for the {@code CallbackHandler} to handle this.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class ServerNameCallback implements ExtendedCallback, Serializable {

    private static final long serialVersionUID = -8376970360160709801L;

    private final String serverName;

    /**
     * Construct a new instance for the specific server name.
     *
     * @param serverName the serverName to be contained by this instance.
     */
    public ServerNameCallback(final String serverName) {
        this.serverName = serverName;
    }

    /**
     * Get the server name contained by this {@link Callback}.
     *
     * @return the server name contained by this {@code Callback}.
     */
    public String getServerName() {
        return serverName;
    }

}
