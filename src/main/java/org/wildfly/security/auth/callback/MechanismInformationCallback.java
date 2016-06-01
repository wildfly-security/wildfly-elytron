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
 * A {@link Callback} to pass the information about the current mechanism to the {@link CallbackHandler}.
 *
 * As an informational {@code Callback} it is optional for the {@code CallbackHandler} to handle this.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class MechanismInformationCallback implements ExtendedCallback, Serializable {

    private static final long serialVersionUID = -8376970360160709801L;

    private final String mechanismType;
    private final String mechanismName;
    private final String hostName;
    private final String protocol;

    /**
     * Construct a new instance with the appropriate mechanism information.
     *
     * @param mechanismType the mechanism type.
     * @param mechanismName the name of the mechanism.
     * @param hostName the host name for the current authentication.
     * @param protocol the protocol for the current authentication.
     */
    public MechanismInformationCallback(final String mechanismType, final String mechanismName, final String hostName, final String protocol) {
        this.mechanismType = mechanismType;
        this.mechanismName = mechanismName;
        this.hostName = hostName;
        this.protocol = protocol;
    }

    /**
     * Get the type of the mechanism for the current authentication.
     *
     * @return the type of the mechanism for the current authentication.
     */
    public String getMechanismType() {
        return mechanismType;
    }

    /**
     * Get the name of the mechanism for the current authentication.
     *
     * @return the name of the mechanism for the current authentication.
     */
    public String getMechanismName() {
        return mechanismName;
    }

    /**
     * Get the host name for the current authentication.
     *
     * @return the host name for the current authentication.
     */
    public String getHostName() {
        return hostName;
    }

    /**
     * Get the protocol for the current authentication.
     *
     * @return the protocol for the current authentication.
     */
    public String getProtocol() {
        return protocol;
    }

}
