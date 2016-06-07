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
package org.wildfly.security.auth.server;

/**
 * Information about the current mechanism being used for authentication.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public interface MechanismInformation {

    /**
     * Get the type of the authentication mechanism.
     *
     * @return the type of the authentication mechanism.
     */
    String getMechanismType();


    /**
     * Get the name of the current authentication mechanism.
     *
     * @return the name of the current authentication mechanism.
     */
    String getMechanismName();

    /**
     * Get the name of the host the current authentication attempt is for.
     *
     * @return the name of the host the current authentication attempt is for.
     */
    String getHostName();

    /**
     * Get the protocol for the current authentication attempt.
     *
     * @return the protocol for the current authentication attempt.
     */
    String getProtocol();

    MechanismInformation DEFAULT = new MechanismInformation() {

        @Override
        public String getProtocol() {
            return null;
        }

        @Override
        public String getMechanismType() {
            return null;
        }

        @Override
        public String getMechanismName() {
            return null;
        }

        @Override
        public String getHostName() {
            return null;
        }
    };

}
