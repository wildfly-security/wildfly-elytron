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

import static org.wildfly.security._private.ElytronMessages.log;

/**
 * Authentication process information for credential selection mappers.
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
public class AuthenticationInformation {

    private final String mechanismType; // SASL / HTTP / SSL / ...

    private final String mechanismName; // "digest-md5" (SaslMechanismInformation.Names.*)

    private AuthenticationInformation(Builder builder) {
        this.mechanismType = builder.mechanismType;
        this.mechanismName = builder.mechanismName;
    }

    public String getMechanismType() {
        return mechanismType;
    }

    public String getMechanismName() {
        return mechanismName;
    }

    public static final class Builder {
        private boolean built = false;

        private String mechanismType;
        private String mechanismName;

        /**
         * Sets a mechanism type: SASL / HTTP / SSL / ...
         *
         * @param mechanismType the mechanism type
         * @return this builder
         */
        public Builder setMechanismType(String mechanismType) {
            assertNotBuilt();
            this.mechanismType = mechanismType;
            return this;
        }

        /**
         * Sets a mechanism name: "digest-md5" (SaslMechanismInformation.Names.*)
         *
         * @param mechanismName the mechanism name
         * @return this builder
         */
        public Builder setMechanismName(String mechanismName) {
            assertNotBuilt();
            this.mechanismName = mechanismName;
            return this;
        }

        /**
         * Construct this authentication information.
         *
         * @return the new authentication information
         */
        public AuthenticationInformation build() {
            built = true;
            return new AuthenticationInformation(this);
        }

        private void assertNotBuilt() {
            if (built) {
                throw log.builderAlreadyBuilt();
            }
        }
    }
}
