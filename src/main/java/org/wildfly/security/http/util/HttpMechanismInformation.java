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
package org.wildfly.security.http.util;

import java.util.Collections;

import org.wildfly.security.auth.server.CredentialMapper;

/**
 * Information about HTTP authentication mechanisms.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public final class HttpMechanismInformation {

    public static final class Names {

        public static final String BASIC = "Basic";

        private Names() {};
    }

    public static final CredentialMapper HTTP_CREDENITAL_MAPPER = information -> {
        switch (information.getMechanismName()) {
            case Names.BASIC:
                return Collections.singletonList("password-clear");
            default:
                return Collections.emptyList();
        }
    };

}
