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

import java.util.Collections;
import java.util.List;

import org.wildfly.security.http.util.HttpMechanismInformation;
import org.wildfly.security.sasl.util.SaslMechanismInformation;

/**
 * Credential selection mapper mechanism consume authentication process information and use it to yield a credential name.
 * Provided to ServerAuthenticationContext for determine credential name(s) which should be acquired from security realm.
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
public interface CredentialMapper {

    /**
     * Get credential names by authentication information.
     * @param information the authentication information (at least mechanism type, name and user name)
     * @return the list of credential names
     */
    List<String> getCredentialNameMapping(AuthenticationInformation information);

    /**
     * Default implementation of credential mapper
     */
    CredentialMapper ELYTRON_CREDENTIAL_MAPPER = information -> {
        switch (information.getMechanismType()) {
            case "HTTP":
                return HttpMechanismInformation.HTTP_CREDENITAL_MAPPER.getCredentialNameMapping(information);
            case "SASL":
                return SaslMechanismInformation.SASL_CREDENTIAL_MAPPER.getCredentialNameMapping(information);
            default:
                return Collections.emptyList();
        }
    };

}
