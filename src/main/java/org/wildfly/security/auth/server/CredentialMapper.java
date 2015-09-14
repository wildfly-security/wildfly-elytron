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

import org.wildfly.security.sasl.util.SaslMechanismInformation.Names;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

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
        switch (information.getMechanismName()) {
            case Names.DIGEST_MD5:
                return Collections.unmodifiableList(Arrays.asList("password-digest-md5", "password-clear"));
            case Names.DIGEST_SHA:
                return Collections.unmodifiableList(Arrays.asList("password-digest-sha", "password-clear"));
            case Names.DIGEST_SHA_256:
                return Collections.unmodifiableList(Arrays.asList("password-digest-sha256", "password-clear"));
            case Names.DIGEST_SHA_384:
                return Collections.unmodifiableList(Arrays.asList("password-digest-sha384", "password-clear"));
            case Names.DIGEST_SHA_512:
                return Collections.unmodifiableList(Arrays.asList("password-digest-sha512", "password-clear"));
            case Names.SCRAM_SHA_1:
            case Names.SCRAM_SHA_1_PLUS:
                return Collections.unmodifiableList(Arrays.asList("password-scram-sha1", "password-clear"));
            case Names.SCRAM_SHA_256:
            case Names.SCRAM_SHA_256_PLUS:
                return Collections.unmodifiableList(Arrays.asList("password-scram-sha256", "password-clear"));
            case Names.SCRAM_SHA_384:
            case Names.SCRAM_SHA_384_PLUS:
                return Collections.unmodifiableList(Arrays.asList("password-scram-sha384", "password-clear"));
            case Names.SCRAM_SHA_512:
            case Names.SCRAM_SHA_512_PLUS:
                return Collections.unmodifiableList(Arrays.asList("password-scram-sha512", "password-clear"));
            case Names.PLAIN:
                return Collections.singletonList("password");
            case Names.OTP:
                return Collections.singletonList("otp");
            case Names.IEC_ISO_9798_M_DSA_SHA1:
            case Names.IEC_ISO_9798_U_DSA_SHA1:
                return Collections.singletonList("certificate-dsa-sha1");
            case Names.IEC_ISO_9798_M_ECDSA_SHA1:
            case Names.IEC_ISO_9798_U_ECDSA_SHA1:
                return Collections.singletonList("certificate-ecdsa-sha1");
            case Names.IEC_ISO_9798_M_RSA_SHA1_ENC:
            case Names.IEC_ISO_9798_U_RSA_SHA1_ENC:
                return Collections.singletonList("certificate-rsa-sha1-enc");
            default:
                return Collections.emptyList();
        }
    };

}
