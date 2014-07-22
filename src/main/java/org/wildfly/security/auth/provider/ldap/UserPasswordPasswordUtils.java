/*
 * JBoss, Home of Professional Open Source
 * Copyright 2014 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.auth.provider.ldap;

import static org.wildfly.security.password.interfaces.TrivialDigestPassword.*;
import java.nio.charset.Charset;
import java.security.spec.InvalidKeySpecException;

import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.password.spec.PasswordSpec;
import org.wildfly.security.password.spec.TrivialDigestPasswordSpec;
import org.wildfly.security.util.Base64;
import org.wildfly.security.util.CharacterArrayIterator;

/**
 * A password utility for LDAP formatted passwords.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class UserPasswordPasswordUtils {

    static final Charset UTF_8 = Charset.forName("UTF-8");

    private UserPasswordPasswordUtils() {
    }

    public static PasswordSpec parseUserPassword(byte[] userPassword) throws InvalidKeySpecException {
        if (userPassword == null || userPassword.length == 0) {
            throw new IllegalArgumentException("userPassword can not be null or empty.");
        }

        if (userPassword[0] != '{') {
            return createClearPasswordSpec(userPassword);
        } else {
            if (userPassword[1] == 's' && userPassword[2] == 'h' && userPassword[3] == 'a') {
                if (userPassword[4] == '}') {
                    // {sha}
                    return createTrivialDigestSpec(ALGORITHM_DIGEST_SHA_1, 5, userPassword);
                } else if (userPassword[4] == '2' && userPassword[5] == '5' && userPassword[6] == '6' && userPassword[7] == '}') {
                    // {sha256}
                    return createTrivialDigestSpec(ALGORITHM_DIGEST_SHA_256, 8, userPassword);
                } else if (userPassword[4] == '3' && userPassword[5] == '8' && userPassword[6] == '4' && userPassword[7] == '}') {
                    // {sha384}
                    return createTrivialDigestSpec(ALGORITHM_DIGEST_SHA_384, 8, userPassword);
                } else if (userPassword[4] == '5' && userPassword[5] == '1' && userPassword[6] == '2' && userPassword[7] == '}') {
                    // {sha512}
                    return createTrivialDigestSpec(ALGORITHM_DIGEST_SHA_512, 8, userPassword);
                }
                for (int i = 1; i < userPassword.length - 1; i++) {
                    if (userPassword[i] == '}') {
                        throw new InvalidKeySpecException();
                    }
                }
                return createClearPasswordSpec(userPassword);
            }
        }

        throw new InvalidKeySpecException();
    }

    private static PasswordSpec createClearPasswordSpec(byte[] userPassword) {
        return new ClearPasswordSpec(new String(userPassword, UTF_8).toCharArray());
    }

    private static PasswordSpec createTrivialDigestSpec(String algorithm, int prefixSize, byte[] userPassword)
            throws InvalidKeySpecException {
        // TODO - ELY-43 should clean up Base64 handling and remove the need to trim the padding from the encoded value.
        int length = userPassword.length - prefixSize;
        for (int i = userPassword.length - 1; i > 0; i--) {
            if (userPassword[i] == '=') {
                length--;
            } else {
                break;
            }
        }

        char[] encodedBase64 = new String(userPassword, prefixSize, length, UTF_8).toCharArray();
        byte[] digest = new byte[encodedBase64.length * 3 / 4];
        Base64.base64DecodeB(new CharacterArrayIterator(encodedBase64), digest);

        return new TrivialDigestPasswordSpec(algorithm, digest);
    }

}
