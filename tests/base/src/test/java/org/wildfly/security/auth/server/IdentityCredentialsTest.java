/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.auth.server;

import static org.junit.Assert.assertNotNull;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.Security;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;
import org.wildfly.security.password.interfaces.ScramDigestPassword;
import org.wildfly.security.password.spec.EncryptablePasswordSpec;
import org.wildfly.security.password.spec.IteratedSaltedPasswordAlgorithmSpec;

public class IdentityCredentialsTest {

    private static final Provider provider = WildFlyElytronPasswordProvider.getInstance();

    @BeforeClass
    public static void registerProvider() {
        Security.addProvider(provider);
    }

    @AfterClass
    public static void removeProvider() {
        Security.removeProvider(provider.getName());
    }

    @Test
    public void testLooseMatches() throws GeneralSecurityException {
        IdentityCredentials credentials = IdentityCredentials.NONE;
        PasswordCredential credential1 = new PasswordCredential(generatePassword(ScramDigestPassword.ALGORITHM_SCRAM_SHA_1, "password", "salt", 1));
        credentials = credentials.withCredential(credential1);

        // Assert ONE matches
        assertCredentials(credentials, credential1, ScramDigestPassword.ALGORITHM_SCRAM_SHA_1);

        PasswordCredential credential2 = new PasswordCredential(generatePassword(ScramDigestPassword.ALGORITHM_SCRAM_SHA_256, "password", "salt", 2));
        credentials = credentials.withCredential(credential2);

        // Assert TWO matches
        assertCredentials(credentials, credential1, ScramDigestPassword.ALGORITHM_SCRAM_SHA_1);
        assertCredentials(credentials, credential2, ScramDigestPassword.ALGORITHM_SCRAM_SHA_256);

        PasswordCredential credential3 = new PasswordCredential(generatePassword(ScramDigestPassword.ALGORITHM_SCRAM_SHA_512, "password", "salt", 3));
        credentials = credentials.withCredential(credential3);

        // Assert MANY matches
        assertCredentials(credentials, credential1, ScramDigestPassword.ALGORITHM_SCRAM_SHA_1);
        assertCredentials(credentials, credential2, ScramDigestPassword.ALGORITHM_SCRAM_SHA_256);
        assertCredentials(credentials, credential3, ScramDigestPassword.ALGORITHM_SCRAM_SHA_512);
    }

    private void assertCredentials(IdentityCredentials credentials, PasswordCredential credential, String algorithm) {
        assertNotNull(credentials.getCredential(PasswordCredential.class)); // null algo, null paramspec
        assertNotNull(credentials.getCredential(PasswordCredential.class, algorithm)); // null paramspec
        assertNotNull(credentials.getCredential(PasswordCredential.class, algorithm, credential.getPassword().castAs(ScramDigestPassword.class).getParameterSpec()));
    }

    private static Password generatePassword(String algorithm, String password, String salt, int iterationCount) throws GeneralSecurityException {
        IteratedSaltedPasswordAlgorithmSpec algoSpec = new IteratedSaltedPasswordAlgorithmSpec(iterationCount, salt.getBytes(StandardCharsets.UTF_8));
        EncryptablePasswordSpec encSpec = new EncryptablePasswordSpec(password.toCharArray(), algoSpec);
        return PasswordFactory.getInstance(algorithm).generatePassword(encSpec);
    }
}
