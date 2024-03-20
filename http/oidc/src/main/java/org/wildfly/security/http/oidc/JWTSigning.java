/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2023 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.http.oidc;

import java.io.InputStream;
import java.security.KeyPair;

/**
 * An interface to obtain the KeyPair from a keystore file.
 *
 * @author <a href="mailto:prpaul@redhat.com">Prarthona Paul</a>
 */

public interface JWTSigning {
    /**
     * @param keyStoreFile the path to the keystore file
     * @param storePassword the password for the keystore file
     * @param keyPassword the password for the key we would like ot extract from the keystore
     * @param keyAlias  the alias for the key that uniquely identifies it
     * @param keyStoreType the type of keystore we are trying to access
     * @return the private-public keypair extracted from the keystore
     */
    KeyPair loadKeyPairFromKeyStore(String keyStoreFile, String storePassword, String keyPassword, String keyAlias, String keyStoreType);

    /**
     * @param keystoreFile the path the keystore file we are trying to access
     * @return the contents of the file as an inputStream
     */
    InputStream findFile(String keystoreFile);
}
