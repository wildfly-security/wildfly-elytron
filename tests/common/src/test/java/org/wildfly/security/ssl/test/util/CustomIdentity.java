/*
 * Copyright 2024 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.ssl.test.util;

import java.io.File;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

public class CustomIdentity extends CommonIdentity {

    private final File keyStoreFile;

    CustomIdentity(CAGenerationTool caGenerationTool, X509Certificate certificate, File keyStoreFile) {
        super(caGenerationTool, certificate);
        this.keyStoreFile = keyStoreFile;
    }

    @Override
    public KeyStore loadKeyStore() {
        return CAGenerationTool.loadKeyStore(keyStoreFile);
    }

}
