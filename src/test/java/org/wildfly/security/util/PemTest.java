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

package org.wildfly.security.util;

import org.junit.Test;
import org.wildfly.security.pem.Pem;

import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPairGenerator;
import java.security.PublicKey;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class PemTest {

    @Test
    public void testEncodeDecodeRSAPublicKey() throws Exception {
        assertParsing(KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic());
    }

    @Test
    public void testEncodeDecodeDSAPublicKey() throws Exception {
        assertParsing(KeyPairGenerator.getInstance("DSA").generateKeyPair().getPublic());
    }

    @Test
    public void testEncodeDecodeECPublicKey() throws Exception {
        assertParsing(KeyPairGenerator.getInstance("EC").generateKeyPair().getPublic());
    }

    /**
     * Motivated by ELY-1301
     */
    @Test
    public void testParsePemX509CertificateCacert() throws Exception {
        URL url = PemTest.class.getResource("/ca/cacert.pem");
        byte[] bytes = Files.readAllBytes(Paths.get(url.toURI()));
        assertNotNull(Pem.parsePemX509Certificate(CodePointIterator.ofUtf8Bytes(bytes)));
    }

    private void assertParsing(PublicKey publicKey) {
        ByteStringBuilder publicKeyPem = new ByteStringBuilder();

        Pem.generatePemPublicKey(publicKeyPem, publicKey);

        PublicKey parsedKey = Pem.parsePemPublicKey(CodePointIterator.ofUtf8Bytes(publicKeyPem.toArray()));

        assertNotNull(parsedKey);
        assertArrayEquals(publicKey.getEncoded(), parsedKey.getEncoded());
    }

}
