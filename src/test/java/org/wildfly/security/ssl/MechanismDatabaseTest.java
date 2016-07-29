/*
 * JBoss, Home of Professional Open Source.
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

package org.wildfly.security.ssl;

import org.junit.Assert;
import org.junit.Test;

public class MechanismDatabaseTest {

    @Test
    public void testBasicLoad() {
        final MechanismDatabase instance = MechanismDatabase.getInstance();
        final MechanismDatabase.Entry entry = instance.getCipherSuiteOpenSSLName("NULL-MD5");
        Assert.assertNotNull(entry);
    }

    @Test
    public void cipherSuiteSelector1() {
        CipherSuiteSelector selector = CipherSuiteSelector.fromString("ALL");
        Assert.assertArrayEquals(
            new String[] {
                "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
                "SSL_RSA_WITH_3DES_EDE_CBC_SHA",
                "TLS_SRP_SHA_WITH_AES_256_CBC_SHA",
                "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256",
            },
            selector.evaluate(new String[] {
                "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
                "SSL_RSA_WITH_3DES_EDE_CBC_SHA",
                "TLS_SRP_SHA_WITH_AES_256_CBC_SHA",
                "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256",
            })
        );
    }

    @Test
    public void cipherSuiteSelector2() {
        CipherSuiteSelector selector = CipherSuiteSelector.fromString("ALL:!RSA");
        Assert.assertArrayEquals(
            new String[] {
                "TLS_SRP_SHA_WITH_AES_256_CBC_SHA",
                "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256",
            },
            selector.evaluate(new String[] {
                "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
                "SSL_RSA_WITH_3DES_EDE_CBC_SHA",
                "TLS_SRP_SHA_WITH_AES_256_CBC_SHA",
                "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256",
            })
        );
    }

    @Test
    public void cipherSuiteSelector3() {
        CipherSuiteSelector selector = CipherSuiteSelector.fromString("ALL:!RSA:RSA");
        Assert.assertArrayEquals(
            new String[] {
                "TLS_SRP_SHA_WITH_AES_256_CBC_SHA",
                "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256",
            },
            selector.evaluate(new String[] {
                "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
                "SSL_RSA_WITH_3DES_EDE_CBC_SHA",
                "TLS_SRP_SHA_WITH_AES_256_CBC_SHA",
                "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256",
            })
        );
    }

    @Test
    public void cipherSuiteSelector4() {
        CipherSuiteSelector selector = CipherSuiteSelector.fromString("ALL:-RSA:RSA");
        Assert.assertArrayEquals(
            new String[] {
                "TLS_SRP_SHA_WITH_AES_256_CBC_SHA",
                "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
                "SSL_RSA_WITH_3DES_EDE_CBC_SHA",
            },
            selector.evaluate(new String[] {
                "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
                "SSL_RSA_WITH_3DES_EDE_CBC_SHA",
                "TLS_SRP_SHA_WITH_AES_256_CBC_SHA",
                "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256",
            })
        );
    }

    @Test
    public void cipherSuiteSelector5() {
        CipherSuiteSelector selector = CipherSuiteSelector.fromString("SSL_ECDHE_RSA_WITH_AES_128_CBC_SHA");
        Assert.assertArrayEquals(
            new String[] {
                "SSL_ECDHE_RSA_WITH_AES_128_CBC_SHA"
            },
            selector.evaluate(new String[] {
                "SSL_ECDHE_RSA_WITH_AES_128_CBC_SHA"
            })
        );
    }

}
