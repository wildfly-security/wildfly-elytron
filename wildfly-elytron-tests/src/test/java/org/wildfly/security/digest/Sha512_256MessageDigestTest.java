/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.digest;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.common.iteration.ByteIterator;
import org.wildfly.security.WildFlyElytronProvider;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.Security;

/**
 * SHA-512/256 hashing test
 */
public class Sha512_256MessageDigestTest {

    private static final Provider provider = new WildFlyElytronProvider();

    @BeforeClass
    public static void register() {
        Security.addProvider(provider);
    }

    @AfterClass
    public static void remove() {
        Security.removeProvider(provider.getName());
    }

    // For reference output: http://emn178.github.io/online-tools/
    @Test
    public void testSha512_256() throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-512-256");

        byte[] digest = md.digest(new byte[]{});
        Assert.assertEquals("c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a", ByteIterator.ofBytes(digest).hexEncode().drainToString());

        digest = md.digest("abc".getBytes(StandardCharsets.UTF_8));
        Assert.assertEquals("53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23", ByteIterator.ofBytes(digest).hexEncode().drainToString());

        digest = md.digest("aaaaaaaaaabbbbbbbbbbCCCCCCCCCCaaaaaaaaaabbbbbbbbbbCCCCCCCCCCaaaaaaaaaabbbbbbbbbbCCCCCCCCCCaaaaaaaaaabbbbbbbbbbCCCCCCCCCC".getBytes(StandardCharsets.UTF_8));
        Assert.assertEquals("12561da13cbc174f7f53f3a536595e09861de4682c087647c1b10f9e5d981b1e", ByteIterator.ofBytes(digest).hexEncode().drainToString());

        md.update("to drop".getBytes(StandardCharsets.UTF_8));
        md.reset();
        md.update("aaaaaaaaa".getBytes(StandardCharsets.UTF_8));
        md.update("bbbbbbbbb".getBytes(StandardCharsets.UTF_8));
        digest = md.digest("ccc".getBytes(StandardCharsets.UTF_8));
        Assert.assertEquals("855637b2fdd593e36bdf30b4ad6d51741e4a2044323b605c26611e4a536d955b", ByteIterator.ofBytes(digest).hexEncode().drainToString());
    }
}
