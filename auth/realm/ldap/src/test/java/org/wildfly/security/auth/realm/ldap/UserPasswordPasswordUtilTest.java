/*
 * JBoss, Home of Professional Open Source
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

package org.wildfly.security.auth.realm.ldap;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.interfaces.BSDUnixDESCryptPassword;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.interfaces.SaltedSimpleDigestPassword;
import org.wildfly.security.password.interfaces.SimpleDigestPassword;
import org.wildfly.security.password.interfaces.UnixDESCryptPassword;
import org.wildfly.security.password.spec.Encoding;

import java.nio.charset.StandardCharsets;

/**
 * Test of composing and parsing of individual LDAP passwords in {@link org.wildfly.security.auth.realm.ldap.UserPasswordPasswordUtil}
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
public class UserPasswordPasswordUtilTest {

    @Test
    public void testClear() throws Exception {
        byte[] orig = "{clear}alpha".getBytes(StandardCharsets.UTF_8);
        ClearPassword parsedPassword = (ClearPassword) UserPasswordPasswordUtil.parseUserPassword(orig);
        assertEquals(ClearPassword.ALGORITHM_CLEAR, parsedPassword.getAlgorithm());
        assertEquals("alpha", new String(parsedPassword.getPassword()));

        byte[] composed = UserPasswordPasswordUtil.composeUserPassword(parsedPassword);
        assertEquals("alpha", new String(composed, StandardCharsets.UTF_8));
    }

    @Test
    public void testClearWithoutPrefix() throws Exception {
        byte[] orig = "alpha".getBytes(StandardCharsets.UTF_8);
        ClearPassword parsedPassword = (ClearPassword) UserPasswordPasswordUtil.parseUserPassword(orig);
        assertEquals(ClearPassword.ALGORITHM_CLEAR, parsedPassword.getAlgorithm());
        assertEquals("alpha", new String(parsedPassword.getPassword()));

        byte[] composed = UserPasswordPasswordUtil.composeUserPassword(parsedPassword);
        assertEquals("alpha", new String(composed, StandardCharsets.UTF_8));
    }

    @Test
    public void testMd5() throws Exception {
        byte[] orig = "{md5}WhBei51A4TKXgNYuoiZdig==".getBytes(StandardCharsets.UTF_8);
        SimpleDigestPassword parsedPassword = (SimpleDigestPassword) UserPasswordPasswordUtil.parseUserPassword(orig);
        assertEquals(SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_MD5, parsedPassword.getAlgorithm());

        byte[] composed = UserPasswordPasswordUtil.composeUserPassword(parsedPassword);
        assertEquals("{md5}WhBei51A4TKXgNYuoiZdig==", new String(composed, StandardCharsets.UTF_8));
    }

    @Test
    public void testMd5HexEncoded() throws Exception {
        byte[] orig = "{md5}166cd90440d36bec262f8ba3867ad646".getBytes(StandardCharsets.UTF_8);
        SimpleDigestPassword parsedPassword = (SimpleDigestPassword) UserPasswordPasswordUtil.parseUserPassword(orig, Encoding.HEX);
        assertEquals(SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_MD5, parsedPassword.getAlgorithm());

        byte[] composed = UserPasswordPasswordUtil.composeUserPassword(parsedPassword, Encoding.HEX);
        assertEquals("{md5}166cd90440d36bec262f8ba3867ad646", new String(composed, StandardCharsets.UTF_8));
    }

    @Test
    public void testSha1() throws Exception {
        byte[] orig = "{sha}tESsBmE/yNY3lb6a0L6vVQEZNqw=".getBytes(StandardCharsets.UTF_8);
        SimpleDigestPassword parsedPassword = (SimpleDigestPassword) UserPasswordPasswordUtil.parseUserPassword(orig);
        assertEquals(SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_SHA_1, parsedPassword.getAlgorithm());

        byte[] composed = UserPasswordPasswordUtil.composeUserPassword(parsedPassword);
        assertEquals("{sha}tESsBmE/yNY3lb6a0L6vVQEZNqw=", new String(composed, StandardCharsets.UTF_8));
    }

    @Test
    public void testSha1HexEncoded() throws Exception {
        byte[] orig = "{sha}b444ac06613fc8d63795be9ad0beaf55011936ac".getBytes(StandardCharsets.UTF_8);
        SimpleDigestPassword parsedPassword = (SimpleDigestPassword) UserPasswordPasswordUtil.parseUserPassword(orig, Encoding.HEX);
        assertEquals(SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_SHA_1, parsedPassword.getAlgorithm());

        byte[] composed = UserPasswordPasswordUtil.composeUserPassword(parsedPassword, Encoding.HEX);
        assertEquals("{sha}b444ac06613fc8d63795be9ad0beaf55011936ac", new String(composed, StandardCharsets.UTF_8));
    }

    @Test
    public void testSha256() throws Exception {
        byte[] orig = "{sha256}5en6G6MezRroT3XKqkdPOmY/BfQ=".getBytes(StandardCharsets.UTF_8);
        SimpleDigestPassword parsedPassword = (SimpleDigestPassword) UserPasswordPasswordUtil.parseUserPassword(orig);
        assertEquals(SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_SHA_256, parsedPassword.getAlgorithm());

        byte[] composed = UserPasswordPasswordUtil.composeUserPassword(parsedPassword);
        assertEquals("{sha256}5en6G6MezRroT3XKqkdPOmY/BfQ=", new String(composed, StandardCharsets.UTF_8));
    }

    @Test
    public void testSha256HexEncoded() throws Exception {
        byte[] orig = "{sha256}e5e9fa1ba31ecd1ae84f75caaa474f3a663f05f4".getBytes(StandardCharsets.UTF_8);
        SimpleDigestPassword parsedPassword = (SimpleDigestPassword) UserPasswordPasswordUtil.parseUserPassword(orig, Encoding.HEX);
        assertEquals(SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_SHA_256, parsedPassword.getAlgorithm());

        byte[] composed = UserPasswordPasswordUtil.composeUserPassword(parsedPassword, Encoding.HEX);
        assertEquals("{sha256}e5e9fa1ba31ecd1ae84f75caaa474f3a663f05f4", new String(composed, StandardCharsets.UTF_8));
    }

    @Test
    public void testSha384() throws Exception {
        byte[] orig = "{sha384}5en6G6MezRroT3XKqkdPOmY/BfQ=".getBytes(StandardCharsets.UTF_8);
        SimpleDigestPassword parsedPassword = (SimpleDigestPassword) UserPasswordPasswordUtil.parseUserPassword(orig);
        assertEquals(SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_SHA_384, parsedPassword.getAlgorithm());

        byte[] composed = UserPasswordPasswordUtil.composeUserPassword(parsedPassword);
        assertEquals("{sha384}5en6G6MezRroT3XKqkdPOmY/BfQ=", new String(composed, StandardCharsets.UTF_8));
    }

    @Test
    public void testSha384HexEncoded() throws Exception {
        byte[] orig = "{sha384}e5e9fa1ba31ecd1ae84f75caaa474f3a663f05f4".getBytes(StandardCharsets.UTF_8);
        SimpleDigestPassword parsedPassword = (SimpleDigestPassword) UserPasswordPasswordUtil.parseUserPassword(orig, Encoding.HEX);
        assertEquals(SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_SHA_384, parsedPassword.getAlgorithm());

        byte[] composed = UserPasswordPasswordUtil.composeUserPassword(parsedPassword, Encoding.HEX);
        assertEquals("{sha384}e5e9fa1ba31ecd1ae84f75caaa474f3a663f05f4", new String(composed, StandardCharsets.UTF_8));
    }

    @Test
    public void testSha512() throws Exception {
        byte[] orig = "{sha512}5en6G6MezRroT3XKqkdPOmY/BfQ=".getBytes(StandardCharsets.UTF_8);
        SimpleDigestPassword parsedPassword = (SimpleDigestPassword) UserPasswordPasswordUtil.parseUserPassword(orig);
        assertEquals(SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_SHA_512, parsedPassword.getAlgorithm());

        byte[] composed = UserPasswordPasswordUtil.composeUserPassword(parsedPassword);
        assertEquals("{sha512}5en6G6MezRroT3XKqkdPOmY/BfQ=", new String(composed, StandardCharsets.UTF_8));
    }

    @Test
    public void testSha512HexEncoded() throws Exception {
        byte[] orig = "{sha512}e5e9fa1ba31ecd1ae84f75caaa474f3a663f05f4".getBytes(StandardCharsets.UTF_8);
        SimpleDigestPassword parsedPassword = (SimpleDigestPassword) UserPasswordPasswordUtil.parseUserPassword(orig, Encoding.HEX);
        assertEquals(SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_SHA_512, parsedPassword.getAlgorithm());

        byte[] composed = UserPasswordPasswordUtil.composeUserPassword(parsedPassword, Encoding.HEX);
        assertEquals("{sha512}e5e9fa1ba31ecd1ae84f75caaa474f3a663f05f4", new String(composed, StandardCharsets.UTF_8));
    }

    @Test
    public void testSaltedMd5() throws Exception {
        byte[] orig = "{smd5}i1GhUWtlHIva18fyzSVoSi6pLqk=".getBytes(StandardCharsets.UTF_8);
        Password parsedPassword = UserPasswordPasswordUtil.parseUserPassword(orig);
        assertEquals(SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_MD5, parsedPassword.getAlgorithm());

        byte[] composed = UserPasswordPasswordUtil.composeUserPassword(parsedPassword);
        assertEquals("{smd5}i1GhUWtlHIva18fyzSVoSi6pLqk=", new String(composed, StandardCharsets.UTF_8));
    }

    @Test
    public void testSaltedMd5HexEncoded() throws Exception {
        byte[] orig = "{smd5}8b51a1516b651c8bdad7c7f2cd25684a2ea92ea9".getBytes(StandardCharsets.UTF_8);
        Password parsedPassword = UserPasswordPasswordUtil.parseUserPassword(orig, Encoding.HEX);
        assertEquals(SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_MD5, parsedPassword.getAlgorithm());

        byte[] composed = UserPasswordPasswordUtil.composeUserPassword(parsedPassword, Encoding.HEX);
        assertEquals("{smd5}8b51a1516b651c8bdad7c7f2cd25684a2ea92ea9", new String(composed, StandardCharsets.UTF_8));
    }

    @Test
    public void testSaltedSha1() throws Exception {
        byte[] orig = "{ssha}uWg1PmLHZsZUqGOncZBiRTNXE3uHSyGC".getBytes(StandardCharsets.UTF_8);
        Password parsedPassword = UserPasswordPasswordUtil.parseUserPassword(orig);
        assertEquals(SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_SHA_1, parsedPassword.getAlgorithm());

        byte[] composed = UserPasswordPasswordUtil.composeUserPassword(parsedPassword);
        assertEquals("{ssha}uWg1PmLHZsZUqGOncZBiRTNXE3uHSyGC", new String(composed, StandardCharsets.UTF_8));
    }

    @Test
    public void testSaltedSha1HexEncoded() throws Exception {
        byte[] orig = "{ssha}b968353e62c766c654a863a7719062453357137b874b2182".getBytes(StandardCharsets.UTF_8);
        Password parsedPassword = UserPasswordPasswordUtil.parseUserPassword(orig, Encoding.HEX);
        assertEquals(SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_SHA_1, parsedPassword.getAlgorithm());

        byte[] composed = UserPasswordPasswordUtil.composeUserPassword(parsedPassword, Encoding.HEX);
        assertEquals("{ssha}b968353e62c766c654a863a7719062453357137b874b2182", new String(composed, StandardCharsets.UTF_8));
    }

    @Test
    public void testSaltedSha256() throws Exception {
        byte[] orig = "{ssha256}NnbD5ZmBpVlY8Ice+uANuNGP30AOiGvFIo8uMJAQZfCGasvDn2F6BQ==".getBytes(StandardCharsets.UTF_8);
        Password parsedPassword = UserPasswordPasswordUtil.parseUserPassword(orig);
        assertEquals(SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_SHA_256, parsedPassword.getAlgorithm());

        byte[] composed = UserPasswordPasswordUtil.composeUserPassword(parsedPassword);
        assertEquals("{ssha256}NnbD5ZmBpVlY8Ice+uANuNGP30AOiGvFIo8uMJAQZfCGasvDn2F6BQ==", new String(composed, StandardCharsets.UTF_8));
    }

    @Test
    public void testSaltedSha256HexEncoded() throws Exception {
        byte[] orig = "{ssha256}3676c3e59981a55958f0871efae00db8d18fdf400e886bc5228f2e30901065f0866acbc39f617a05".getBytes(StandardCharsets.UTF_8);
        Password parsedPassword = UserPasswordPasswordUtil.parseUserPassword(orig, Encoding.HEX);
        assertEquals(SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_SHA_256, parsedPassword.getAlgorithm());

        byte[] composed = UserPasswordPasswordUtil.composeUserPassword(parsedPassword, Encoding.HEX);
        assertEquals("{ssha256}3676c3e59981a55958f0871efae00db8d18fdf400e886bc5228f2e30901065f0866acbc39f617a05", new String(composed, StandardCharsets.UTF_8));
    }

    @Test
    public void testSaltedSha384() throws Exception {
        byte[] orig = "{ssha384}q3/C06GNWsP0pJRZU+a+rFwY9zbzbvY04IQP0SVneH88YohMYkT3BNda+LgjTKgTP3sKZZP6fAU=".getBytes(StandardCharsets.UTF_8);
        Password parsedPassword = UserPasswordPasswordUtil.parseUserPassword(orig);
        assertEquals(SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_SHA_384, parsedPassword.getAlgorithm());

        byte[] composed = UserPasswordPasswordUtil.composeUserPassword(parsedPassword);
        assertEquals("{ssha384}q3/C06GNWsP0pJRZU+a+rFwY9zbzbvY04IQP0SVneH88YohMYkT3BNda+LgjTKgTP3sKZZP6fAU=", new String(composed, StandardCharsets.UTF_8));
    }

    @Test
    public void testSaltedSha384HexEncoded() throws Exception {
        byte[] orig = "{ssha384}ab7fc2d3a18d5ac3f4a4945953e6beac5c18f736f36ef634e0840fd12567787f3c62884c6244f704d75af8b8234ca8133f7b0a6593fa7c05".getBytes(StandardCharsets.UTF_8);
        Password parsedPassword = UserPasswordPasswordUtil.parseUserPassword(orig, Encoding.HEX);
        assertEquals(SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_SHA_384, parsedPassword.getAlgorithm());

        byte[] composed = UserPasswordPasswordUtil.composeUserPassword(parsedPassword, Encoding.HEX);
        assertEquals("{ssha384}ab7fc2d3a18d5ac3f4a4945953e6beac5c18f736f36ef634e0840fd12567787f3c62884c6244f704d75af8b8234ca8133f7b0a6593fa7c05", new String(composed, StandardCharsets.UTF_8));
    }

    @Test
    public void testSaltedSha512() throws Exception {
        byte[] orig = "{ssha512}j3i1SgOox/ShzZiMIhTj6EGN7kHvq1TehRVf7YIQXuo7GwradZKGCdmEcy8qCZsUaI+4iPkzbsYjcT8L/yFq+D+GCB4lHEF5".getBytes(StandardCharsets.UTF_8);
        Password parsedPassword = UserPasswordPasswordUtil.parseUserPassword(orig);
        assertEquals(SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_SHA_512, parsedPassword.getAlgorithm());

        byte[] composed = UserPasswordPasswordUtil.composeUserPassword(parsedPassword);
        assertEquals("{ssha512}j3i1SgOox/ShzZiMIhTj6EGN7kHvq1TehRVf7YIQXuo7GwradZKGCdmEcy8qCZsUaI+4iPkzbsYjcT8L/yFq+D+GCB4lHEF5", new String(composed, StandardCharsets.UTF_8));
    }

    @Test
    public void testSaltedSha512HexEncoded() throws Exception {
        byte[] orig = "{ssha512}8f78b54a03a8c7f4a1cd988c2214e3e8418dee41efab54de85155fed82105eea3b1b0ada75928609d984732f2a099b14688fb888f9336ec623713f0bff216af83f86081e251c4179".getBytes(StandardCharsets.UTF_8);
        Password parsedPassword = UserPasswordPasswordUtil.parseUserPassword(orig, Encoding.HEX);
        assertEquals(SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_SHA_512, parsedPassword.getAlgorithm());

        byte[] composed = UserPasswordPasswordUtil.composeUserPassword(parsedPassword, Encoding.HEX);
        assertEquals("{ssha512}8f78b54a03a8c7f4a1cd988c2214e3e8418dee41efab54de85155fed82105eea3b1b0ada75928609d984732f2a099b14688fb888f9336ec623713f0bff216af83f86081e251c4179", new String(composed, StandardCharsets.UTF_8));
    }

    @Test
    public void testUnixDesCrypt() throws Exception {
        byte[] orig = "{crypt}k8d0CodT.v5Nw".getBytes(StandardCharsets.UTF_8);
        UnixDESCryptPassword parsedPassword = (UnixDESCryptPassword) UserPasswordPasswordUtil.parseUserPassword(orig);
        assertEquals(UnixDESCryptPassword.ALGORITHM_CRYPT_DES, parsedPassword.getAlgorithm());

        byte[] composed = UserPasswordPasswordUtil.composeUserPassword(parsedPassword);
        assertEquals("{crypt}k8d0CodT.v5Nw", new String(composed, StandardCharsets.UTF_8));
    }

    @Test
    public void testBsdDesCrypt() throws Exception {
        byte[] orig = "{crypt}_N.../TTpyByTVvdmWGo".getBytes(StandardCharsets.UTF_8);
        BSDUnixDESCryptPassword parsedPassword = (BSDUnixDESCryptPassword) UserPasswordPasswordUtil.parseUserPassword(orig);
        assertEquals(BSDUnixDESCryptPassword.ALGORITHM_BSD_CRYPT_DES, parsedPassword.getAlgorithm());

        byte[] composed = UserPasswordPasswordUtil.composeUserPassword(parsedPassword);
        assertEquals("{crypt}_N.../TTpyByTVvdmWGo", new String(composed, StandardCharsets.UTF_8));
    }

}
