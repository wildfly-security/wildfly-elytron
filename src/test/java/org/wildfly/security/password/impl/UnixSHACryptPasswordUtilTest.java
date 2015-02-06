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

package org.wildfly.security.password.impl;

import org.junit.Test;
import org.wildfly.security.password.Password;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.wildfly.security.password.interfaces.UnixSHACryptPassword.ALGORITHM_CRYPT_SHA_256;
import static org.wildfly.security.password.interfaces.UnixSHACryptPassword.ALGORITHM_CRYPT_SHA_512;

import org.wildfly.security.password.PasswordUtil;
import org.wildfly.security.password.interfaces.UnixSHACryptPassword;
import org.wildfly.security.password.spec.EncryptablePasswordSpec;
import org.wildfly.security.password.spec.HashedPasswordAlgorithmSpec;
import org.wildfly.security.password.spec.PasswordSpec;
import org.wildfly.security.password.spec.UnixSHACryptPasswordSpec;

/**
 * @author <a href="mailto:jpkroehling.javadoc@redhat.com">Juraci Paixão Kröhling</a>
 */
@SuppressWarnings("SpellCheckingInspection")
public class UnixSHACryptPasswordUtilTest {

    @Test
    public void shouldParseSpecWithoutRounds() throws NoSuchAlgorithmException, InvalidKeySpecException {
        assertEquals("Didn't parse the number of rounds correctly", 5_000, ((UnixSHACryptPasswordSpec) PasswordUtil.parseCryptString("$6$toolongsaltstrin$0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")).getIterationCount());
    }

    @Test
    public void shouldParseSpecWithRounds() throws NoSuchAlgorithmException, InvalidKeySpecException {
        assertEquals("Didn't parse the number of rounds correctly", 10_000, ((UnixSHACryptPasswordSpec) PasswordUtil.parseCryptString("$6$rounds=10000$saltstring$0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")).getIterationCount());
    }

    @Test
    public void shouldTruncateSaltAt16Chars() throws NoSuchAlgorithmException, InvalidKeySpecException {
        assertEquals("Didn't parse the number of rounds correctly", 5_000, ((UnixSHACryptPasswordSpec) PasswordUtil.parseCryptString("$6$rounds=5000$toolongsaltstrin$0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")).getIterationCount());
    }

    @Test
    public void shouldIncreaseIterationCountIfLowerThan1000() throws NoSuchAlgorithmException, InvalidKeySpecException {
        assertEquals("Didn't increase the number of rounds", 1_000, ((UnixSHACryptPasswordSpec) PasswordUtil.parseCryptString("$6$rounds=10$roundstoobig$0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")).getIterationCount());
    }

    @Test
    public void shouldDecreaseIterationCountIfBiggerThan999999999() throws NoSuchAlgorithmException, InvalidKeySpecException {
        // this test is being kept as a way to mark that this behavior is intended, but it's not tested with the
        // usual tests because it would run the hashing with 999,999,999 iterations
        assertEquals("Didn't decrease the number of rounds", 999_999_999, ((UnixSHACryptPasswordSpec) PasswordUtil.parseCryptString("$6$rounds=1000000000$roundstoobig$0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")).getIterationCount());
    }

    @Test
    public void shouldVerifyOnMatchingHashes() throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {
        String cryptString = "$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA";
        final PasswordFactorySpiImpl factorySpi = new PasswordFactorySpiImpl();
        final PasswordSpec parsed = PasswordUtil.parseCryptString(cryptString);
        assertEquals(cryptString, PasswordUtil.getCryptString(parsed));
        UnixSHACryptPassword password = (UnixSHACryptPassword) factorySpi.engineGeneratePassword(PasswordUtil.identifyAlgorithm(cryptString), parsed);
        final String algorithm = password.getAlgorithm();
        UnixSHACryptPassword comparePassword = (UnixSHACryptPassword) factorySpi.engineGeneratePassword(algorithm, new EncryptablePasswordSpec("Hello world!".toCharArray(), new HashedPasswordAlgorithmSpec(10000, password.getSalt())));
        assertEquals(cryptString, PasswordUtil.getCryptString(factorySpi.engineGetKeySpec(algorithm, comparePassword, UnixSHACryptPasswordSpec.class)));
        assertEquals(password.getIterationCount(), comparePassword.getIterationCount());
        assertArrayEquals(password.getSalt(), comparePassword.getSalt());
        assertArrayEquals(password.getHash(), comparePassword.getHash());
        assertTrue(factorySpi.engineVerify(algorithm, password, "Hello world!".toCharArray()));
    }

    @Test
    public void shouldNotVerifyOnNonMatchingHashes() {

    }

    private String generate(String alg, String salt, String passwd, int iterationCount) throws InvalidKeySpecException {
        final PasswordFactorySpiImpl spi = new PasswordFactorySpiImpl();
        final Password password = spi.engineGeneratePassword(alg, new EncryptablePasswordSpec(passwd.toCharArray(), new HashedPasswordAlgorithmSpec(iterationCount, salt.getBytes(UTF_8))));
        return PasswordUtil.getCryptString(spi.engineGetKeySpec(alg, password, UnixSHACryptPasswordSpec.class));
    }

    @Test
    public void shouldPassAllCasesFromSpecForSha256() throws NoSuchAlgorithmException, InvalidKeySpecException {
        assertEquals(
                "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5",
                generate(ALGORITHM_CRYPT_SHA_256, "saltstring", "Hello world!", 5_000)
        );

        assertEquals(
                "$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA",
                generate(ALGORITHM_CRYPT_SHA_256, "saltstringsaltstring", "Hello world!", 10_000)
        );

        assertEquals(
                "$5$toolongsaltstrin$Un/5jzAHMgOGZ5.mWJpuVolil07guHPvOW8mGRcvxa5",
                generate(ALGORITHM_CRYPT_SHA_256, "toolongsaltstring", "This is just a test", 5_000)
        );

        assertEquals(
                "$5$rounds=1400$anotherlongsalts$Rx.j8H.h8HjEDGomFU8bDkXm3XIUnzyxf12oP84Bnq1",
                generate(ALGORITHM_CRYPT_SHA_256, "anotherlongsaltstring", "a very much longer text to encrypt.  This one even stretches over morethan one line.", 1_400)
        );

        assertEquals(
                "$5$rounds=77777$short$JiO1O3ZpDAxGJeaDIuqCoEFysAe1mZNJRs3pw0KQRd/",
                generate(ALGORITHM_CRYPT_SHA_256, "short", "we have a short salt string but not a short password", 77_777)
        );

        assertEquals(
                "$5$rounds=123456$asaltof16chars..$gP3VQ/6X7UUEW3HkBn2w1/Ptq2jxPyzV/cZKmF/wJvD",
                generate(ALGORITHM_CRYPT_SHA_256, "asaltof16chars..", "a short string", 123_456)
        );

        assertEquals(
                "$5$rounds=1000$roundstoolow$yfvwcWrQ8l/K0DAWyuPMDNHpIVlTQebY9l/gL972bIC",
                generate(ALGORITHM_CRYPT_SHA_256, "roundstoolow", "the minimum number is still observed", 10)
        );
    }

    @Test
    public void shouldPassAllCasesFromSpecForSha512() throws NoSuchAlgorithmException, InvalidKeySpecException {
        assertEquals(
                "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1",
                generate(ALGORITHM_CRYPT_SHA_512, "saltstring", "Hello world!", 5_000)
        );

        assertEquals(
                "$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v.",
                generate(ALGORITHM_CRYPT_SHA_512, "saltstringsaltstring", "Hello world!", 10_000)
        );

        assertEquals(
                "$6$toolongsaltstrin$lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQzQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0",
                generate(ALGORITHM_CRYPT_SHA_512, "toolongsaltstring", "This is just a test", 5_000)
        );

        assertEquals(
                "$6$rounds=1400$anotherlongsalts$POfYwTEok97VWcjxIiSOjiykti.o/pQs.wPvMxQ6Fm7I6IoYN3CmLs66x9t0oSwbtEW7o7UmJEiDwGqd8p4ur1",
                generate(ALGORITHM_CRYPT_SHA_512, "anotherlongsaltstring", "a very much longer text to encrypt.  This one even stretches over morethan one line.", 1_400)
        );

        assertEquals(
                "$6$rounds=77777$short$WuQyW2YR.hBNpjjRhpYD/ifIw05xdfeEyQoMxIXbkvr0gge1a1x3yRULJ5CCaUeOxFmtlcGZelFl5CxtgfiAc0",
                generate(ALGORITHM_CRYPT_SHA_512, "short", "we have a short salt string but not a short password", 77_777)
        );

        assertEquals(
                "$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwcelCjmw2kSYu.Ec6ycULevoBK25fs2xXgMNrCzIMVcgEJAstJeonj1",
                generate(ALGORITHM_CRYPT_SHA_512, "asaltof16chars..", "a short string", 123_456)
        );

        assertEquals(
                "$6$rounds=1000$roundstoolow$kUMsbe306n21p9R.FRkW3IGn.S9NPN0x50YhH1xhLsPuWGsUSklZt58jaTfF4ZEQpyUNGc0dqbpBYYBaHHrsX.",
                generate(ALGORITHM_CRYPT_SHA_512, "roundstoolow", "the minimum number is still observed", 10)
        );
    }

}
