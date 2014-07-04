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

import org.junit.Ignore;
import org.junit.Test;
import org.wildfly.security.password.Password;

import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import org.wildfly.security.password.interfaces.UnixSHACryptPassword;

/**
 * @author <a href="mailto:jpkroehling.javadoc@redhat.com">Juraci Paixão Kröhling</a>
 */
public class UnixSHACryptPasswordUtilTest {

    @Test
    public void shouldParseSpecWithoutRounds() throws NoSuchAlgorithmException {
        String result = new String(UnixSHACryptPasswordUtil.encode("$6$saltstring", "".getBytes()));
        assertTrue("Didn't parse the ID correctly", result.startsWith("$6$"));
        assertTrue("Didn't parse the salt correctly", result.startsWith("$6$saltstring$"));
    }

    @Test
    public void shouldParseSpecWithRounds() throws NoSuchAlgorithmException {
        String result = new String(UnixSHACryptPasswordUtil.encode("$6$rounds=10000$saltstring", "".getBytes()));
        assertTrue("Didn't parse the number of rounds correctly", result.startsWith("$6$rounds=10000$saltstring$"));
    }

    @Test
    public void shouldTruncateSaltAt16Chars() throws NoSuchAlgorithmException {
        String result = new String(UnixSHACryptPasswordUtil.encode("$6$rounds=5000$toolongsaltstring", "".getBytes()));
        assertTrue("Didn't parse the number of rounds correctly", result.startsWith("$6$rounds=5000$toolongsaltstrin$"));
    }

    @Test
    public void shouldIncreaseIterationCountIfLowerThan1000() throws NoSuchAlgorithmException {
        String result = new String(UnixSHACryptPasswordUtil.encode("$6$rounds=10$roundstoolow", "".getBytes()));
        assertTrue("Didn't increase the number of rounds", result.startsWith("$6$rounds=1000$roundstoolow"));
    }

    @Test
    @Ignore("The way it currently works, this would really hash the password and it would take a really long time.")
    public void shouldDecreaseIterationCountIfBiggerThan999999999() throws NoSuchAlgorithmException {
        // this test is being kept as a way to mark that this behavior is intended, but it's not tested with the
        // usual tests because it would run the hashing with 999,999,999 iterations
        String result = new String(UnixSHACryptPasswordUtil.encode("$6$rounds=1000000000$roundstoobig", "".getBytes()));
        assertTrue("Didn't decrease the number of rounds", result.startsWith("$6$rounds=999999999$roundstoobig"));
    }

    @Test(expected=IllegalArgumentException.class)
    public void shouldRejectInvalidId() throws NoSuchAlgorithmException {
        UnixSHACryptPasswordUtil.encode("$8$rounds=10000$saltstring", "".getBytes());
    }

    @Test(expected=IllegalArgumentException.class)
    public void shouldRejectInvalidIdStartingWithValidChar() throws NoSuchAlgorithmException {
        UnixSHACryptPasswordUtil.encode("$68$rounds=10000$saltstring", "".getBytes());
    }

    @Test(expected=IllegalArgumentException.class)
    public void shouldRejectIncompleteSpecification() throws NoSuchAlgorithmException {
        UnixSHACryptPasswordUtil.encode("$6$", "".getBytes());
    }

    @Test(expected=IllegalArgumentException.class)
    public void shouldRejectEmptySpecification() throws NoSuchAlgorithmException {
        UnixSHACryptPasswordUtil.encode("$$", "".getBytes());
    }

    @Test
    public void shouldVerifyOnMatchingHashes() throws UnsupportedEncodingException, NoSuchAlgorithmException {
        Charset charset = Charset.forName("UTF-8");
        byte[] salt = "saltstringsaltstring".getBytes(charset);
        byte[] encoded = "$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA".getBytes(charset);
        Password password = new UnixSHACryptPasswordImpl(salt, 10000, UnixSHACryptPassword.ALGORITHM_SHA256CRYPT, encoded);
        assertTrue(UnixSHACryptPasswordUtil.verify(password, "Hello world!".toCharArray()));
    }

    @Test
    public void shouldNotVerifyOnNonMatchingHashes() {

    }

    @Test
    public void shouldPassAllCasesFromSpecForSha256() throws NoSuchAlgorithmException {
        Charset charset = Charset.forName("UTF-8");
        assertEquals(
                "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5",
                new String(UnixSHACryptPasswordUtil.encode("$5$saltstring", "Hello world!".getBytes(charset)))
        );

        assertEquals(
                "$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA",
                new String(UnixSHACryptPasswordUtil.encode("$5$rounds=10000$saltstringsaltstring", "Hello world!".getBytes(charset)))
        );

        assertEquals(
                "$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA",
                new String(UnixSHACryptPasswordUtil.encode('5', "saltstringsaltstring".getBytes(charset), 10000, "Hello world!".getBytes(charset)))
        );

        assertEquals(
                "$5$rounds=5000$toolongsaltstrin$Un/5jzAHMgOGZ5.mWJpuVolil07guHPvOW8mGRcvxa5",
                new String(UnixSHACryptPasswordUtil.encode("$5$rounds=5000$toolongsaltstring", "This is just a test".getBytes(charset)))
        );

        assertEquals(
                "$5$rounds=1400$anotherlongsalts$Rx.j8H.h8HjEDGomFU8bDkXm3XIUnzyxf12oP84Bnq1",
                new String(UnixSHACryptPasswordUtil.encode("$5$rounds=1400$anotherlongsaltstring", "a very much longer text to encrypt.  This one even stretches over morethan one line.".getBytes(charset)))
        );

        assertEquals(
                "$5$rounds=77777$short$JiO1O3ZpDAxGJeaDIuqCoEFysAe1mZNJRs3pw0KQRd/",
                new String(UnixSHACryptPasswordUtil.encode("$5$rounds=77777$short", "we have a short salt string but not a short password".getBytes(charset)))
        );

        assertEquals(
                "$5$rounds=123456$asaltof16chars..$gP3VQ/6X7UUEW3HkBn2w1/Ptq2jxPyzV/cZKmF/wJvD",
                new String(UnixSHACryptPasswordUtil.encode("$5$rounds=123456$asaltof16chars..", "a short string".getBytes(charset)))
        );

        assertEquals(
                "$5$rounds=1000$roundstoolow$yfvwcWrQ8l/K0DAWyuPMDNHpIVlTQebY9l/gL972bIC",
                new String(UnixSHACryptPasswordUtil.encode("$5$rounds=10$roundstoolow", "the minimum number is still observed".getBytes(charset)))
        );
    }

    @Test
    public void shouldPassAllCasesFromSpecForSha512() throws NoSuchAlgorithmException {
        Charset charset = Charset.forName("UTF-8");
        assertEquals(
                "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1",
                new String(UnixSHACryptPasswordUtil.encode("$6$saltstring", "Hello world!".getBytes(charset)))
        );

        assertEquals(
                "$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v.",
                new String(UnixSHACryptPasswordUtil.encode("$6$rounds=10000$saltstringsaltstring", "Hello world!".getBytes(charset)))
        );

        assertEquals(
                "$6$rounds=5000$toolongsaltstrin$lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQzQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0",
                new String(UnixSHACryptPasswordUtil.encode("$6$rounds=5000$toolongsaltstring", "This is just a test".getBytes(charset)))
        );

        assertEquals(
                "$6$rounds=1400$anotherlongsalts$POfYwTEok97VWcjxIiSOjiykti.o/pQs.wPvMxQ6Fm7I6IoYN3CmLs66x9t0oSwbtEW7o7UmJEiDwGqd8p4ur1",
                new String(UnixSHACryptPasswordUtil.encode("$6$rounds=1400$anotherlongsaltstring", "a very much longer text to encrypt.  This one even stretches over morethan one line.".getBytes(charset)))
        );

        assertEquals(
                "$6$rounds=77777$short$WuQyW2YR.hBNpjjRhpYD/ifIw05xdfeEyQoMxIXbkvr0gge1a1x3yRULJ5CCaUeOxFmtlcGZelFl5CxtgfiAc0",
                new String(UnixSHACryptPasswordUtil.encode("$6$rounds=77777$short", "we have a short salt string but not a short password".getBytes(charset)))
        );

        assertEquals(
                "$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwcelCjmw2kSYu.Ec6ycULevoBK25fs2xXgMNrCzIMVcgEJAstJeonj1",
                new String(UnixSHACryptPasswordUtil.encode("$6$rounds=123456$asaltof16chars..", "a short string".getBytes(charset)))
        );

        assertEquals(
                "$6$rounds=1000$roundstoolow$kUMsbe306n21p9R.FRkW3IGn.S9NPN0x50YhH1xhLsPuWGsUSklZt58jaTfF4ZEQpyUNGc0dqbpBYYBaHHrsX.",
                new String(UnixSHACryptPasswordUtil.encode("$6$rounds=10$roundstoolow", "the minimum number is still observed".getBytes(charset)))
        );
    }

}
