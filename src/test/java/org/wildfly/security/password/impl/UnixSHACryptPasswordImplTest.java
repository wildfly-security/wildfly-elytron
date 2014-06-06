package org.wildfly.security.password.impl;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

/**
 * @author <a href="mailto:jpkroehling.javadoc@redhat.com">Juraci Paixão Kröhling</a>
 */
public class UnixSHACryptPasswordImplTest {

    @Test
    public void shouldParseSpecWithoutRounds() {
        UnixSHACryptPasswordImpl password = new UnixSHACryptPasswordImpl("$6$saltstring", "".getBytes());
        assertEquals("Didn't parse the salt correctly", "saltstring", new String(password.getSalt()));
        assertEquals("Didn't parse the ID correctly", '6', password.getId());
    }

    @Test
    public void shouldParseSpecWithRounds() {
        UnixSHACryptPasswordImpl password = new UnixSHACryptPasswordImpl("$6$rounds=10000$saltstring", "".getBytes());
        assertEquals("Didn't parse the salt correctly", "saltstring", new String(password.getSalt()));
        assertEquals("Didn't parse the ID correctly", '6', password.getId());
        assertEquals("Didn't parse the number of rounds correctly", 10000, password.getIterationCount());
    }

    @Test
    public void shouldTruncateSaltAt16Chars() {
        UnixSHACryptPasswordImpl password = new UnixSHACryptPasswordImpl("$6$rounds=5000$toolongsaltstring", "".getBytes());
        assertEquals("Didn't parse the salt correctly", "toolongsaltstrin", new String(password.getSalt()));
        assertEquals("Didn't parse the ID correctly", '6', password.getId());
        assertEquals("Didn't parse the number of rounds correctly", 5000, password.getIterationCount());
    }

    @Test
    public void shouldIncreaseIterationCountIfLowerThan1000() {
        UnixSHACryptPasswordImpl password = new UnixSHACryptPasswordImpl("$6$rounds=10$roundstoolow", "".getBytes());
        assertEquals("Didn't parse the salt correctly", "roundstoolow", new String(password.getSalt()));
        assertEquals("Didn't parse the ID correctly", '6', password.getId());
        assertEquals("Didn't parse the number of rounds correctly", 1000, password.getIterationCount());
    }

    @Test
    public void shouldDecreaseIterationCountIfBiggerThan999999999() {
        UnixSHACryptPasswordImpl password = new UnixSHACryptPasswordImpl("$6$rounds=1000000000$roundstoobig", "".getBytes());
        assertEquals("Didn't parse the salt correctly", "roundstoobig", new String(password.getSalt()));
        assertEquals("Didn't parse the ID correctly", '6', password.getId());
        assertEquals("Didn't parse the number of rounds correctly", 999999999, password.getIterationCount());
    }

    @Test(expected=IllegalArgumentException.class)
    public void shouldRejectInvalidId() {
        new UnixSHACryptPasswordImpl("$8$rounds=10000$saltstring", "".getBytes());
    }

    @Test(expected=IllegalArgumentException.class)
    public void shouldRejectInvalidIdStartingWithValidChar() {
        new UnixSHACryptPasswordImpl("$68$rounds=10000$saltstring", "".getBytes());
    }

    @Test(expected=IllegalArgumentException.class)
    public void shouldRejectIncompleteSpecification() {
        new UnixSHACryptPasswordImpl("$6$", "".getBytes());
    }

    @Test(expected=IllegalArgumentException.class)
    public void shouldRejectEmptySpecification() {
        new UnixSHACryptPasswordImpl("$$", "".getBytes());
    }

    @Test
    public void shouldPassAllCasesFromSpecForSha256() {
        assertEquals(
                "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5",
                new String(new UnixSHACryptPasswordImpl("$5$saltstring", "Hello world!".getBytes()).getEncoded())
        );

        assertEquals(
                "$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA",
                new String(new UnixSHACryptPasswordImpl("$5$rounds=10000$saltstringsaltstring", "Hello world!".getBytes()).getEncoded())
        );

        assertEquals(
                "$5$rounds=5000$toolongsaltstrin$Un/5jzAHMgOGZ5.mWJpuVolil07guHPvOW8mGRcvxa5",
                new String(new UnixSHACryptPasswordImpl("$5$rounds=5000$toolongsaltstring", "This is just a test".getBytes()).getEncoded())
        );

        assertEquals(
                "$5$rounds=1400$anotherlongsalts$Rx.j8H.h8HjEDGomFU8bDkXm3XIUnzyxf12oP84Bnq1",
                new String(new UnixSHACryptPasswordImpl("$5$rounds=1400$anotherlongsaltstring", "a very much longer text to encrypt.  This one even stretches over morethan one line.".getBytes()).getEncoded())
        );

        assertEquals(
                "$5$rounds=77777$short$JiO1O3ZpDAxGJeaDIuqCoEFysAe1mZNJRs3pw0KQRd/",
                new String(new UnixSHACryptPasswordImpl("$5$rounds=77777$short", "we have a short salt string but not a short password".getBytes()).getEncoded())
        );

        assertEquals(
                "$5$rounds=123456$asaltof16chars..$gP3VQ/6X7UUEW3HkBn2w1/Ptq2jxPyzV/cZKmF/wJvD",
                new String(new UnixSHACryptPasswordImpl("$5$rounds=123456$asaltof16chars..", "a short string".getBytes()).getEncoded())
        );

        assertEquals(
                "$5$rounds=1000$roundstoolow$yfvwcWrQ8l/K0DAWyuPMDNHpIVlTQebY9l/gL972bIC",
                new String(new UnixSHACryptPasswordImpl("$5$rounds=10$roundstoolow", "the minimum number is still observed".getBytes()).getEncoded())
        );
    }

    @Test
    public void shouldPassAllCasesFromSpecForSha512() {
        assertEquals(
                "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1",
                new String(new UnixSHACryptPasswordImpl("$6$saltstring", "Hello world!".getBytes()).getEncoded())
        );

        assertEquals(
                "$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v.",
                new String(new UnixSHACryptPasswordImpl("$6$rounds=10000$saltstringsaltstring", "Hello world!".getBytes()).getEncoded())
        );

        assertEquals(
                "$6$rounds=5000$toolongsaltstrin$lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQzQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0",
                new String(new UnixSHACryptPasswordImpl("$6$rounds=5000$toolongsaltstring", "This is just a test".getBytes()).getEncoded())
        );

        assertEquals(
                "$6$rounds=1400$anotherlongsalts$POfYwTEok97VWcjxIiSOjiykti.o/pQs.wPvMxQ6Fm7I6IoYN3CmLs66x9t0oSwbtEW7o7UmJEiDwGqd8p4ur1",
                new String(new UnixSHACryptPasswordImpl("$6$rounds=1400$anotherlongsaltstring", "a very much longer text to encrypt.  This one even stretches over morethan one line.".getBytes()).getEncoded())
        );

        assertEquals(
                "$6$rounds=77777$short$WuQyW2YR.hBNpjjRhpYD/ifIw05xdfeEyQoMxIXbkvr0gge1a1x3yRULJ5CCaUeOxFmtlcGZelFl5CxtgfiAc0",
                new String(new UnixSHACryptPasswordImpl("$6$rounds=77777$short", "we have a short salt string but not a short password".getBytes()).getEncoded())
        );

        assertEquals(
                "$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwcelCjmw2kSYu.Ec6ycULevoBK25fs2xXgMNrCzIMVcgEJAstJeonj1",
                new String(new UnixSHACryptPasswordImpl("$6$rounds=123456$asaltof16chars..", "a short string".getBytes()).getEncoded())
        );

        assertEquals(
                "$6$rounds=1000$roundstoolow$kUMsbe306n21p9R.FRkW3IGn.S9NPN0x50YhH1xhLsPuWGsUSklZt58jaTfF4ZEQpyUNGc0dqbpBYYBaHHrsX.",
                new String(new UnixSHACryptPasswordImpl("$6$rounds=10$roundstoolow", "the minimum number is still observed".getBytes()).getEncoded())
        );
    }

}
