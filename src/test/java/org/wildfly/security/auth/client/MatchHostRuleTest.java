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

package org.wildfly.security.auth.client;

import java.net.URI;
import java.net.URISyntaxException;

import org.junit.Assert;
import org.junit.Test;

/**
 * @author Tomas Hofman (thofman@redhat.com)
 */
public class MatchHostRuleTest {

    @Test
    public void testDomainNameMatching() throws URISyntaxException {
        Assert.assertTrue(MatchRule.ALL.matchHost("security.wildfly.org").matches(new URI("remote+http://security.wildfly.org:9990")));

        // prefixes or suffixes shouldn't match
        Assert.assertFalse(MatchRule.ALL.matchHost("security.wildfly").matches(new URI("remote+http://security.wildfly.org:9990")));
        Assert.assertFalse(MatchRule.ALL.matchHost("wildfly.org").matches(new URI("remote+http://security.wildfly.org:9990")));
    }

    @Test
    public void testInvalidDomainName() {
        assertHostSpecFails("security.wildfly.");
        assertHostSpecFails(".wildfly.org");
    }

    @Test
    public void testIPv4Matching() throws URISyntaxException {
        // equivalent IPv4 addresses should match
        Assert.assertTrue(MatchRule.ALL.matchHost("127.0.0.1").matches(new URI("remote+http://127.0.0.1:9990")));

        // shortened IPv4 addresses are not supported
        Assert.assertFalse(MatchRule.ALL.matchHost("127.1").matches(new URI("remote+http://127.0.0.1:9990")));
        Assert.assertFalse(MatchRule.ALL.matchHost("1").matches(new URI("remote+http://0.0.0.1:9990")));

        // prefixes shouldn't match
        Assert.assertFalse(MatchRule.ALL.matchHost("1.2.3.4").matches(new URI("remote+http://1.2.3.40:9990")));
        Assert.assertFalse(MatchRule.ALL.matchHost("1.2.30").matches(new URI("remote+http://1.2.30.1:9990")));
    }

    @Test
    public void testInvalidIPv4Spec() {
        assertHostSpecFails("1.2.3.");
        assertHostSpecFails("1.2.");
        assertHostSpecFails("1..3.4");
        assertHostSpecFails(".2.3.4");
    }

    @Test
    public void testIPv6Matching() throws URISyntaxException {
        // equivalent addresses should match
        Assert.assertTrue(MatchRule.ALL.matchHost("2001:db8:85a3:0:0:8a2e:370:7334").matches(new URI("remote+http://[2001:db8:85a3:0:0:8a2e:370:7334]:9990")));
        Assert.assertTrue(MatchRule.ALL.matchHost("2001:db8:85a3:0:0:8a2e:370:7334").matches(new URI("remote+http://[2001:db8:85a3::8a2e:370:7334]:9990")));
        Assert.assertTrue(MatchRule.ALL.matchHost("2001:db8:85a3::8a2e:370:7334").matches(new URI("remote+http://[2001:db8:85a3:0:0:8a2e:370:7334]:9990")));
        Assert.assertTrue(MatchRule.ALL.matchHost("2001:db8:85a3::8a2e:370:7334").matches(new URI("remote+http://[2001:db8:85a3::8a2e:370:7334]:9990")));
        Assert.assertTrue(MatchRule.ALL.matchHost("::1").matches(new URI("remote+http://[::1]:9990")));

        // IPv4 mapped IPv6 address
        Assert.assertTrue(MatchRule.ALL.matchHost("0:0:0:0:ffff:0:192.0.2.128").matches(new URI("remote+http://[0:0:0:0:ffff:0:192.0.2.128]:9990")));
        Assert.assertTrue(MatchRule.ALL.matchHost("0:0:0:0:ffff:0:192.0.2.128").matches(new URI("remote+http://[::ffff:0:192.0.2.128]:9990")));
        Assert.assertTrue(MatchRule.ALL.matchHost("::ffff:0:192.0.2.128").matches(new URI("remote+http://[0:0:0:0:ffff:0:192.0.2.128]:9990")));
        Assert.assertTrue(MatchRule.ALL.matchHost("::ffff:0:192.0.2.128").matches(new URI("remote+http://[::ffff:0:192.0.2.128]:9990")));

        // different case
        Assert.assertTrue(MatchRule.ALL.matchHost("::ffff:0:1").matches(new URI("remote+http://[0:0:0:0:0:FFFF:0:1]:9990")));
        Assert.assertTrue(MatchRule.ALL.matchHost("0:0:0:0:0:FFFF:0:1").matches(new URI("remote+http://[::ffff:0:1]:9990")));

        // brackets in the spec
        Assert.assertTrue(MatchRule.ALL.matchHost("[::1]").matches(new URI("remote+http://[::1]:9990")));

        // prefix mustn't match
        Assert.assertFalse(MatchRule.ALL.matchHost("2001:db8::1").matches(new URI("remote+http://[2001:db8::10]:9990")));
    }

    @Test
    public void testValidIPv6Specs() {
        // substitution at the end
        MatchRule.ALL.matchHost("1:2:3:4:5:6:7::");
        MatchRule.ALL.matchHost("1:2:3:4:5:6::");
        MatchRule.ALL.matchHost("1::");
        MatchRule.ALL.matchHost("::");

        // substitution at the begging
        MatchRule.ALL.matchHost("::2:3:4:5:6:7:8");
        MatchRule.ALL.matchHost("::4:5:6:7:8");
        MatchRule.ALL.matchHost("::1");

        // substitution in the middle
        MatchRule.ALL.matchHost("1::3:4:5:6:7:8");
        MatchRule.ALL.matchHost("1::4:5:6:7:8");
        MatchRule.ALL.matchHost("1::8");

        // mapped IPv4
        MatchRule.ALL.matchHost("::ffff:192.168.0.1");
        MatchRule.ALL.matchHost("::127.0.0.1");

        // no substitution
        MatchRule.ALL.matchHost("1:2:3:4:5:6:7:8");
        MatchRule.ALL.matchHost("1:2:3:4:5:6:192.0.0.1");
    }

    @Test
    public void testInvalidIPv6Spec() {
        assertHostSpecFails("::ffff:192.168.0.1:123"); // IPv4 in the middle
        assertHostSpecFails("2001:db8:85a3:0:0:8a2e:370:"); // missing segment
        assertHostSpecFails("2001:db8:85a3:0:0:8a2e:370"); // missing segment
        assertHostSpecFails("2001:db8:85a3:0:0:8a2e:370:123:"); // extra :
        assertHostSpecFails("::12345:f"); // too long number
        assertHostSpecFails("::ffff:x"); // not a hex digit
        assertHostSpecFails("1::ffff::f"); // multiple substitutions
        assertHostSpecFails("1:::f");

        // invalid IPv4 segment
        assertHostSpecFails("::ffff:192.168.0.256");
        assertHostSpecFails("::ffff:192.1680.0.255");
        assertHostSpecFails("::ffff:192..0.255");
        assertHostSpecFails("::ffff:192.0.255");
        assertHostSpecFails("::ffff:192.0.255.");
        assertHostSpecFails("::ffff:192.0.255.0.1");
    }

    private void assertHostSpecFails(String hostSpec) {
        try {
            MatchRule.ALL.matchHost(hostSpec);
            Assert.fail("Exception expected for hostSpec " + hostSpec);
        } catch (Exception e) {
            Assert.assertEquals(IllegalArgumentException.class, e.getClass());
        }
    }
}
