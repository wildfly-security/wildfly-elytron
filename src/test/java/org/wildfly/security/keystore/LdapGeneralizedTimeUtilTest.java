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

package org.wildfly.security.keystore;

import org.junit.Assert;
import org.junit.Test;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Date;

/**
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
public class LdapGeneralizedTimeUtilTest {

    @Test
    public void testGeneralizedTimeBaseParsing() throws Exception {
        // Apache Directory createTimestamp format
        Date expected = Date.from(ZonedDateTime.parse("2016-08-12T10:17:13.678Z").toInstant());
        Assert.assertEquals(expected, LdapGeneralizedTimeUtil.generalizedTimeToDate("20160812101713.678Z"));

        // OpenLDAP createTimestamp format
        expected = Date.from(ZonedDateTime.parse("2013-09-03T08:58:29Z").toInstant());
        Assert.assertEquals(expected, LdapGeneralizedTimeUtil.generalizedTimeToDate("20130903085829Z"));
    }

    @Test
    public void testRfc4517() throws Exception {
        // examples from RFC 4517
        Date expected = Date.from(ZonedDateTime.parse("1994-12-16T10:32:00+00:00[UTC]").toInstant());
        Assert.assertEquals(expected, LdapGeneralizedTimeUtil.generalizedTimeToDate("199412161032Z"));
        Assert.assertEquals(expected, LdapGeneralizedTimeUtil.generalizedTimeToDate("199412160532-0500"));
    }

    @Test
    public void testItuX680() throws Exception {
        // ITU X.680 local time
        Date expected = Date.from(LocalDateTime.parse("1985-11-06T21:06:27.3").atZone(ZoneId.systemDefault()).toInstant());
        Assert.assertEquals(expected, LdapGeneralizedTimeUtil.generalizedTimeToDate("19851106210627.3"));

        // ITU X.680 CET
        expected = Date.from(ZonedDateTime.parse("1985-11-06T21:06:27.3+00:00").toInstant());
        Assert.assertEquals(expected, LdapGeneralizedTimeUtil.generalizedTimeToDate("19851106210627.3Z"));

        // ITU X.680 5 hours retarded
        expected = Date.from(ZonedDateTime.parse("1985-11-06T21:06:27.3-05:00").toInstant());
        Assert.assertEquals(expected, LdapGeneralizedTimeUtil.generalizedTimeToDate("19851106210627.3-0500"));
    }

    @Test
    public void testFractions() throws Exception {
        // of hour
        Date expected = Date.from(ZonedDateTime.parse("2016-08-11T12:30:00Z").toInstant());
        Assert.assertEquals(expected, LdapGeneralizedTimeUtil.generalizedTimeToDate("2016081112,5Z"));

        // of minute
        expected = Date.from(ZonedDateTime.parse("2016-08-11T12:34:30Z").toInstant());
        Assert.assertEquals(expected, LdapGeneralizedTimeUtil.generalizedTimeToDate("201608111234.5Z"));

        // of second
        expected = Date.from(ZonedDateTime.parse("2016-08-11T12:34:56.5Z").toInstant());
        Assert.assertEquals(expected, LdapGeneralizedTimeUtil.generalizedTimeToDate("20160811123456.5Z"));
    }

}
