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
package org.wildfly.security.audit;

import mockit.Mock;
import mockit.MockUp;
import mockit.integration.junit4.JMockit;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.wildfly.security.util.TestClock;

import java.io.File;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;


/**
 * Test case to test {@link PeriodicRotatingFileAuditEndpoint}
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 * @author <a href="mailto:yborgess@redhat.com">Yeray Borges</a>
 */
//has dependency on TestClock wildfly-elytron-tests (util)
@RunWith(JMockit.class)
public class PeriodicRotatingFileAuditEndpointTest {
    static File logDirFile;
    static Path logFile;
    static ZoneId UTC = ZoneId.of("UTC");
    static TestClock clock;

    @BeforeClass
    public static void init() throws Exception {
        Locale.setDefault(Locale.US);
        logDirFile = new File(PeriodicRotatingFileAuditEndpointTest.class.getResource(".").getFile(), "audit");
        logFile = logDirFile.toPath().resolve( "audit");
    }

    @Before
    public void initDir() {
        logDirFile.mkdirs();
        Assert.assertTrue(logDirFile.isDirectory());
        for (File file : logDirFile.listFiles()) {
            file.delete();
        }
        assertFiles();
    }

    @Test
    public void testBase() throws Exception {
        AuditEndpoint endpoint = PeriodicRotatingFileAuditEndpoint.builder()
                .setLocation(logFile)
                .setClock(clock)
                .build();
        endpoint.accept(EventPriority.CRITICAL, "testing log message");
        endpoint.close();
        assertFiles("audit");
    }

    @Test
    public void testTimeBasedRolloverYear() throws Exception {
        AuditEndpoint endpoint = PeriodicRotatingFileAuditEndpoint.builder()
                .setTimeZone(UTC)
                .setSuffix(".yyyy")
                .setLocation(logFile)
                .setClock(clock)
                .build();
        endpoint.accept(EventPriority.CRITICAL, "testing log message 1");
        clock.plus(365,ChronoUnit.DAYS);
        endpoint.accept(EventPriority.CRITICAL, "testing log message 2");
        clock.plus(365,ChronoUnit.DAYS);
        endpoint.accept(EventPriority.CRITICAL, "testing log message 3");
        endpoint.close();
        assertFiles("audit", "audit.1970","audit.1971");
    }

    @Test
    public void testTimeBasedRolloverMonth() throws Exception {
        AuditEndpoint endpoint = PeriodicRotatingFileAuditEndpoint.builder()
                .setTimeZone(UTC)
                .setSuffix(".yyyy-MM")
                .setLocation(logFile)
                .setClock(clock)
                .build();
        endpoint.accept(EventPriority.CRITICAL, "testing log message 1");
        clock.plus(32,ChronoUnit.DAYS);
        endpoint.accept(EventPriority.CRITICAL, "testing log message 2");
        clock.plus(32,ChronoUnit.DAYS);
        endpoint.accept(EventPriority.CRITICAL, "testing log message 3");
        endpoint.close();
        assertFiles("audit", "audit.1970-01","audit.1970-02");
    }

    @Test
    public void testTimeBasedRolloverWeek() throws Exception {
        AuditEndpoint endpoint = PeriodicRotatingFileAuditEndpoint.builder()
                .setTimeZone(UTC)
                .setSuffix(".yyyy-MM-ww")
                .setLocation(logFile)
                .setClock(clock)
                .build();
        //1 January 1970 is a Thursday
        endpoint.accept(EventPriority.CRITICAL, "testing log message 1");
        clock.plus(4,ChronoUnit.DAYS);
        endpoint.accept(EventPriority.CRITICAL, "testing log message 2");
        clock.plus(7,ChronoUnit.DAYS);
        endpoint.accept(EventPriority.CRITICAL, "testing log message 3");
        endpoint.close();
        assertFiles("audit", "audit.1970-01-01","audit.1970-01-02");
    }

    @Test
    public void testTimeBasedRolloverDay() throws Exception {
        AuditEndpoint endpoint = PeriodicRotatingFileAuditEndpoint.builder()
                .setTimeZone(UTC)
                .setSuffix(".yyyy-MM-ww-dd")
                .setLocation(logFile)
                .setClock(clock)
                .build();
        endpoint.accept(EventPriority.CRITICAL, "testing log message 1");
        clock.plus(1,ChronoUnit.DAYS);
        endpoint.accept(EventPriority.CRITICAL, "testing log message 2");
        clock.plus(1,ChronoUnit.DAYS);
        endpoint.accept(EventPriority.CRITICAL, "testing log message 3");
        endpoint.close();
        assertFiles("audit", "audit.1970-01-01-01","audit.1970-01-01-02");
    }

    @Test
    public void testTimeBasedRolloverHalfDay() throws Exception {
        AuditEndpoint endpoint = PeriodicRotatingFileAuditEndpoint.builder()
                .setTimeZone(UTC)
                .setSuffix(".yyyy-MM-ww-dd-a")
                .setLocation(logFile)
                .setClock(clock)
                .build();
        endpoint.accept(EventPriority.CRITICAL, "testing log message 1");
        clock.plus(12,ChronoUnit.HOURS);
        endpoint.accept(EventPriority.CRITICAL, "testing log message 2");
        clock.plus(12,ChronoUnit.HOURS);
        endpoint.accept(EventPriority.CRITICAL, "testing log message 3");
        endpoint.close();
        assertFiles("audit", "audit.1970-01-01-01-AM","audit.1970-01-01-01-PM");
    }

    @Test
    public void testTimeBasedRolloverHour() throws Exception {
        AuditEndpoint endpoint = PeriodicRotatingFileAuditEndpoint.builder()
                .setTimeZone(UTC)
                .setSuffix(".yyyy-MM-ww-dd-a-hh")
                .setLocation(logFile)
                .setClock(clock)
                .build();
        endpoint.accept(EventPriority.CRITICAL, "testing log message 1");
        clock.plus(1,ChronoUnit.HOURS);
        endpoint.accept(EventPriority.CRITICAL, "testing log message 2");
        clock.plus(1,ChronoUnit.HOURS);
        endpoint.accept(EventPriority.CRITICAL, "testing log message 3");
        endpoint.close();
        assertFiles("audit", "audit.1970-01-01-01-AM-12","audit.1970-01-01-01-AM-01");
    }

    @Test
    public void testTimeBasedRolloverHour24() throws Exception {
        AuditEndpoint endpoint = PeriodicRotatingFileAuditEndpoint.builder()
                .setTimeZone(UTC)
                .setSuffix(".yyyy-MM-ww-dd-a-HH")
                .setLocation(logFile)
                .setClock(clock)
                .build();
        endpoint.accept(EventPriority.CRITICAL, "testing log message 1");
        clock.plus(1,ChronoUnit.HOURS);
        endpoint.accept(EventPriority.CRITICAL, "testing log message 2");
        clock.plus(1,ChronoUnit.HOURS);
        endpoint.accept(EventPriority.CRITICAL, "testing log message 3");
        endpoint.close();
        assertFiles("audit", "audit.1970-01-01-01-AM-00","audit.1970-01-01-01-AM-01");
    }

    @Test
    public void testTimeBasedRolloverMinutes() throws Exception {
        AuditEndpoint endpoint = PeriodicRotatingFileAuditEndpoint.builder()
                .setTimeZone(UTC)
                .setSuffix(".yyyy-MM-ww-dd-a-HH_mm")
                .setLocation(logFile)
                .setClock(clock)
                .build();
        endpoint.accept(EventPriority.CRITICAL, "testing log message 1");
        clock.plus(1,ChronoUnit.MINUTES);
        endpoint.accept(EventPriority.CRITICAL, "testing log message 2");
        clock.plus(1,ChronoUnit.MINUTES);
        endpoint.accept(EventPriority.CRITICAL, "testing log message 3");
        endpoint.close();
        assertFiles("audit", "audit.1970-01-01-01-AM-00_00","audit.1970-01-01-01-AM-00_01");
    }

    @Before
    public void mockTime() {
        clock = new TestClock(Instant.EPOCH.truncatedTo(ChronoUnit.DAYS));
        new MockUp<File>() {
            @Mock
            public long lastModified() {
                return clock.millis();
            }
        };
    }

    private void assertFiles(String...files) {
        Set<String> expected = new HashSet<>(Arrays.asList(files));
        for (File file : logDirFile.listFiles()) {
            if (! expected.remove(file.getName())) {
                Assert.fail("Unexpected file "+file.getName());
            }
        }
        for (String missing : expected) {
            Assert.fail("Missing file "+missing);
        }
    }
}
