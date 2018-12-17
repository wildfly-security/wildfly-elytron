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
import java.nio.file.Paths;
import java.time.Instant;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Test case to test {@link SizeRotatingFileAuditEndpointTest}
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 * @author <a href="mailto:yborgess@redhat.com">Yeray Borges</a>
 */
//has dependency on TestClock from wildfly-elytron-tests (util)
@RunWith(JMockit.class)
public class SizeRotatingFileAuditEndpointTest {
    static File logDirFile;
    static Path logFile;
    static ZoneId UTC = ZoneId.of("UTC");
    static TestClock clock;

    @BeforeClass
    public static void init() throws Exception {
        logDirFile = new File(SizeRotatingFileAuditEndpointTest.class.getResource(".").getFile(), "audit");
        logFile = Paths.get(logDirFile.getPath(), "audit");
    }

    @Test
    public void testBase() throws Exception {
        AuditEndpoint endpoint = SizeRotatingFileAuditEndpoint.builder()
                .setLocation(logFile)
                .setClock(clock)
                .build();
        endpoint.accept(EventPriority.CRITICAL, "testing log message");
        endpoint.close();
        assertFiles("audit");
    }

    @Test
    public void testRotateOnSizeOverflow() throws Exception {
        AuditEndpoint endpoint = SizeRotatingFileAuditEndpoint.builder()
                .setTimeZone(UTC)
                .setMaxBackupIndex(4)
                .setRotateSize(60)
                .setSuffix(".yyyy-MM-dd")
                .setLocation(logFile)
                .setClock(clock)
                .build();
        int i = 0;
        for (;i < 15; i++) {
            endpoint.accept(EventPriority.CRITICAL, "testing log message "+i);
        }
        clock.plus(1, ChronoUnit.DAYS);
        for (;i < 30; i++) {
            endpoint.accept(EventPriority.CRITICAL, "testing log message "+i);
        }
        endpoint.close();
        assertFiles("audit", "audit.1970-01-01.1", "audit.1970-01-01.2", "audit.1970-01-01.3", "audit.1970-01-01.4",
                "audit.1970-01-02.1", "audit.1970-01-02.2", "audit.1970-01-02.3", "audit.1970-01-02.4");
    }

    @Test
    public void testRotateOnBoot() throws Exception {
        AuditEndpoint endpoint = SizeRotatingFileAuditEndpoint.builder()
                .setTimeZone(UTC)
                .setRotateOnBoot(true)
                .setMaxBackupIndex(2)
                .setRotateSize(1)
                .setSuffix(".yyyy-MM-dd")
                .setLocation(logFile)
                .setClock(clock)
                .build();
        endpoint.accept(EventPriority.CRITICAL, "testing log message 1");
        endpoint.close();
        endpoint = SizeRotatingFileAuditEndpoint.builder()
                .setTimeZone(UTC)
                .setRotateOnBoot(true)
                .setMaxBackupIndex(2)
                .setRotateSize(1)
                .setSuffix(".yyyy-MM-dd")
                .setLocation(logFile)
                .setClock(clock)
                .build();
        endpoint.accept(EventPriority.CRITICAL, "testing log message 2");
        endpoint.close();
        assertFiles("audit", "audit.1970-01-01.1");
    }

    @Before
    public void initDir() {
        logDirFile.mkdirs();
        Assert.assertTrue(logDirFile.isDirectory());
        File[] var1 = logDirFile.listFiles();
        int var2 = var1.length;

        for(int var3 = 0; var3 < var2; ++var3) {
            File file = var1[var3];
            file.delete();
        }

        this.assertFiles(new String[0]);
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
