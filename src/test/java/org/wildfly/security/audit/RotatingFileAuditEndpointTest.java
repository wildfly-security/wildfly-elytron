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

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.TimeZone;

/**
 * Test case to test {@link RotatingFileAuditEndpoint}
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
@RunWith(JMockit.class)
public class RotatingFileAuditEndpointTest {

    static File logDirFile;
    static Path logFile;
    static TimeZone UTC = TimeZone.getTimeZone("UTC");
    long time = 0x1000000L;
    long lastModTime = 0x1000000L;

    @BeforeClass
    public static void init() throws Exception {
        logDirFile = new File(RotatingFileAuditEndpointTest.class.getResource(".").getFile(), "audit");
        logFile = Paths.get(logDirFile.getPath(), "audit");
    }

    @Test
    public void testBase() throws Exception {
        AuditEndpoint endpoint = RotatingFileAuditEndpoint.builder()
                .setLocation(logFile)
                .build();
        endpoint.accept(EventPriority.CRITICAL, "testing log message");
        endpoint.close();
        assertFiles("audit");
    }

    @Test
    public void testTimeBasedRollover() throws Exception {
        AuditEndpoint endpoint = RotatingFileAuditEndpoint.builder()
                .setTimeZone(UTC)
                .setMaxBackupIndex(0)
                .setSuffix(".yyyy-MM-dd")
                .setLocation(logFile)
                .build();
        endpoint.accept(EventPriority.CRITICAL, "testing log message 1");
        time = 0x2000000L;
        endpoint.accept(EventPriority.CRITICAL, "testing log message 2");
        endpoint.close();
        assertFiles("audit", "audit.1970-07-14");
    }

    @Test
    public void testAppend() throws Exception {
        AuditEndpoint endpoint = RotatingFileAuditEndpoint.builder()
                .setRotateOnBoot(false)
                .setMaxBackupIndex(2)
                .setRotateSize(1)
                .setSuffix(".yyyy-MM-dd")
                .setLocation(logFile)
                .build();
        endpoint.accept(EventPriority.CRITICAL, "testing log message 1");
        endpoint.close();
        AuditEndpoint endpoint2 = RotatingFileAuditEndpoint.builder()
                .setRotateOnBoot(false)
                .setMaxBackupIndex(2)
                .setRotateSize(1)
                .setSuffix(".yyyy-MM-dd")
                .setLocation(logFile)
                .build();
        time = 0x1000001L;
        endpoint2.accept(EventPriority.CRITICAL, "testing log message 2");
        endpoint2.close();
        assertFiles("audit");
    }

    @Test
    public void testRotateOnBoot() throws Exception {
        AuditEndpoint endpoint = RotatingFileAuditEndpoint.builder()
                .setTimeZone(UTC)
                .setRotateOnBoot(true)
                .setMaxBackupIndex(2)
                .setRotateSize(1)
                .setSuffix(".yyyy-MM-dd")
                .setLocation(logFile)
                .build();
        endpoint.accept(EventPriority.CRITICAL, "testing log message 1");
        endpoint.close();
        AuditEndpoint endpoint2 = RotatingFileAuditEndpoint.builder()
                .setTimeZone(UTC)
                .setRotateOnBoot(true)
                .setMaxBackupIndex(2)
                .setRotateSize(1)
                .setSuffix(".yyyy-MM-dd")
                .setLocation(logFile)
                .build();
        time = 0x1000001L;
        endpoint2.accept(EventPriority.CRITICAL, "testing log message 2");
        endpoint2.close();
        assertFiles("audit", "audit.1970-07-14.1");
    }

    @Test
    public void testRotateOnSizeOverflow() throws Exception {
        AuditEndpoint endpoint = RotatingFileAuditEndpoint.builder()
                .setTimeZone(UTC)
                .setMaxBackupIndex(4)
                .setRotateSize(60)
                .setSuffix(".yyyy-MM-dd")
                .setLocation(logFile)
                .build();
        for (int i = 0; i < 15; i++) {
            endpoint.accept(EventPriority.CRITICAL, "testing log message "+i);
        }
        endpoint.close();
        assertFiles("audit", "audit.1970-07-14.1", "audit.1970-07-14.2", "audit.1970-07-14.3", "audit.1970-07-14.4");
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

    @Before
    public void mockTime() {
        new MockUp<System>() {
            @Mock
            public long currentTimeMillis() {
                return time * 1000L;
            }
        };
        new MockUp<File>() {
            @Mock
            public long lastModified() {
                return lastModTime * 1000L;
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
