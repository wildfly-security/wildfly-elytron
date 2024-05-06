/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2023 Red Hat, Inc., and individual contributors
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

import java.io.BufferedReader;
import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Test case to test {@link FileAuditEndpointTest}
 *
 * @author <a href="mailto:ivassile@redhat.com">Ilia Vassilev</a>
 */
@RunWith(JMockit.class)
public class FileAuditEndpointTest {
    static File logDirFile;
    static Path logFile;
    static ZoneId UTC = ZoneId.of("UTC");
    static TestClock clock;

    @BeforeClass
    public static void init() throws Exception {
        logDirFile = new File(FileAuditEndpointTest.class.getResource(".").getFile(), "audit");
        logFile = Paths.get(logDirFile.getPath(), "audit");
    }

    @Test
    public void testFileEncoding() throws Exception {
        Charset charset = StandardCharsets.UTF_16;
        AuditEndpoint endpoint = FileAuditEndpoint.builder()
                .setLocation(logFile)
                .setClock(clock)
                .setCharset(charset)
                .build();
        endpoint.accept(EventPriority.CRITICAL, "testing log message");
        endpoint.close();
        assertFiles("audit");

        FileInputStream fis = null;
        BufferedReader br = null;
        try {
            fis = new FileInputStream(logFile.toFile());
            br = new BufferedReader(new InputStreamReader(fis, charset));
            Assert.assertTrue(br.readLine().contains("testing log message"));
        } finally {
            safeClose(fis);
            safeClose(br);
        }
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

    private void safeClose(Closeable c) {
        if (c != null) {
            try {
                c.close();
            } catch (Throwable ignored) {}
        }
    }
}
