/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2013 Red Hat, Inc., and individual contributors
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

package org.wildfly.security;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Properties;

import org.wildfly.security._private.ElytronMessages;

/**
 * The version of this JAR.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class Version {

    private Version() {
    }

    private static final String VERSION;

    static {
        Properties versionProps = new Properties();
        String versionString = "(unknown)";
        try (final InputStream stream = Version.class.getResourceAsStream("Version.properties")) {
            try (final InputStreamReader reader = new InputStreamReader(stream)) {
                versionProps.load(reader);
                versionString = versionProps.getProperty("version", versionString);
            }
        } catch (IOException ignored) {
        }
        VERSION = versionString;
        ElytronMessages.log.logVersion(versionString);
    }

    /**
     * Get the version.
     *
     * @return the version
     */
    public static String getVersion() {
        return VERSION;
    }

    /**
     * Print the version to {@code System.out}.
     *
     * @param args ignored
     */
    public static void main(String[] args) {
        System.out.print(VERSION);
    }
}
