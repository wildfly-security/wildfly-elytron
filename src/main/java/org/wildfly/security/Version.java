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
import java.net.URL;
import java.util.Enumeration;
import java.util.jar.Attributes;
import java.util.jar.Manifest;

/**
 * The version of this JAR.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class Version {
    private Version() {}

    private static final String JAR_NAME;
    private static final String VERSION_STRING;

    static {
        final Enumeration<URL> resources;
        String jarName = "(unknown)";
        String versionString = "(unknown)";
        try {
            final ClassLoader classLoader = Version.class.getClassLoader();
            resources = classLoader == null ? ClassLoader.getSystemResources("META-INF/MANIFEST.MF") : classLoader.getResources("META-INF/MANIFEST.MF");
            while (resources.hasMoreElements()) {
                final URL url = resources.nextElement();
                try (InputStream stream = url.openStream()) {
                    final Manifest manifest = new Manifest(stream);
                    final Attributes mainAttributes = manifest.getMainAttributes();
                    if (mainAttributes != null && "WildFly Elytron".equals(mainAttributes.getValue("Specification-Title"))) {
                        jarName = mainAttributes.getValue("Jar-Name");
                        versionString = mainAttributes.getValue("Jar-Version");
                    }
                } catch (IOException ignored) {}
            }
        } catch (IOException ignored) {}
        JAR_NAME = jarName;
        VERSION_STRING = versionString;
    }

    /**
     * Get the name of the this JAR.
     *
     * @return the name
     */
    public static String getJarName() {
        return JAR_NAME;
    }

    /**
     * Get the version string of this JAR.
     *
     * @return the version string
     */
    public static String getVersionString() {
        return VERSION_STRING;
    }

    /**
     * Print out the current version on {@code System.out}.
     *
     * @param args ignored
     */
    public static void main(String[] args) {
        System.out.printf("WildFly Elytron version %s\n", VERSION_STRING);
    }

}
