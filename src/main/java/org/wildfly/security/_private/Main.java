/*
 * JBoss, Home of Professional Open Source.
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

package org.wildfly.security._private;

import static java.lang.System.err;
import static java.lang.System.exit;
import static java.lang.System.out;
import static java.util.Arrays.asList;

import java.util.Iterator;
import java.util.List;

import org.wildfly.security.Version;

/**
 * Elytron main entry point.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class Main {
    private Main() {}

    /**
     * The Elytron main method.
     *
     * @param args the command-line arguments
     */
    public static void main(String... args) {
        final List<String> argsList = asList(args);
        final Iterator<String> argIterator = argsList.iterator();
        boolean version = false;
        boolean help = false;
        while (argIterator.hasNext()) {
            final String arg = argIterator.next();
            switch (arg) {
                case "-help": {
                    help = true;
                    break;
                }
                case "-version": {
                    version = true;
                    break;
                }
                default: {
                    err.printf("Unrecognized argument \"%s\"", arg);
                    printHelpAndExit();
                    break; // unreachable
                }
            }
        }
        if (version) {
            out.printf("WildFly Elytron version %s%n", Version.getVersion());
        }
        // if no options were given (other than help) then report the usage message
        if (help || ! version) {
            printHelpAndExit();
            return; // unreachable
        }
    }

    private static void printHelpAndExit() {
        out.printf("Usage: java [-jvmoptions...] -jar %s.jar [-options...]%n", Version.getJarName());
        out.printf("where options include:%n");
        out.printf("        -help       Display this message and exit%n");
        out.printf("     -version       Print the version%n%n");
        exit(1);
    }
}
