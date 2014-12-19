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

import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.ListIterator;

import org.wildfly.security.Version;
import org.wildfly.security.sasl.util.UsernamePasswordHashUtil;

/**
 * Elytron main entry point.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
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
        final ListIterator<String> argIterator = argsList.listIterator();
        boolean help = false;
        boolean version = false;
        String operationName = null;
        String[] operationArgs = null;

        while (argIterator.hasNext()) {
            final String arg = argIterator.next();
            if (arg.charAt(0) == '-') {
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
                        err.printf("Unrecognized argument \"%s\"%n", arg);
                        printHelp();
                        exit(1);
                    }
                }
            } else {
                operationName = arg;
                int index = argIterator.nextIndex();
                int count = args.length - index;
                operationArgs = new String[count];
                System.arraycopy(args, index, operationArgs, 0, count);
                break; // terminate argument iterating
            }
        }

        if (version) {
            out.printf("WildFly Elytron version %s%n", Version.getVersion());
        }
        // if operation was specified
        else if (operationArgs != null){
            switch(operationName){
                case "UsernamePasswordHashUtil":
                    usernamePasswordHash(operationArgs);
                break;
                default:
                    err.printf("Unrecognized operation \"%s\"%n", operationName);
                    printHelp();
                    exit(1);
            }
        }
        // if no options were given (other than help) then report the usage message
        else if (args.length == 0 || help) {
            printHelp();
            exit(0);
        }
    }

    private static void printHelp() {
        out.printf("Usage: java [-jvmoptions...] -jar %s.jar [-options...] <operation-spec> [args...]%n", Version.getJarName());
        out.printf("where <operation-spec> is a valid operation specification string%n");
        out.printf("and options include:%n");
        out.printf("     -help          Display this message and exit%n");
        out.printf("     -version       Print the version%n%n");
    }

    private static void usernamePasswordHash(String[] args) {
        String userName;
        String realm;
        char[] password;

        if (args.length == 2) {
            userName = args[0];
            realm = "";
            password = args[1].toCharArray();
        } else if (args.length == 3) {
            userName = args[0];
            realm = args[1];
            password = args[2].toCharArray();
        } else {
            out.printf("Usage: java [-jvmoptions...] -jar %s.jar [-options...] UsernamePasswordHashUtil UserName [Realm] Password%n", Version.getJarName());
            return;
        }

        try {
            UsernamePasswordHashUtil util = new UsernamePasswordHashUtil();
            out.println(userName + "=" + util.generateHashedHexURP(userName, realm, password));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

}
