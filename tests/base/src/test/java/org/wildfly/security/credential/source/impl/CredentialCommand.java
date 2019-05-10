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
package org.wildfly.security.credential.source.impl;

/**
 * Class that simulates credential command for tests.
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 */
public class CredentialCommand {

    private CredentialCommand() {

    }

    /**
     * Main method.
     * @param args arguments to create password
     */
    public static void main(String[] args) {
        String password;
        if (args != null && args.length > 0) {
            StringBuilder sb = new StringBuilder(args[0]);
            for(int i = 1; i < args.length; i++) {
                sb.append(" ").append(args[i]);
            }
            password = sb.toString();
        } else {
            password = "password";
        }
        System.out.println(password);
        System.out.flush();
    }
}
