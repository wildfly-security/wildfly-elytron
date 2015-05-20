/*
 * JBoss, Home of Professional Open Source
 * Copyright 2015 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.vault;

import org.wildfly.security.vault._private.KeystorePasswordStorage;

import java.util.Map;

/**
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>.
 */
public class TestExternalKeyPasswordClass extends TestExternalPasswordClass {

    public TestExternalKeyPasswordClass() {
        password = "secret_key_THREE".toCharArray();
    }

    public TestExternalKeyPasswordClass(String passwordToReturn, String ignoredArg) {
        password = passwordToReturn.toCharArray();
    }

    public TestExternalKeyPasswordClass(Map<String, ?> options) {
        super(options);
    }

    @Override
    public char[] getPassword() {
        if (password != null) {
            return password.clone();
        } else if (options != null) {
            return ((String)options.get(KeystorePasswordStorage.KEY_PASSWORD_CALLBACK + ".myPassword")).toCharArray();
        }
        throw new RuntimeException("Key password is not specified correctly");
    }
}
