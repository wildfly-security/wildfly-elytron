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

import javax.security.auth.DestroyFailedException;
import java.util.Arrays;
import java.util.Map;

/**
 * Class used by tests to simulate external password gathering using ExternalPasswordClass implementation.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>.
 */
public class TestExternalPasswordClass implements PasswordClass {

    protected char[] password = null;
    protected Map<String, ?> options = null;


    public TestExternalPasswordClass() {
        password = "secret_store_THREE".toCharArray();
    }

    public TestExternalPasswordClass(String passwordToReturn, String arg1, String arg2) {
        password = passwordToReturn.toCharArray();
    }

    public TestExternalPasswordClass(Map<String, ?> options) {
        this.options = options;
    }

    @Override
    public char[] getPassword() {
        if (password != null) {
            return password.clone();
        } else if (options != null) {
            return ((String)options.get(VaultSpi.CALLBACK + ".myPassword")).toCharArray();
        }
        throw new RuntimeException("Password is not specified correctly");
    }

    @Override
    public void destroy() throws DestroyFailedException {
        if (password != null) {
            Arrays.fill(password, (char) 0x00);
            password = null;
        }
    }

    @Override
    public boolean isDestroyed() {
        return password == null;
    }
}
