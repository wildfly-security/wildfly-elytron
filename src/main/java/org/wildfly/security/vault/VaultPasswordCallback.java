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
import javax.security.auth.Destroyable;
import javax.security.auth.callback.Callback;
import java.util.Arrays;

/**
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>.
 */
public class VaultPasswordCallback implements Callback, Destroyable {

    private char[] password;

    public char[] getPassword() {
        return password != null ? Arrays.copyOf(password, password.length) : null;
    }

    public void setPassword(char[] password) {
        this.password = password != null ? Arrays.copyOf(password, password.length) : null;
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
        return (password == null);
    }
}
