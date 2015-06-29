/*
 * JBoss, Home of Professional Open Source.
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

package org.wildfly.security.password.interfaces;

class RawClearPassword extends RawPassword implements ClearPassword {

    private static final long serialVersionUID = -7982031201140935435L;

    private final char[] password;

    RawClearPassword(final String algorithm, final char[] password) {
        super(algorithm);
        this.password = password;
    }

    public char[] getPassword() throws IllegalStateException {
        return password.clone();
    }
}
