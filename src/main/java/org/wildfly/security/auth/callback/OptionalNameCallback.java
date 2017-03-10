/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.auth.callback;

import javax.security.auth.callback.NameCallback;

/**
 * A {@code NameCallback} which is optional, for mechanisms that can accept a name from the server.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class OptionalNameCallback extends NameCallback implements ExtendedCallback {
    private static final long serialVersionUID = 1848637046120873969L;

    /**
     * Construct a new instance.
     *
     * @param prompt the prompt to offer the user
     */
    public OptionalNameCallback(final String prompt) {
        super(prompt);
    }

    /**
     * Construct a new instance.
     *
     * @param prompt the prompt to offer the user
     * @param defaultName the default name to specify (must not be {@code null})
     */
    public OptionalNameCallback(final String prompt, final String defaultName) {
        super(prompt, defaultName);
    }

    public boolean needsInformation() {
        return true;
    }
}
