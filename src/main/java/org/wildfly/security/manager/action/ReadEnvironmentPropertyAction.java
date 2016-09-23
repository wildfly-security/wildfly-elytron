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

package org.wildfly.security.manager.action;

import java.security.PrivilegedAction;

/**
 * A security action which reads an environment property.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class ReadEnvironmentPropertyAction implements PrivilegedAction<String> {

    private final String propertyName;
    private final String defaultValue;

    /**
     * Construct a new instance.
     *
     * @param propertyName the environment property to read
     */
    public ReadEnvironmentPropertyAction(final String propertyName) {
        this(propertyName, null);
    }

    /**
     * Construct a new instance.
     *
     * @param propertyName the environment property to read
     * @param defaultValue the value to return if the property is not present
     */
    public ReadEnvironmentPropertyAction(final String propertyName, final String defaultValue) {
        this.propertyName = propertyName;
        this.defaultValue = defaultValue;
    }

    public String run() {
        final String val = System.getenv(propertyName);
        return val == null ? defaultValue : val;
    }
}
