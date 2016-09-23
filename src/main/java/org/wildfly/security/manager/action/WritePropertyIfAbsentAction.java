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
import java.util.Properties;

/**
 * A privileged action for setting a system property if it is absent.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class WritePropertyIfAbsentAction implements PrivilegedAction<String> {
    private final String propertyName;
    private final String value;

    /**
     * Construct a new instance.
     *
     * @param propertyName the property name to set
     * @param value the value to use
     */
    public WritePropertyIfAbsentAction(final String propertyName, final String value) {
        this.propertyName = propertyName;
        this.value = value;
    }

    public String run() {
        final Properties properties = System.getProperties();
        synchronized (properties) {
            if (properties.containsKey(propertyName)) {
                return properties.getProperty(propertyName);
            } else {
                return (String) properties.setProperty(propertyName, value);
            }
        }
    }
}
