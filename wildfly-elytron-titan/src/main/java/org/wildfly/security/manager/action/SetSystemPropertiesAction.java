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
 * A security action which replaces the system properties map.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class SetSystemPropertiesAction implements PrivilegedAction<Void> {

    private final Properties properties;

    /**
     * Construct a new instance.
     *
     * @param properties the new properties map
     */
    public SetSystemPropertiesAction(final Properties properties) {
        this.properties = properties;
    }

    public Void run() {
        System.setProperties(properties);
        return null;
    }
}
