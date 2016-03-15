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
 * A security action which clears a system property.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class ClearPropertyAction implements PrivilegedAction<String> {

    private final String propertyName;

    /**
     * Construct a new instance.
     *
     * @param propertyName the name of the property to clear
     */
    public ClearPropertyAction(final String propertyName) {
        this.propertyName = propertyName;
    }

    public String run() {
        return System.clearProperty(propertyName);
    }
}
