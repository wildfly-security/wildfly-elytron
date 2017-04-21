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

package org.wildfly.security.permission;

/**
 * An exception similar to {@link IllegalArgumentException}, but providing invalid attribute name.
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
public class InvalidNamedArgumentException extends IllegalArgumentException {
    private static final long serialVersionUID = 6720672218992387011L;

    private String name;

    public InvalidNamedArgumentException(String name) {
        this.name = name;
    }

    public InvalidNamedArgumentException(String name, Throwable cause) {
        super(cause);
        this.name = name;
    }

    /**
     * Name of invalid argument
     * @return the name of argument
     */
    public String getName() {
        return name;
    }
}
