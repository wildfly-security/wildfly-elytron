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
 * A base class for nameless and actionless permissions that are either granted or not granted.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public abstract class AbstractBooleanPermission<This extends AbstractBooleanPermission<This>> extends AbstractPermission<This> {
    /**
     * Construct a new instance.
     */
    protected AbstractBooleanPermission() {
        super("");
    }

    public boolean implies(final This permission) {
        return permission != null;
    }

    public boolean equals(final This other) {
        return other != null;
    }

    public int hashCode() {
        return getClass().hashCode();
    }

    public AbstractPermissionCollection newPermissionCollection() {
        return new BooleanPermissionCollection(this);
    }
}
