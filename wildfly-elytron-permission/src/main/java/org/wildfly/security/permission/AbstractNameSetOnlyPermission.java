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

import org.wildfly.security.util.StringEnumeration;

/**
 * An actionless permission with a finite, fixed set of possible names.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public abstract class AbstractNameSetOnlyPermission<This extends AbstractNameSetOnlyPermission<This>> extends AbstractNameOnlyPermission<This> {

    private final StringEnumeration nameEnumeration;

    /**
     * Construct a new instance.
     *
     * @param name the name of this permission
     * @param nameEnumeration the set of valid names for this permission type
     */
    protected AbstractNameSetOnlyPermission(final String name, final StringEnumeration nameEnumeration) {
        super("*".equals(name) ? "*" : nameEnumeration.canonicalName(name));
        this.nameEnumeration = nameEnumeration;
    }

    StringEnumeration getNameEnumeration() {
        return nameEnumeration;
    }

    public AbstractPermissionCollection newPermissionCollection() {
        return NameSetPermissionCollection.newInstance(this, nameEnumeration);
    }

    public final boolean nameEquals(final String name) {
        return super.nameEquals(name);
    }

    public final boolean impliesName(final String name) {
        return super.impliesName(name);
    }

    protected final int nameHashCode() {
        return nameEnumeration.indexOf(getName());
    }
}
