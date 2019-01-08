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
package org.wildfly.security.auth.server.event;

import java.security.Permission;

import org.wildfly.security.auth.server.SecurityIdentity;

/**
 * A security event relating to a permission check.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public abstract class SecurityPermissionCheckEvent extends SecurityDefiniteOutcomeEvent {

    private final Permission permission;

    /**
     * Construct a new instance.
     *
     * @param securityIdentity the {@link SecurityIdentity} the permission check was against.
     * @param successful was the permission check successful.
     * @param permission the {@link Permission} that was checked.
     */
    public SecurityPermissionCheckEvent(SecurityIdentity securityIdentity, Permission permission, boolean successful) {
        super(securityIdentity, successful);
        this.permission = permission;
    }

    /**
     * Obtain the {@link Permission} this event related to.
     *
     * @return the {@link Permission} this event related to.
     */
    public Permission getPermission() {
        return permission;
    }

    @Override
    public <P, R> R accept(SecurityEventVisitor<P, R> visitor, P param) {
        return visitor.handlePermissionCheckEvent(this, param);
    }

}
