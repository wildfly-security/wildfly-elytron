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
 * An event to represent a successful permission check.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public final class SecurityPermissionCheckSuccessfulEvent extends SecurityPermissionCheckEvent {

    /**
     * Construct a new instance.
     *
     * @param securityIdentity the {@link SecurityIdentity} the permisson check was against.
     * @param permission the {@link Permission} that was checked.
     */
    public SecurityPermissionCheckSuccessfulEvent(SecurityIdentity securityIdentity, Permission permission) {
        super(securityIdentity, permission, true);
    }

    @Override
    public <P, R> R accept(SecurityEventVisitor<P, R> visitor, P param) {
        return visitor.handlePermissionCheckSuccessfulEvent(this, param);
    }

}
