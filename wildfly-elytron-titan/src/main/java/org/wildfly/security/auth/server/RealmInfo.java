/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
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
package org.wildfly.security.auth.server;

import java.security.Principal;
import java.util.function.Function;

import org.wildfly.security.authz.RoleDecoder;
import org.wildfly.security.authz.RoleMapper;

/**
 * <p>Holds the reference to a {@link SecurityRealm} and the configuration associated with it.</p>
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
class RealmInfo {

    private final SecurityRealm securityRealm;
    private final String name;
    private final RoleMapper roleMapper;
    private final Function<Principal, Principal> principalRewriter;
    private final RoleDecoder roleDecoder;

    RealmInfo(final SecurityDomain.RealmBuilder realmBuilder) {
        this.name = realmBuilder.getName();
        this.securityRealm = realmBuilder.getRealm();
        this.roleMapper = realmBuilder.getRoleMapper();
        this.principalRewriter = realmBuilder.getPrincipalRewriter();
        this.roleDecoder = realmBuilder.getRoleDecoder();
    }

    RealmInfo() {
        this.securityRealm = SecurityRealm.EMPTY_REALM;
        this.name = "default";
        this.roleMapper = RoleMapper.IDENTITY_ROLE_MAPPER;
        this.principalRewriter = Function.identity();
        this.roleDecoder = RoleDecoder.DEFAULT;
    }

    String getName() {
        return this.name;
    }

    SecurityRealm getSecurityRealm() {
        return this.securityRealm;
    }

    RoleMapper getRoleMapper() {
        return this.roleMapper;
    }

    Function<Principal, Principal> getPrincipalRewriter() {
        return principalRewriter;
    }

    RoleDecoder getRoleDecoder() {
        return roleDecoder;
    }

    @Override
    public String toString() {
        return "RealmInfo{name='" + name + "', securityRealm=" + securityRealm + "}";
    }
}
