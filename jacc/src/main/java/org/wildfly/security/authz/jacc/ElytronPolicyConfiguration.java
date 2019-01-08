/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2015 Red Hat, Inc. and/or its affiliates.
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
package org.wildfly.security.authz.jacc;

import javax.security.jacc.PolicyConfiguration;
import javax.security.jacc.PolicyContextException;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Permissions;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import static org.wildfly.common.Assert.checkNotNullParam;
import static org.wildfly.security.authz.jacc.ElytronMessages.log;

/**
 * {@link javax.security.jacc.PolicyConfiguration} implementation.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 * @see org.wildfly.security.authz.jacc.ElytronPolicyConfigurationFactory
 */
class ElytronPolicyConfiguration implements PolicyConfiguration {

    /**
     * An enum with all the possible states accordingly with the specification.
     */
    enum State {
        OPEN,
        IN_SERVICE,
        DELETED
    }

    private final String contextId;
    private final Map<String, Permissions> rolePermissions = Collections.synchronizedMap(new HashMap<>());
    private State state = State.OPEN; // needs synchronization
    private volatile Permissions uncheckedPermissions = new Permissions(); // atomic reference + synchronized inside
    private volatile Permissions excludedPermissions = new Permissions(); // atomic reference + synchronized inside
    private volatile Set<PolicyConfiguration> linkedPolicies = Collections.synchronizedSet(new LinkedHashSet<>()); // atomic reference

    ElytronPolicyConfiguration(String contextID) {
        checkNotNullParam("contextID", contextID);
        this.contextId = contextID;
    }

    @Override
    public void addToExcludedPolicy(Permission permission) throws PolicyContextException {
        checkNotNullParam("permission", permission);

        synchronized (this) { // prevents state change while adding
            checkIfInOpenState();
            this.excludedPermissions.add(permission);
        }
    }

    @Override
    public void addToExcludedPolicy(PermissionCollection permissions) throws PolicyContextException {
        checkNotNullParam("permissions", permissions);

        Enumeration<Permission> elements = permissions.elements();

        while (elements.hasMoreElements()) {
            addToExcludedPolicy(elements.nextElement());
        }
    }

    @Override
    public void addToRole(String roleName, Permission permission) throws PolicyContextException {
        checkNotNullParam("roleName", roleName);
        checkNotNullParam("permission", permission);

        synchronized (this) { // prevents state change while adding
            checkIfInOpenState();
            this.rolePermissions.computeIfAbsent(roleName, s -> new Permissions()).add(permission);
        }
    }

    @Override
    public void addToRole(String roleName, PermissionCollection permissions) throws PolicyContextException {
        checkNotNullParam("roleName", roleName);
        checkNotNullParam("permissions", permissions);

        Enumeration<Permission> elements = permissions.elements();

        while (elements.hasMoreElements()) {
            addToRole(roleName, elements.nextElement());
        }
    }

    @Override
    public void addToUncheckedPolicy(Permission permission) throws PolicyContextException {
        checkNotNullParam("permission", permission);

        synchronized (this) { // prevents state change while adding
            checkIfInOpenState();
            this.uncheckedPermissions.add(permission);
        }
    }

    @Override
    public void addToUncheckedPolicy(PermissionCollection permissions) throws PolicyContextException {
        checkNotNullParam("permissions", permissions);

        Enumeration<Permission> elements = permissions.elements();

        while (elements.hasMoreElements()) {
            addToUncheckedPolicy(elements.nextElement());
        }
    }

    @Override
    public void commit() throws PolicyContextException {
        synchronized (this) { // prevents concurrent state changes
            if (isDeleted()) {
                throw log.authzInvalidStateForOperation(this.state.name());
            }

            transitionTo(State.IN_SERVICE);
        }
    }

    @Override
    public void delete() throws PolicyContextException {
        synchronized (this) { // prevents concurrent state changes
            transitionTo(State.DELETED);
            this.uncheckedPermissions = new Permissions();
            this.excludedPermissions = new Permissions();
            this.rolePermissions.clear();
            this.linkedPolicies.remove(this);
        }
    }

    @Override
    public String getContextID() throws PolicyContextException {
        return this.contextId;
    }

    @Override
    public boolean inService() {
        synchronized (this) {
            return State.IN_SERVICE.equals(this.state);
        }
    }

    @Override
    public void linkConfiguration(PolicyConfiguration link) throws PolicyContextException {
        checkNotNullParam("link", link);

        synchronized (this) { // prevents concurrent state changes
            checkIfInOpenState();
            if (getContextID().equals(link.getContextID())) {
                throw log.authzLinkSamePolicyConfiguration(getContextID());
            }

            this.linkedPolicies.add(this);

            if (!this.linkedPolicies.add(link)) {
                return;
            }

            ElytronPolicyConfiguration linkedPolicyConfiguration = (ElytronPolicyConfiguration) link;

            linkedPolicyConfiguration.linkConfiguration(this);
            // policies share the same set of linked policies, so we can remove policies from the set when they are deleted.
            this.linkedPolicies = linkedPolicyConfiguration.getLinkedPolicies();
        }
    }

    @Override
    public void removeExcludedPolicy() throws PolicyContextException {
        synchronized (this) { // prevents concurrent state changes
            checkIfInOpenState();
            this.excludedPermissions = new Permissions();
        }
    }

    @Override
    public void removeRole(String roleName) throws PolicyContextException {
        checkNotNullParam("roleName", roleName);
        checkNotNullParam("roleName", roleName);

        synchronized (this) { // prevents concurrent state changes
            checkIfInOpenState();
            this.rolePermissions.remove(roleName);
        }
    }

    @Override
    public void removeUncheckedPolicy() throws PolicyContextException {
        synchronized (this) { // prevents concurrent state changes
            checkIfInOpenState();
            this.uncheckedPermissions = new Permissions();
        }
    }

    Set<PolicyConfiguration> getLinkedPolicies() {
        return this.linkedPolicies; // volatile/atomic reference - no synchronization needed
    }

    Permissions getUncheckedPermissions() {
        return this.uncheckedPermissions; // volatile/atomic reference - no synchronization needed
    }

    Permissions getExcludedPermissions() {
        return this.excludedPermissions; // volatile/atomic reference - no synchronization needed
    }

    Map<String, Permissions> getRolePermissions() {
        return this.rolePermissions;
    }

    /* must not be called outside of synchronized(this) section */
    void transitionTo(State state) {
        this.state = state;
    }

    /* must not be called outside of synchronized(this) section */
    private void checkIfInOpenState() {
        if (!State.OPEN.equals(this.state)) {
            throw log.authzInvalidStateForOperation(this.state.name());
        }
    }

    /* must not be called outside of synchronized(this) section */
    private boolean isDeleted() {
        return State.DELETED.equals(this.state);
    }
}
