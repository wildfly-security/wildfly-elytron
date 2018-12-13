/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
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

import java.io.InvalidObjectException;
import java.security.Permission;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;

/**
 * Log messages and exceptions for Elytron.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@MessageLogger(projectCode = "ELY", length = 5)
interface ElytronMessages extends BasicLogger {

    ElytronMessages log = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security");

    @Message(id = 3013, value = "Permission collection must be read-only")
    SecurityException permissionCollectionMustBeReadOnly();
    
    @Message(id = 3015, value = "Could not load permission class \"%s\"")
    InvalidPermissionClassException permissionClassMissing(String className, @Cause ClassNotFoundException cause);
    
    @Message(id = 3016, value = "Could not instantiate permission class \"%s\"")
    InvalidPermissionClassException permissionInstantiation(String className, @Cause Throwable cause);
    
    @Message(id = 3017, value = "No valid permission constructor found on class \"%s\"")
    InvalidPermissionClassException noPermissionConstructor(String className);
    
    @Message(id = 3018, value = "Cannot add permissions to a read-only permission collection")
    SecurityException readOnlyPermissionCollection();

    @Message(id = 3019, value = "Failure to deserialize object: field \"%s\" is null")
    InvalidObjectException invalidObjectNull(String fieldName);
    
    @Message(id = 3020, value = "Expected empty actions string, got \"%s\"")
    IllegalArgumentException expectedEmptyActions(String actions);
    
    @Message(id = 3021, value = "Invalid permission type; expected %s, got %s")
    IllegalArgumentException invalidPermissionType(Class<? extends Permission> expected, Permission actual);
    
    @Message(id = 3022, value = "Permission check failed: %s is not implied by %s")
    SecurityException permissionCheckFailed(Permission permission, PermissionVerifier permissionVerifier);
    
}
