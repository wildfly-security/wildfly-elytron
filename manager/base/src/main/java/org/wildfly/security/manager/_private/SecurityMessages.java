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

package org.wildfly.security.manager._private;

import java.security.AccessControlException;
import java.security.CodeSource;
import java.security.Permission;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.LogMessage;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;
import org.jboss.logging.annotations.Param;

import static org.jboss.logging.Logger.Level.DEBUG;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
@MessageLogger(projectCode = "WFSM")
public interface SecurityMessages extends BasicLogger {
    SecurityMessages access = Logger.getMessageLogger(SecurityMessages.class, "org.wildfly.security.access");
    SecurityMessages permission = Logger.getMessageLogger(SecurityMessages.class, "org.wildfly.security.permission");

    @LogMessage(level = DEBUG)
    @Message(value = "Permission check failed (permission \"%s\" in code source \"%s\" of \"%s\", principals \"%s\")")
    void accessCheckFailed(Permission permission, CodeSource codeSource, ClassLoader classLoader, String principals);

    @LogMessage(level = DEBUG)
    @Message(value = "Permission check failed (permission \"%s\" in code source \"%s\" of \"%s\")")
    void accessCheckFailed(Permission permission, CodeSource codeSource, ClassLoader classLoader);

    @Message(id = 1, value = "Permission check failed (permission \"%s\" in code source \"%s\" of \"%s\")")
    AccessControlException accessControlException(@Param Permission permission, Permission permission_, CodeSource codeSource, ClassLoader classLoader);

    @Message(id = 2, value = "Security manager may not be changed")
    SecurityException secMgrChange();

    @Message(id = 3, value = "Unknown security context type")
    SecurityException unknownContext();

//    @Message(id = 4, value = "Unexpected character '%s' at offset %d of '%s'")
//    IllegalArgumentException unexpectedActionCharacter(char ch, int offset, String actionString);

//    @Message(id = 5, value = "Invalid action '%s' at offset %d of '%s'")
//    IllegalArgumentException invalidAction(String action, int offset, String actionString);

    @Message(id = 6, value = "Invalid permission name '%s'")
    IllegalArgumentException invalidName(String name);

    @Message(id = 7, value = "Permission collection is read-only")
    SecurityException readOnlyPermCollection();

    @Message(id = 8, value = "Invalid permission (expected an instance of %s, but got %s)")
    IllegalArgumentException wrongPermType(Class<? extends Permission> expectedType, Permission permission);
}
