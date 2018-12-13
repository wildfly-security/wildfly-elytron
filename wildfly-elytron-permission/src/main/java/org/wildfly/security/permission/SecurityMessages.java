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

import org.jboss.logging.Logger;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
@MessageLogger(projectCode = "WFSM")
public interface SecurityMessages {
    SecurityMessages permission = Logger.getMessageLogger(SecurityMessages.class, "org.wildfly.security.permission");

    @Message(id = 4, value = "Unexpected character '%s' at offset %d of '%s'")
    IllegalArgumentException unexpectedActionCharacter(char ch, int offset, String actionString);

    @Message(id = 5, value = "Invalid action '%s' at offset %d of '%s'")
    IllegalArgumentException invalidAction(String action, int offset, String actionString);
    
}
