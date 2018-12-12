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
package org.wildfly.security.audit;

/**
 * The priority level of an audit event.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public enum EventPriority {

    /** Emergency - system is unusable */
    EMERGENCY,

    /** Action must be taken immediately */
    ALERT,

    /** Critical condition */
    CRITICAL,

    /** Error condition */
    ERROR,

    /** Warning condition */
    WARNING,

    /** Normal but significant condition */
    NOTICE,

    /** Informational message */
    INFORMATIONAL,

    /** Message for debugging/troubleshooting */
    DEBUG,

    /** No message should be emitted */
    OFF;

}
