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

package org.wildfly.sasl.localuser;

import org.wildfly.sasl.util.AbstractSaslFactory;

/**
 * Base class for the {@code JBOSS-LOCAL-USER} SASL mechanism.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public abstract class LocalUserSaslFactory extends AbstractSaslFactory {

    public static final String JBOSS_LOCAL_USER = "JBOSS-LOCAL-USER";

    LocalUserSaslFactory() {
        super(JBOSS_LOCAL_USER);
    }

    protected boolean isPassCredentials() {
        return false;
    }

    protected boolean isDictionarySusceptible() {
        return false;
    }

    protected boolean isActiveSusceptible() {
        return false;
    }

    protected boolean isForwardSecrecy() {
        return false;
    }

    protected boolean isPlainText() {
        return false;
    }

    protected boolean isAnonymous() {
        return false;
    }
}
