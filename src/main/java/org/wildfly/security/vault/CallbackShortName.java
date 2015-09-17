/*
 * JBoss, Home of Professional Open Source
 * Copyright 2015 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.vault;

/**
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>.
 */
public enum CallbackShortName {

    /**
     * Callback short name for using {EXT} type of call as known from older Vault implementations.
     */
    EXT(ExtCallback.class.getName()),

    /**
     * Callback short name for using {CMD} type of call as known from older Vault implementations.
     */
    CMD(CmdCallback.class.getName()),

    /**
     * Callback short name for using {CLASS} type of call as known from older Vault implementations.
     */
    CLASS(ClassCallback.class.getName()),

    /**
     * Callback short name for MASKED callback used to decrypt PBE masked passwords.
     */
    MASKED(MaskedPasswordCallback.class.getName()),
    ;

    private final String className;

    CallbackShortName(final String className) {
        this.className = className;
    }

    /**
     * Get class name behind the shorten name.
     * @return className of this short name
     */
    public final String get() {
        return className;
    }

}
