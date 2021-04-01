/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2021 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.auth.server.jwt;

/**
 * The exception thrown when there is a loading public and private keys in JWT
 * configuration
 * @author <a href="mailto:szaldana@redhat.com">Sonia Zaldana</a>
 */
public class LoadingKeyException extends Exception {
    private static final long serialVersionUID = 2L;

    public LoadingKeyException(String message) {
        super(message);
    }

    public LoadingKeyException(String message, Throwable cause) {
        super(message, cause);
    }
}
