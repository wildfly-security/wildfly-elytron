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

package org.wildfly.security.credential;

import static org.wildfly.common.Assert.checkNotNullParam;

/**
 * A {@link Credential} that usually holds an access security token.
 *
 * @author <a href="mailto:szaldana@redhat.com">Sonia Zaldana</a>
 */
public final class AccessTokenCredential implements Credential {

    private final String token;

    /**
     * Construct a new instance.
     *
     * @param token the access security token (must not be {@code null})
     */
    public AccessTokenCredential(String token) {
        this.token = checkNotNullParam("token", token);
    }

    /**
     * Get the access security token.
     *
     * @return the access security token
     */
    public String getToken() {
        return this.token;
    }

    public AccessTokenCredential clone() {
        return this;
    }

    public int hashCode() {
        return token.hashCode();
    }

    public boolean equals(final Object obj) {
        return obj instanceof AccessTokenCredential && token.equals(((AccessTokenCredential) obj).token);
    }
}
