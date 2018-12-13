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
package org.wildfly.security.evidence;

import org.wildfly.common.Assert;

/**
 * A piece of evidence that is comprised of a bearer security token.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public final class BearerTokenEvidence implements Evidence {

    private final String token;

    /**
     * Construct a new instance.
     *
     * @param token the bearer security token (must not be {@code null})
     */
    public BearerTokenEvidence(String token) {
        this.token = Assert.checkNotNullParam("token", token);
    }

    /**
     * Get the bearer security token.
     *
     * @return the bearer security token
     */
    public String getToken() {
        return this.token;
    }
}
