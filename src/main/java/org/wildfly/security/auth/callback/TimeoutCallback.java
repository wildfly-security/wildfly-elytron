/*
 * JBoss, Home of Professional Open Source.
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

package org.wildfly.security.auth.callback;

import java.io.Serializable;

/**
 * A server-side callback used to pass authentication timeout information from the callback handler
 * to the authentication mechanism.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public final class TimeoutCallback implements ExtendedCallback, Serializable {

    private static final long serialVersionUID = -2664543262262862516L;

    /**
     * @serial The timeout.
     */
    private long timeout;

    /**
     * Construct a new instance.
     */
    public TimeoutCallback() {
    }

    /**
     * Get the timeout.
     *
     * @return the time at which an authentication attempt should time out, in seconds since 1970-01-01T00:00:00Z
     */
    public long getTimeout() {
        return timeout;
    }

    /**
     * Set the timeout.
     *
     * @param timeout the time at which an authentication attempt should time out, in seconds since 1970-01-01T00:00:00Z
     */
    public void setTimeout(final long timeout) {
        this.timeout = timeout;
    }

    public boolean isOptional() {
        return false;
    }

    public boolean needsInformation() {
        return true;
    }
}
