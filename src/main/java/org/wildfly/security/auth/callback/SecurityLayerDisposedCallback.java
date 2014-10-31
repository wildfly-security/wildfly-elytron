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

package org.wildfly.security.auth.callback;

/**
 * A callback which indicates that the corresponding security layer (SASL client, SASL server, etc.) has been disposed
 * and any related resources may be relinquished.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class SecurityLayerDisposedCallback extends AbstractExtendedCallback {

    private static final long serialVersionUID = 3720690487735346163L;

    private static final SecurityLayerDisposedCallback INSTANCE = new SecurityLayerDisposedCallback();

    private SecurityLayerDisposedCallback() {
    }

    /**
     * Get the singleton instance.
     *
     * @return the singleton instance
     */
    public static SecurityLayerDisposedCallback getInstance() {
        return INSTANCE;
    }

    Object readResolve() {
        return INSTANCE;
    }

    Object writeReplace() {
        return INSTANCE;
    }
}
