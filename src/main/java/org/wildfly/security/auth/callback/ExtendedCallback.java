/*
 * JBoss, Home of Professional Open Source
 * Copyright 2013 Red Hat, Inc., and individual contributors
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

import javax.security.auth.callback.Callback;

/**
 * A callback which provides extended information about its usage.
 * <p>
 * For example, the following code can be used to detect an optional callback instead of failing if the callback is
 * unrecognized:
 * <pre>{@code
    if (callback instanceof ExtendedCallback && ((ExtendedCallback) callback).isOptional()) {
        // The callback is harmless
        return;
    }
    // Let the caller know that we failed to support this callback
    throw new UnsupportedCallbackException(callback);
 * }</pre>
 * Or, the utility method in {@link CallbackUtil} can be used:
 * <pre>{@code
    CallbackUtils.unsupported(callback);
 * }</pre>
 */
public interface ExtendedCallback extends Callback {

    /**
     * Determine if this callback is optional.
     *
     * @return {@code true} if the callback is optional, {@code false} if it is mandatory
     */
    boolean isOptional();

    /**
     * Determine if this callback is requesting information.
     *
     * @return {@code true} if the callback is requesting information, {@code false} if it is only providing information
     */
    boolean needsInformation();
}
