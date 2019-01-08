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

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;

/**
 * Helper utility methods for callback handlers.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class CallbackUtil {

    private CallbackUtil() {
    }

    /**
     * Determine whether a callback is optional.
     *
     * @param callback the callback
     * @return {@code true} if it is optional, {@code false} if it is not optional or optionality could not be determined
     */
    public static boolean isOptional(Callback callback) {
        return callback instanceof ExtendedCallback && ((ExtendedCallback) callback).isOptional();
    }

    /**
     * A utility to handle a callback which is unsupported.  Optional callbacks will be ignored, otherwise the
     * exception will be thrown.  In the case of optional callbacks, this method <em>will</em> return.
     *
     * @param callback the callback which is not supported
     * @throws UnsupportedCallbackException if the callback is not optional
     */
    public static void unsupported(Callback callback) throws UnsupportedCallbackException {
        if (! isOptional(callback)) {
            throw new FastUnsupportedCallbackException(callback);
        }
    }
}
