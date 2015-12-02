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
package org.wildfly.security.credential.store.external;

import javax.security.auth.callback.CallbackHandler;

/**
 * Interface to implement when custom callback handler is needed. Implementation has to be specified in Vault configuration {@code URI}.
 * This gives the user ability to influence callback interpretation.
 * Callback handler can receive configuration parameters through {@link #initialize(String[])} method which will be called automatically
 * by {@code VaultManager}.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>.
 */
public interface ParametrizedCallbackHandler extends CallbackHandler {
    /**
     * Initialize callback handler with parameters.
     * @param parameters to initialize the callback handler
     */
    void initialize(String[] parameters);
}
