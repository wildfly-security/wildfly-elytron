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

package org.wildfly.security;

/**
 * A privileged action which accepts a parameter and can throw an exception.
 *
 * @param <T> the action result type
 * @param <P> the action parameter type
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public interface ParametricPrivilegedExceptionAction<T, P> {

    /**
     * Perform the action.
     *
     * @param parameter the passed-in parameter
     * @return the action result
     * @throws Exception if the action fails
     */
    T run(P parameter) throws Exception;
}
