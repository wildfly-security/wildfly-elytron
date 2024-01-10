/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2023 Red Hat, Inc., and individual contributors
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
import java.util.HashMap;

import static org.wildfly.common.Assert.checkNotNullParam;

/**
 * A {@link javax.security.auth.callback.Callback} to inform a server authentication context about current authentication request.
 *
 */
public class RequestInformationCallback implements ExtendedCallback {

    /**
     * Properties of the current authentication request
     */
    private final HashMap<String, Object> props;

    /**
     * Construct a new instance of this {@link Callback}.
     *
     * @param props Properties of the current authentication request
     */
    public  RequestInformationCallback(HashMap<String, Object> props) {
        checkNotNullParam("props", props);
        this.props = props;
    }

    /**
     * Get the properties of this request.
     *
     * @return properties of the current authentication request
     */
    public HashMap<String, Object> getProperties() {
        return this.props;
    }
}
