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
package org.wildfly.security.http;

import java.util.Map;

import javax.security.auth.callback.CallbackHandler;

/**
 * Factory to create authentication mechanisms.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public interface HttpServerAuthenticationMechanismFactory {

    /**
     * Get the names of the HTTP authentication mechanisms that can be supplied by this factory filtered by the supplied
     * properties.
     *
     * @param properties the selection criteria for the mechanisms.
     * @return the names of the supported HTTP authentication mechanisms.
     */
    String[] getMechanismNames(Map<String, ?> properties);


    /**
     * Obtain an instance of the authentication mechanism requested provided this is allowed by any policy specified within the supplied properties.
     *
     * @param mechanismName
     * @param properties
     * @param callbackHandler
     * @return
     */
    HttpServerAuthenticationMechanism createAuthenticationMechanism(String mechanismName, Map<String, ?> properties, CallbackHandler callbackHandler);

}
