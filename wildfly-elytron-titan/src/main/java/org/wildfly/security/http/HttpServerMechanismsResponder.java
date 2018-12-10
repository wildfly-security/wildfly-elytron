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

/**
 * A responder for sending either authentication challenges or responses as a result of successful authentication back to the
 * calling client.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@FunctionalInterface
public interface HttpServerMechanismsResponder {

    /**
     * Send any required response to the client.
     *
     * @param response the {@link HttpServerResponse} to use to set the response / challenge.
     */
    void sendResponse(HttpServerResponse response) throws HttpAuthenticationException;

}
