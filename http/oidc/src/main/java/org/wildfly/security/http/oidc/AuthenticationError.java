/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2021 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wildfly.security.http.oidc;

/**
 * Indicates an OIDC related authentication error. For servlets, you'll be able to extract
 * this error from the HttpServletRequest.getAttribute(AuthenticationError.class.getName()).
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class AuthenticationError {
    public enum Reason {
        NO_BEARER_TOKEN,
        NO_REDIRECT_URI,
        INVALID_STATE_COOKIE,
        OAUTH_ERROR,
        SSL_REQUIRED,
        CODE_TO_TOKEN_FAILURE,
        INVALID_TOKEN,
        STALE_TOKEN,
        NO_AUTHORIZATION_HEADER,
        NO_QUERY_PARAMETER_ACCESS_TOKEN
    }

    private Reason reason;
    private String description;

    public AuthenticationError(Reason reason, String description) {
        this.reason = reason;
        this.description = description;
    }

    public Reason getReason() {
        return reason;
    }

    public String getDescription() {
        return description;
    }

    @Override
    public String toString() {
        return "AuthenticationError [reason=" + reason + ", description=" + description + "]";
    }

}
