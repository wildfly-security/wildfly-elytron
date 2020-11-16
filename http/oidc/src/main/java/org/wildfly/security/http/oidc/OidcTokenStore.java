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

import java.util.List;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public interface OidcTokenStore {

    void logout(boolean glo);

    /**
     * Check if the current token exists. Refresh the token if it exists but is expired.
     */
    void checkCurrentToken();

    /**
     * Check if we are already logged in (i.e., check if we have a valid and successfully refreshed access token). If so,
     * establish the security context.
     *
     * @param authenticator used for actual request authentication
     * @return {@code true} if we are logged in already; {@code false} otherwise
     */
    boolean isCached(RequestAuthenticator authenticator);

    /**
     * Finish a successful login and store the validated account.
     *
     * @param account the validated account
     */
    void saveAccountInfo(OidcAccount account);

    /**
     * Handle logout on store side and possibly propagate logout call to the OIDC provider.
     */
    void logout();

    void logoutAll();

    void logoutHttpSessions(List<String> ids);

    /**
     * Callback invoked after a successful token refresh.
     *
     * @param securityContext context where refresh was performed
     */
    void refreshCallback(RefreshableOidcSecurityContext securityContext);

    /**
     * Save the request.
     */
    void saveRequest();

    /**
     * Restore the request.
     * @return {@code true} if the request was successfully restored; {@code false} otherwise
     */
    boolean restoreRequest();
}
