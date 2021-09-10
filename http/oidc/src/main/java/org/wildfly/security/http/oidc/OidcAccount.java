/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2020 Red Hat, Inc., and individual contributors
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

import static org.wildfly.security.http.oidc.ElytronMessages.log;

import java.io.Serializable;
import java.security.Principal;
import java.util.HashSet;
import java.util.Set;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class OidcAccount implements Serializable {

    private static final long serialVersionUID = -2871833856346510925L;
    private final OidcPrincipal<RefreshableOidcSecurityContext> principal;

    public OidcAccount(OidcPrincipal<RefreshableOidcSecurityContext> principal) {
        this.principal = principal;
    }

    public RefreshableOidcSecurityContext getOidcSecurityContext() {
        return principal.getOidcSecurityContext();
    }

    public Principal getPrincipal() {
        return principal;
    }

    public Set<String> getRoles() {
        Set<String> roles = new HashSet<>();
        return roles;
    }

    void setCurrentRequestInfo(OidcClientConfiguration deployment, OidcTokenStore tokenStore) {
        principal.getOidcSecurityContext().setCurrentRequestInfo(deployment, tokenStore);
    }

    public boolean checkActive() {
        RefreshableOidcSecurityContext session = getOidcSecurityContext();
        if (session.isActive() && ! session.getOidcClientConfiguration().isAlwaysRefreshToken()) {
            log.debug("session is active");
            return true;
        }
        log.debug("session not active");
        return false;
    }

    boolean tryRefresh() {
        log.debug("Trying to refresh");
        RefreshableOidcSecurityContext securityContext = getOidcSecurityContext();
        if (securityContext == null) {
            log.debug("No security context. Aborting refresh.");
        }
        if (securityContext.refreshToken(false)) {
            log.debug("refresh succeeded");
            return true;
        }
        return checkActive();
    }
}
