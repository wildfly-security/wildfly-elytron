/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.http.oidc;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
interface ServiceUrlConstants {

    public static final String AUTH_PATH = "/realms/{realm-name}/protocol/openid-connect/auth";
    public static final String TOKEN_PATH = "/realms/{realm-name}/protocol/openid-connect/token";
    public static final String TOKEN_SERVICE_LOGOUT_PATH = "/realms/{realm-name}/protocol/openid-connect/logout";
    public static final String ACCOUNT_SERVICE_PATH = "/realms/{realm-name}/account";
    public static final String REALM_INFO_PATH = "/realms/{realm-name}";
    public static final String CLIENTS_MANAGEMENT_REGISTER_NODE_PATH = "/realms/{realm-name}/clients-managements/register-node";
    public static final String CLIENTS_MANAGEMENT_UNREGISTER_NODE_PATH = "/realms/{realm-name}/clients-managements/unregister-node";
    public static final String JWKS_URL = "/realms/{realm-name}/protocol/openid-connect/certs";
}
