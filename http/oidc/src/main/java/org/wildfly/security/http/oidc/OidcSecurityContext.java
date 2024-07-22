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

import static org.wildfly.security.http.oidc.ElytronMessages.log;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;

import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;

/**
 * Available in secured requests under HttpServletRequest.getAttribute().
 * Also available in HttpSession.getAttribute under the classname of this class.
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class OidcSecurityContext implements Serializable {
    protected String tokenString;
    protected String idTokenString;

    // Don't store parsed tokens into HTTP session
    protected transient AccessToken token;
    protected transient IDToken idToken;

    public OidcSecurityContext() {
    }

    public OidcSecurityContext(String tokenString, AccessToken token, String idTokenString, IDToken idToken) {
        this.tokenString = tokenString;
        this.token = token;
        this.idToken = idToken;
        this.idTokenString = idTokenString;
    }

    public AccessToken getToken() {
        return token;
    }

    public String getTokenString() {
        return tokenString;
    }

    public IDToken getIDToken() {
        return idToken;
    }

    public String getIDTokenString() {
        return idTokenString;
    }

    public String getRealm() {
        // assumes that issuer contains realm name
        return token.getIssuer().substring(token.getIssuer().lastIndexOf('/') + 1);
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        try {
            token = tokenString == null ? null : new AccessToken(new JwtConsumerBuilder().setSkipSignatureVerification().setSkipAllValidators().build().processToClaims(tokenString));
            idToken = idTokenString == null ? null : new IDToken(new JwtConsumerBuilder().setSkipSignatureVerification().setSkipAllValidators().build().processToClaims(idTokenString));
        } catch (InvalidJwtException e) {
            throw log.unableToParseToken();
        }
    }
}
