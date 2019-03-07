/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.mechanism.http;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.RealmCallback;

import org.wildfly.security.auth.callback.AuthenticationCompleteCallback;
import org.wildfly.security.auth.callback.EvidenceVerifyCallback;
import org.wildfly.security.auth.callback.IdentityCredentialCallback;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.evidence.PasswordGuessEvidence;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.password.interfaces.ClearPassword;

import static org.wildfly.security.mechanism.http.ElytronMessages.httpUserPass;

/**
 * A base class for HTTP mechanisms that operate on validation of plain text usernames and passwords.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public abstract class UsernamePasswordAuthenticationMechanism implements HttpServerAuthenticationMechanism {

    protected final CallbackHandler callbackHandler;

    /**
     * @param callbackHandler
     */
    protected UsernamePasswordAuthenticationMechanism(CallbackHandler callbackHandler) {
        super();
        this.callbackHandler = callbackHandler;
    }

    protected boolean authenticate(String realmName, String username, char[] password) throws HttpAuthenticationException {
        RealmCallback realmCallback = realmName != null ? new RealmCallback("User realm", realmName) : null;
        NameCallback nameCallback = new NameCallback("Remote Authentication Name", username);
        nameCallback.setName(username);
        final PasswordGuessEvidence evidence = new PasswordGuessEvidence(password);
        EvidenceVerifyCallback evidenceVerifyCallback = new EvidenceVerifyCallback(evidence);

        httpUserPass.debugf("Username authentication. Realm: [%s], Username: [%s].",
                realmName, username);

        try {
            final Callback[] callbacks;
            if (realmCallback != null) {
                callbacks = new Callback[] { realmCallback, nameCallback, evidenceVerifyCallback };
            } else {
                callbacks = new Callback[] { nameCallback, evidenceVerifyCallback };
            }

            callbackHandler.handle(callbacks);

            if(evidenceVerifyCallback.isVerified()) {
                IdentityCredentialCallback credentialUpdateCallback = new IdentityCredentialCallback(new PasswordCredential(ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, password)), true);
                callbackHandler.handle(new Callback[]{credentialUpdateCallback});
                return true;
            } else {
                return false;
            }
        } catch (UnsupportedCallbackException e) {
            return false;
        } catch (IOException e) {
            throw new HttpAuthenticationException(e);
        } finally {
            evidence.destroy();
        }
    }

    protected boolean authorize(String username) throws HttpAuthenticationException {
        httpUserPass.debugf("Username authorization. Username: [%s].",
                username);

        AuthorizeCallback authorizeCallback = new AuthorizeCallback(username, username);

        try {
            callbackHandler.handle(new Callback[] {authorizeCallback});

            return authorizeCallback.isAuthorized();
        } catch (UnsupportedCallbackException e) {
            return false;
        } catch (IOException e) {
            throw new HttpAuthenticationException(e);
        }
    }

    protected void succeed() throws IOException, UnsupportedCallbackException {
        callbackHandler.handle(new Callback[] { AuthenticationCompleteCallback.SUCCEEDED });
    }

    protected void fail() throws IOException, UnsupportedCallbackException {
        callbackHandler.handle(new Callback[] { AuthenticationCompleteCallback.FAILED });
    }

}
