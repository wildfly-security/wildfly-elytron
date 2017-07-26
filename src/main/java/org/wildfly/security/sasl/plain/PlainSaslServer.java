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

package org.wildfly.security.sasl.plain;

import static org.wildfly.security._private.ElytronMessages.log;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.NoSuchElementException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;

import org.wildfly.security.auth.callback.EvidenceVerifyCallback;
import org.wildfly.security.auth.callback.IdentityCredentialCallback;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.evidence.PasswordGuessEvidence;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.sasl.util.SaslMechanismInformation;
import org.wildfly.security.sasl.util.SaslWrapper;
import org.wildfly.security.util.CodePointIterator;

/**
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
final class PlainSaslServer implements SaslServer, SaslWrapper {

    private final CallbackHandler callbackHandler;
    private boolean complete;
    private String authorizedId;

    /**
     * Construct a new instance.
     *
     * @param callbackHandler the callback handler
     */
    public PlainSaslServer(final CallbackHandler callbackHandler) {
        this.callbackHandler = callbackHandler;
    }

    @Override
    public String getAuthorizationID() {
        if (! isComplete()) {
            throw log.mechAuthenticationNotComplete(getMechanismName());
        }
        return authorizedId;
    }

    @Override
    public String getMechanismName() {
        return SaslMechanismInformation.Names.PLAIN;
    }

    @Override
    public boolean isComplete() {
        return complete;
    }

    @Override
    public byte[] evaluateResponse(final byte[] response) throws SaslException {
        if (complete) {
            throw log.mechMessageAfterComplete(getMechanismName()).toSaslException();
        }
        complete = true;
        if (response.length >= 65536) {
            throw log.mechMessageTooLong(getMechanismName()).toSaslException();
        }
        CodePointIterator i = CodePointIterator.ofUtf8Bytes(response);
        String authorizationId;
        String loginName;
        String password;
        try {
            final CodePointIterator delimIter = i.delimitedBy(0);
            authorizationId = delimIter.hasNext() ? delimIter.drainToString() : null;
            i.next(); // skip delimiter
            loginName = delimIter.drainToString();
            i.next(); // skip delimiter
            password = delimIter.drainToString();
            if (authorizationId == null || authorizationId.isEmpty()) {
                authorizationId = loginName;
            }
        } catch (NoSuchElementException ignored) {
            throw log.mechInvalidMessageReceived(getMechanismName()).toSaslException();
        }

        // The message has now been parsed, split and converted to UTF-8 Strings
        // now it is time to use the CallbackHandler to validate the supplied credentials.

        // First verify username and password.

        NameCallback ncb = new NameCallback("PLAIN authentication identity", loginName);
        final PasswordGuessEvidence evidence = new PasswordGuessEvidence(password.toCharArray());
        EvidenceVerifyCallback evc = new EvidenceVerifyCallback(evidence);

        try {
            callbackHandler.handle(new Callback[] { ncb, evc });
        } catch (SaslException e) {
            throw e;
        } catch (IOException | UnsupportedCallbackException e) {
            throw log.mechServerSideAuthenticationFailed(getMechanismName(), e).toSaslException();
        } finally {
            evidence.destroy();
        }

        if (evc.isVerified() == false) {
            throw log.mechPasswordNotVerified(getMechanismName()).toSaslException();
        }

        // Propagate the identity to interested callback handlers

        try {
            final PasswordFactory factory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR);
            final Password clearPassword = factory.generatePassword(new ClearPasswordSpec(password.toCharArray()));
            callbackHandler.handle(new Callback[] { new IdentityCredentialCallback(new PasswordCredential(clearPassword), true) } );
        } catch (UnsupportedCallbackException e) {
            // ignored
        } catch (SaslException e) {
            throw e;
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw log.mechServerSideAuthenticationFailed(getMechanismName(), e).toSaslException();
        }

        // Now check the authorization id

        AuthorizeCallback acb = new AuthorizeCallback(loginName, authorizationId);
        try {
            callbackHandler.handle(new Callback[] { acb });
        } catch (SaslException e) {
            throw e;
        } catch (IOException | UnsupportedCallbackException e) {
            throw log.mechServerSideAuthenticationFailed(getMechanismName(), e).toSaslException();
        }

        if (acb.isAuthorized() == true) {
            authorizedId = acb.getAuthorizedID();
        } else {
            throw log.mechAuthorizationFailed(getMechanismName(), loginName, authorizationId).toSaslException();
        }
        return null;
    }

    @Override
    public byte[] unwrap(final byte[] incoming, final int offset, final int len) throws SaslException {
        if (complete) {
            throw log.mechNoSecurityLayer(getMechanismName());
        } else {
            throw log.mechAuthenticationNotComplete(getMechanismName());
        }
    }

    @Override
    public byte[] wrap(final byte[] outgoing, final int offset, final int len) throws SaslException {
        if (complete) {
            throw log.mechNoSecurityLayer(getMechanismName());
        } else {
            throw log.mechAuthenticationNotComplete(getMechanismName());
        }
    }

    @Override
    public Object getNegotiatedProperty(final String propName) {
        return null;
    }

    @Override
    public void dispose() throws SaslException {
    }
}
