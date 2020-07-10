/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2019 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.auth.util;

import static org.wildfly.security.auth.util.ElytronMessages.log;

import java.io.IOException;

import javax.xml.stream.XMLStreamException;

import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.session.SessionContext;
import org.wildfly.common.function.ExceptionSupplier;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.source.CredentialSource;
import org.wildfly.security.password.interfaces.ClearPassword;

/**
 * An implementation of {@link FilePasswordProvider} which can provide the password to decrypt a private key using a
 * {@link CredentialSource} or {@link Credential}
 *
 * @author <a href="mailto:aabdelsa@redhat.com">Ashley Abdel-Sayed</a>
 */

public class ElytronFilePasswordProvider implements FilePasswordProvider {

    private final ExceptionSupplier<CredentialSource, XMLStreamException> credentialSourceSupplier;
    private final Credential credential;

    public ElytronFilePasswordProvider(ExceptionSupplier<CredentialSource, XMLStreamException> credentialSourceSupplier) {
        this.credentialSourceSupplier = credentialSourceSupplier;
        this.credential = null;
    }

    public ElytronFilePasswordProvider(Credential credential) {
        this.credentialSourceSupplier = null;
        this.credential = credential;
    }

    @Override
    public String getPassword(SessionContext session, NamedResource resourceKey, int retryIndex) throws IOException {
        char[] password = null;
        if (credentialSourceSupplier != null) {
            CredentialSource credentialSource = null;
            try {
                credentialSource = credentialSourceSupplier.get();
            } catch (XMLStreamException e) {
                throw log.xmlFailedToCreateCredential(e);
            }

            password = credentialSource.applyToCredential(PasswordCredential.class, c -> c.getPassword().castAndApply(ClearPassword.class, ClearPassword::getPassword));
        } else if (credential != null) {
            password = credential.castAndApply(PasswordCredential.class, c -> c.getPassword().castAndApply(ClearPassword.class, ClearPassword::getPassword));
        }

        if (password == null) {
            throw log.xmlFailedToCreateCredential(new NullPointerException());
        }
        return new String(password);
    }
}
