/*
 * Copyright 2020 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.authz.jacc;

import static org.wildfly.security.authz.jacc.ElytronMessages.log;
import static org.wildfly.security.authz.jacc.SecurityActions.doPrivileged;

import java.security.PrivilegedAction;

import javax.security.auth.Subject;

import org.wildfly.common.Assert;
import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.KeyPairCredential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.PublicKeyCredential;
import org.wildfly.security.credential.SecretKeyCredential;
import org.wildfly.security.credential.X509CertificateChainPrivateCredential;
import org.wildfly.security.credential.X509CertificateChainPublicCredential;

/**
 * Utilities for dealing with {@link Subject}.
 *
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
final class SubjectUtil {

    private static final boolean CONVERT_ROLES_TO_GROUP;

    static {
        /*
         * TODO - Once we can build the project using Java 17 we can likely
         * address this in a multi-release jar.
         */
        boolean convertRolesToGroup = false;
        try {
            Class.forName("java.security.acl.Group");
            convertRolesToGroup = true;
        } catch (ClassNotFoundException e) {
            log.trace("Class 'java.security.acl.Group' is not available, role to group mapping disabled.");
        }
        CONVERT_ROLES_TO_GROUP = convertRolesToGroup;
    }

    /**
     * Converts the supplied {@link SecurityIdentity} into a {@link Subject}.
     *
     * @param securityIdentity the {@link SecurityIdentity} to be converted.
     * @return the constructed {@link Subject} instance.
     */
    static Subject fromSecurityIdentity(final SecurityIdentity securityIdentity) {
        Assert.checkNotNullParam("securityIdentity", securityIdentity);
        Subject subject = new Subject();
        subject.getPrincipals().add(securityIdentity.getPrincipal());

        if (CONVERT_ROLES_TO_GROUP) {
            subject.getPrincipals().addAll(RoleToGroupMapper.convert(securityIdentity.getPrincipal(), securityIdentity.getRoles()));
        }

        // process the identity's public and private credentials.
        for (Credential credential : securityIdentity.getPublicCredentials()) {
            if (credential instanceof PublicKeyCredential) {
                subject.getPublicCredentials().add(credential.castAs(PublicKeyCredential.class).getPublicKey());
            }
            else if (credential instanceof X509CertificateChainPublicCredential) {
                subject.getPublicCredentials().add(credential.castAs(X509CertificateChainPublicCredential.class).getCertificateChain());
            }
            else {
                subject.getPublicCredentials().add(credential);
            }
        }

        for (Credential credential : doPrivileged((PrivilegedAction<IdentityCredentials>) securityIdentity::getPrivateCredentials)) {
            if (credential instanceof PasswordCredential) {
                addPrivateCredential(subject, credential.castAs(PasswordCredential.class).getPassword());
            }
            else if (credential instanceof SecretKeyCredential) {
                addPrivateCredential(subject, credential.castAs(SecretKeyCredential.class).getSecretKey());
            }
            else if (credential instanceof KeyPairCredential) {
                addPrivateCredential(subject, credential.castAs(KeyPairCredential.class).getKeyPair());
            }
            else if (credential instanceof X509CertificateChainPrivateCredential) {
                addPrivateCredential(subject, credential.castAs(X509CertificateChainPrivateCredential.class).getCertificateChain());
            }
            else {
                addPrivateCredential(subject, credential);
            }
        }

        // add the identity itself as a private credential - integration code can interact with the SI instead of the Subject if desired.
        addPrivateCredential(subject, securityIdentity);

        return subject;
    }

    static void addPrivateCredential(final Subject subject, final Object credential) {
        doPrivileged((PrivilegedAction<Void>) () -> {
            subject.getPrivateCredentials().add(credential);
            return null;
        });
    }

}
