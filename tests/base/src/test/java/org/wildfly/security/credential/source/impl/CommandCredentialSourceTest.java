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

package org.wildfly.security.credential.source.impl;

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;

import org.junit.Test;
import org.wildfly.security.WildFlyElytronPasswordProvider;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.interfaces.ClearPassword;

// has dependency on wildfly-credential-source-deprecated
public class CommandCredentialSourceTest {
    @Test
    public void testCommand() throws GeneralSecurityException, IOException {
        final CommandCredentialSource.Builder builder = getBuilder();
        builder.addCommand("secret_key_THREE");
        final CommandCredentialSource credentialSource = builder.build();
        final PasswordCredential credential = credentialSource.getCredential(PasswordCredential.class);
        assertNotNull(credential);
        final Password password = credential.castAndApply(PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR, PasswordCredential::getPassword);
        assertNotNull(password);
        final ClearPassword clearPassword = password.castAs(ClearPassword.class, ClearPassword.ALGORITHM_CLEAR);
        assertNotNull(clearPassword);
        assertEquals(new String(clearPassword.getPassword()), "secret_key_THREE");
    }

    private static CommandCredentialSource.Builder getBuilder() {
        final CommandCredentialSource.Builder builder = CommandCredentialSource.builder();
        builder.setPasswordFactoryProvider(WildFlyElytronPasswordProvider.getInstance());
        addJava(builder);
        addCommand(builder);
        return builder;
    }

    private static void addJava(final CommandCredentialSource.Builder builder) {
        // First check for java.exe or java as the binary
        File java = new File(System.getProperty("java.home"), "/bin/java");
        File javaExe = new File(System.getProperty("java.home"), "/bin/java.exe");
        builder.addCommand(java.exists() ? java.getAbsolutePath() : javaExe.getAbsolutePath());
    }

    private static void addCommand(final CommandCredentialSource.Builder builder) {
        builder.addCommand("-cp").addCommand(System.getProperty("java.class.path")).addCommand(CredentialCommand.class.getName());
    }

    private static String buildExternalCommand(final String extOption, final String delimiter, final String argument) {
        // First check for java.exe or java as the binary
        File java = new File(System.getProperty("java.home"), "/bin/java");
        File javaExe = new File(System.getProperty("java.home"), "/bin/java.exe");
        String jre;
        if (java.exists())
            jre = java.getAbsolutePath();
        else
            jre = javaExe.getAbsolutePath();
        // Build the command to run this jre
        String cmd = jre + delimiter + "-cp" + delimiter + System.getProperty("java.class.path") + delimiter
                + CredentialCommand.class.getName() + (argument != null ? delimiter + argument : "");
        return extOption + cmd;
    }

}
