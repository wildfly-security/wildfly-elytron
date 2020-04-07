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

package org.wildfly.security.credential;

import java.io.File;
import java.util.Arrays;
import java.util.Objects;
import org.wildfly.common.Assert;
import org.wildfly.common.math.HashMath;

/**
 * A credential holding the location, key identity and passphrase (instance of {@code Credential}) of a Private key in an external
 * file and/or the name of the file containing the known hosts
 *
 * @author <a href="mailto:aabdelsa@redhat.com">Ashley Abdel-Sayed</a>
 */
public class SSHCredential implements Credential {

    public static File DEFAULT_SSH_DIRECTORY = new File(System.getProperty("user.home"), ".ssh");
    public static String[] DEFAULT_PRIVATE_KEYS = new String[]{"id_rsa", "id_dsa", "id_ecdsa"};
    public static String DEFAULT_KNOWN_HOSTS = "known_hosts";

    private final File sshDirectory;
    private final String[] privateKeyIdentities;
    private final Credential passphrase;
    private final String knownHostsFile;

    /**
     * @param sshDirectory the ssh directory
     * @param privateKeyIdentities an array containing the name of the file(s) containing the private key
     * @param passphrase the passphrase used to decrypt the private key (if applicable)
     * @param knownHostsFile the name of the file containing the known hosts
     */
    private SSHCredential(File sshDirectory, String[] privateKeyIdentities, Credential passphrase, String knownHostsFile) {
        this.sshDirectory = sshDirectory;
        this.privateKeyIdentities = privateKeyIdentities;
        this.passphrase = passphrase;
        this.knownHostsFile = knownHostsFile;
    }

    /**
     * Get the SSH directory containing the private key file and known hosts file
     * @return the SSH directory
     */
    public File getSshDirectory() {
        return this.sshDirectory;
    }

    /**
     * Get the list of private key file names
     * @return the private key identities
     */
    public String[] getPrivateKeyIdentities() {
        return this.privateKeyIdentities;
    }

    /**
     * Get the passphrase used to decrypt the private key
     * @return the passphrase
     */
    public Credential getPassphrase() {
        return this.passphrase;
    }

    /**
     * Get the file containing the known SSH hosts
     * @return the known hosts file name
     */
    public String getKnownHostsFile() {
        return this.knownHostsFile;
    }

    @Override
    public Credential clone() {
        return this;
    }

    public int hashCode() {
        int result = HashMath.multiHashOrdered(getClass().hashCode(), sshDirectory.hashCode());
        result = HashMath.multiHashOrdered(result, Arrays.hashCode(privateKeyIdentities));
        result = HashMath.multiHashOrdered(result, passphrase.hashCode());
        result = HashMath.multiHashOrdered(result, knownHostsFile.hashCode());
        return result;
    }

    public boolean equals(final Object obj) {
        return obj instanceof SSHCredential && equals((SSHCredential) obj);
    }

    private boolean equals(final SSHCredential obj) {
        return Objects.equals(sshDirectory, obj.sshDirectory) && Objects.equals(privateKeyIdentities, obj.privateKeyIdentities)
                && passphrase.equals(obj.passphrase) && knownHostsFile.equals(obj.knownHostsFile);
    }

    /**
     * A builder for SSHCredential.
     */
    public static class Builder {
        private File sshDirectory;
        private String[] privateKeyIdentities;
        private Credential passphrase;
        private String knownHostsFile;

        /**
         * Construct a new instance.
         */
        Builder() {
        }

        /**
         * The path to the ssh directory containing the private key file and known hosts file
         * @param sshDirectory the ssh directory
         * @return this builder instance
         */
        public Builder setSSHDirectory(final String sshDirectory) {
            Assert.assertNotNull(sshDirectory);
            this.sshDirectory = new File(sshDirectory);
            return this;
        }

        /**
         * The path to the ssh directory containing the private key file and known hosts file
         * @param sshDirectory the ssh directory
         * @return this builder instance
         */
        public Builder setSSHDirectory(final File sshDirectory) {
            Assert.assertNotNull(sshDirectory);
            this.sshDirectory = sshDirectory;
            return this;
        }

        /**
         * The name of the file containing the private key
         * @param privateKeyIdentity the name of the private key file
         * @return this builder instance
         */
        public Builder setPrivateKeyIdentity(final String privateKeyIdentity) {
            Assert.assertNotNull(privateKeyIdentity);
            return this.setPrivateKeyIdentities(new String[]{privateKeyIdentity});
        }

        /**
         * An array of the names of files containing private keys
         * @param privateKeyIdentities the names of the private key files
         * @return this builder instance
         */
        public Builder setPrivateKeyIdentities(final String[] privateKeyIdentities) {
            Assert.assertNotNull(privateKeyIdentities);
            this.privateKeyIdentities = privateKeyIdentities;
            return this;
        }

        /**
         * The passphrase needed to decrypt the private key
         * @param passphrase the passphrase used to decrypt the private key
         * @return this builder instance
         */
        public Builder setPassphrase(final Credential passphrase) {
            Assert.assertNotNull(passphrase);
            this.passphrase = passphrase;
            return this;
        }

        /**
         * The name of the file containing the known hosts file
         * @param knownHostsFile the name of the file containing the known SSH hosts
         * @return this builder instance
         */
        public Builder setKnownHostsFile(final String knownHostsFile) {
            Assert.assertNotNull(knownHostsFile);
            this.knownHostsFile = knownHostsFile;
            return this;
        }

        /**
         * Build a new instance of SSHCredential.
         *
         * @return a new SSHCredential instance
         */
        public SSHCredential build() {
            if (this.sshDirectory == null) this.sshDirectory = DEFAULT_SSH_DIRECTORY;
            if (this.privateKeyIdentities == null || this.privateKeyIdentities.length == 0) {
                this.privateKeyIdentities = DEFAULT_PRIVATE_KEYS;
            }
            if (this.knownHostsFile == null) this.knownHostsFile = DEFAULT_KNOWN_HOSTS;
            return new SSHCredential(this.sshDirectory, this.privateKeyIdentities, this.passphrase, this.knownHostsFile);
        }
    }

    public static Builder builder() {
        return new Builder();
    }
}
