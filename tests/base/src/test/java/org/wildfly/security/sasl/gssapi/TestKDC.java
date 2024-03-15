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

package org.wildfly.security.sasl.gssapi;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.ldif.LdifEntry;
import org.apache.directory.api.ldap.model.ldif.LdifReader;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.server.core.api.CoreSession;
import org.apache.directory.server.core.api.DirectoryService;
import org.apache.directory.server.core.api.partition.Partition;
import org.apache.directory.server.core.factory.DefaultDirectoryServiceFactory;
import org.apache.directory.server.core.factory.DirectoryServiceFactory;
import org.apache.directory.server.core.factory.PartitionFactory;
import org.apache.directory.server.core.kerberos.KeyDerivationInterceptor;
import org.apache.directory.server.kerberos.shared.crypto.encryption.KerberosKeyFactory;
import org.apache.directory.server.ldap.LdapServer;
import org.apache.directory.server.protocol.shared.transport.TcpTransport;
import org.apache.directory.server.protocol.shared.transport.Transport;
import org.apache.directory.shared.kerberos.codec.types.EncryptionType;
import org.apache.directory.shared.kerberos.components.EncryptionKey;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.keytab.Keytab;
import org.apache.kerby.kerberos.kerb.keytab.KeytabEntry;
import org.apache.kerby.kerberos.kerb.server.SimpleKdcServer;
import org.apache.kerby.kerberos.kerb.server.impl.DefaultInternalKdcServerImpl;
import org.apache.kerby.kerberos.kerb.type.KerberosTime;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.jboss.logging.Logger;


/**
 * Utility class to wrap starting and stopping of the directory server and the KDC.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class TestKDC {
    public static final int LDAP_PORT = 11390;
    private static Logger log = Logger.getLogger(TestKDC.class);
    private File workingDir;
    private DirectoryService directoryService;
    private SimpleKdcServer kdcServer;
    private String originalConfig;
    private boolean exposeLdapServer;
    private LdapServer ldapServer;

    public TestKDC(boolean exposeLdapServer) {
        this.exposeLdapServer = exposeLdapServer;
    }

    public void startDirectoryService() {
        if (directoryService != null) {
            throw new IllegalStateException("DirectoryService already started");
        }
        createWorkingDir();

        try {
            DirectoryServiceFactory dsf = new DefaultDirectoryServiceFactory();
            DirectoryService ds = dsf.getDirectoryService();

            dsf.init("Test Service");

            ds.getChangeLog().setEnabled(false);

            ds.addLast(new KeyDerivationInterceptor());

            SchemaManager schemaManager = ds.getSchemaManager();
            createPartition(dsf, schemaManager, "wildfly", "dc=wildfly,dc=org", ds, workingDir, "uid", "krb5PrincipalName");

            CoreSession adminSession = ds.getAdminSession();
            processLdif(schemaManager, adminSession, "/KerberosTesting.ldif");

            directoryService = ds;

            if (exposeLdapServer) {
                ldapServer = new LdapServer();
                ldapServer.setServiceName("DefaultLDAP");
                Transport ldap = new TcpTransport("localhost", LDAP_PORT, 3, 5);
                ldapServer.addTransports(ldap);
                ldapServer.setDirectoryService(directoryService);
                ldapServer.start();
            }
        } catch (Exception e) {
            throw new IllegalStateException("Unable to initialise DirectoryService", e);
        }
    }

    private static void createPartition(final DirectoryServiceFactory dsf, final SchemaManager schemaManager, final String id,
            final String suffix, final DirectoryService directoryService, final File workingDir,
            final String... indexAttributes) throws Exception {
        PartitionFactory pf = dsf.getPartitionFactory();
        Partition p = pf.createPartition(schemaManager, directoryService.getDnFactory(), id, suffix, 1000, workingDir);
        for (String current : indexAttributes) {
            pf.addIndex(p, current, 10);
        }
        p.initialize();
        directoryService.addPartition(p);
    }

    private static void processLdif(final SchemaManager schemaManager, final CoreSession adminSession, final String ldifName) throws Exception {
        InputStream ldifInput = TestKDC.class.getResourceAsStream(ldifName);
        LdifReader ldifReader = new LdifReader(ldifInput);
        for (LdifEntry ldifEntry : ldifReader) {
            adminSession.add(new DefaultEntry(schemaManager, ldifEntry.getEntry()));
        }
        ldifReader.close();
        ldifInput.close();
    }

    private void stopDirectoryService() {
        if (directoryService == null) {
            return;
        }

        try {
            directoryService.shutdown();
            directoryService = null;
        } catch (Exception e) {
            throw new IllegalStateException("Error shutting down directory service", e);
        }
    }

    public void startKDC() {
        if (directoryService == null) {
            throw new IllegalStateException("No DirectoryService Available for KDC");
        }
        if (kdcServer != null) {
            throw new IllegalStateException("KDCServer already started");
        }

        File configPath = new File(TestKDC.class.getResource("/krb5.conf").getFile());
        originalConfig = System.setProperty("java.security.krb5.conf", configPath.getAbsolutePath());

        try {
            SimpleKdcServer kdcServer = new SimpleKdcServer();
            kdcServer.setKdcRealm("WILDFLY.ORG");
            kdcServer.setKdcHost("localhost");
            kdcServer.setInnerKdcImpl(new DefaultInternalKdcServerImpl(kdcServer.getKdcSetting()));
            kdcServer.setAllowUdp(true);
            kdcServer.setKdcUdpPort(6088);

            kdcServer.init();

            kdcServer.createPrincipal("sasl/test_server_1@WILDFLY.ORG", "servicepwd");
            kdcServer.createPrincipal("sasl/test_server_2@WILDFLY.ORG", "servicepwd");
            kdcServer.createPrincipal("jduke@WILDFLY.ORG", "theduke");

            // Launch the server
            kdcServer.start();
            this.kdcServer = kdcServer;
        } catch (KrbException e) {
            throw new IllegalStateException("Unable to start KDC", e);
        }
    }

    private void stopKDC() {
        if (kdcServer == null) {
            return;
        }

        try {
            kdcServer.stop();
        } catch (KrbException e) {
            throw new IllegalStateException("Unable to stop KDC", e);
        }
        kdcServer = null;

        if (originalConfig != null) {
            System.setProperty("java.security.krb5.conf", originalConfig);
        }
    }

    private void createWorkingDir() {
        workingDir = new File("./target/apache-ds/working");
        if (workingDir.exists() == false) {
            if (workingDir.mkdirs() == false) {
                throw new IllegalStateException("Unable to create working dir.");
            }
        }
        emptyDir(workingDir);
    }

    private void cleanWorkingDir() {
        emptyDir(workingDir);
        workingDir = null;
    }

    private void emptyDir(final File dir) {
        for (File current : dir.listFiles()) {
            if (current.delete() == false) {
                try {
                    throw new IllegalStateException(String.format("Unable to delete file '%s' from working dir '%s'.",
                            current.getName(), workingDir.getCanonicalPath()));
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                }
            }
        }
    }

    public void stopAll() {
        stopKDC();
        stopDirectoryService();
        //cleanWorkingDir();
    }


    public String generateKeyTab(String keyTabFileName, String... credentials) {
        log.debug("Generating keytab: " + keyTabFileName);
        List<KeytabEntry> entries = new ArrayList<>();
        KerberosTime ktm = KerberosTime.now();

        for (int i = 0; i < credentials.length;) {
            String principal = credentials[i++];
            String password = credentials[i++];

            for (Map.Entry<EncryptionType, EncryptionKey> keyEntry : KerberosKeyFactory.getKerberosKeys(principal, password)
                    .entrySet()) {
                EncryptionKey key = keyEntry.getValue();
                log.debug("Adding key=" + key + " for principal=" + principal);
                entries.add(new KeytabEntry(new PrincipalName(principal), ktm, key.getKeyVersion(),
                        new org.apache.kerby.kerberos.kerb.type.base.EncryptionKey(key.getKeyType().getValue(), key.getKeyValue(), key.getKeyVersion())));
            }
        }

        Keytab keyTab = new Keytab();
        keyTab.addKeytabEntries(entries);
        try {
            File keyTabFile = new File(workingDir, keyTabFileName);
            keyTab.store(keyTabFile);
            return keyTabFile.getAbsolutePath();
        } catch (IOException e) {
            throw new IllegalStateException("Cannot create keytab: " + keyTabFileName, e);
        }
    }

}
