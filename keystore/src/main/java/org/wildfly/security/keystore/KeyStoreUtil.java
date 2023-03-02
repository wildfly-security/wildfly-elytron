/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2018 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.keystore;

import static org.wildfly.security.keystore.ElytronMessages.log;
import static org.wildfly.security.provider.util.ProviderUtil.findProvider;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.channels.FileChannel;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.function.Supplier;

import org.wildfly.common.iteration.CodePointIterator;
import org.wildfly.security.pem.Pem;
import org.wildfly.security.pem.PemEntry;

/**
 * Utility functions for manipulating KeyStores.
 *
 * @author <a href="mailto:mmazanek@redhat.com">Martin Mazanek</a>
 */
public class KeyStoreUtil {

    private static final String BCFKS = "BCFKS";
    private static final String BKS = "BKS";
    private static final String JCEKS = "JCEKS";
    private static final String JKS = "JKS";
    private static final String PKCS12 = "PKCS12";
    private static final String UBER = "UBER";

    private static final int VERSION_0 = 0;
    private static final int VERSION_1 = 1;
    private static final int VERSION_2 = 2;
    private static final int JCEKS_MAGIC = 0xcececece;
    private static final int JKS_MAGIC = 0xfeedfeed;
    private static final int SEQUENCE = 0x30000000;
    private static final int PEM_MAGIC = 0x2d2d2d2d;

    /**
     * Tries to parse a keystore based on known recognizable patterns.
     * <p>
     * This method can parse JKS, JCEKS, PKCS12, BKS, BCFKS and UBER key stores as well as PEM files. At first the
     * method looks for recognizable patterns of JKS, JCEKS, PKCS12 and BKS key store types and tries to parse them if
     * found. If the pattern recognition fails, brute force is used to load the key store.
     * <p>
     * The provider supplier is used for loading the key stores.
     *
     * @param providers    provider supplier for loading the keystore (must not be {@code null})
     * @param providerName if specified only providers with this name will be used
     * @param is           the key store file input stream (must not be {@code null})
     * @param filename     the filename for prioritizing brute force checks using the file extension
     * @param password     password of the key store. Should be the empty string for PEM files.
     * @return loaded key store if recognized
     * @throws IOException
     */
    public static KeyStore loadKeyStore(final Supplier<Provider[]> providers, final String providerName, FileInputStream is, String filename, char[] password) throws IOException, KeyStoreException {

        DataInputStream dis = new ResettableDataFileInputStream(is);

        int firstInt = dis.readInt();
        dis.reset();

        KeyStore result = null;

        if (firstInt == JKS_MAGIC) {
            result = tryLoadKeystore(providers, providerName, dis, password, JKS);
        } else if (firstInt == JCEKS_MAGIC) {
            result = tryLoadKeystore(providers, providerName, dis, password, JCEKS);
        } else if (firstInt == VERSION_1 || firstInt == VERSION_2) {
            dis.reset();
            dis.skip(32);
            byte firstElementType = dis.readByte();
            dis.reset();
            if (firstElementType <= 5) {
                result = tryLoadKeystore(providers, providerName, dis, password, BKS, UBER);
            } else {
                result = tryLoadKeystore(providers, providerName, dis, password, UBER, BKS);
            }

        } else if (firstInt == VERSION_0) {
            result = tryLoadKeystore(providers, providerName, dis, password, UBER);
        } else if ((firstInt & 0xff000000) == SEQUENCE) {
            String[] parts = filename.split("\\.");
            String extension = parts[parts.length - 1];
            if (extension.startsWith("b") || extension.startsWith("B")) {
                result = tryLoadKeystore(providers, providerName, dis, password, BCFKS, PKCS12);
            } else {
                result = tryLoadKeystore(providers, providerName, dis, password, PKCS12, BCFKS);
            }
        } else if (firstInt == PEM_MAGIC) {
            result = loadPemAsKeyStore(is, password);
        }

        if (result == null) {
            throw log.keyStoreTypeNotDetected();
        }

        return result;
    }

    private static KeyStore tryLoadKeystore(final Supplier<Provider[]> providers, final String providerName, InputStream is, char[] password, String... types) {
        for (String type : types) {
            try {
                log.debug("Searching provider for: " + type);
                Provider provider = findProvider(providers, providerName, KeyStore.class, type);
                if (provider == null) {
                    log.debug("Provider not found");
                    continue;
                }
                log.debug("Provider found: " + provider.getName());
                KeyStore keystore = KeyStore.getInstance(type, provider);
                is.reset();
                keystore.load(is, password);
                return keystore;
            } catch (Exception e) {
                log.debug("KeyStore is not of type " + type);
                continue;
            }
        }
        return null;
    }

    public static KeyStore loadPemAsKeyStore(InputStream is, char[] password) throws KeyStoreException, IOException {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        try {
            keyStore.load(null);
        } catch (Exception e) {
            // won't happen
        }
        // try to load it as a PEM
        PrivateKey pk = null;
        List<Certificate> certificates = new ArrayList<>();
        // Reading all of the file should not be an issue
        byte[] pem = readAllBytes(is);
        is.read(pem);
        for (Iterator<PemEntry<?>> it = Pem.parsePemContent(CodePointIterator.ofUtf8Bytes(pem)); it.hasNext(); ) {
            Object entry = it.next().getEntry();
            if (entry instanceof PrivateKey) {
                // Private key
                pk = (PrivateKey) entry;
            } else if (entry instanceof Certificate) {
                // Certificate
                Certificate certificate = (Certificate) entry;
                certificates.add(certificate);
            }
        }
        if (pk != null) {
            // A keystore
            Certificate certificate = certificates.get(0);
            String alias = certificate instanceof X509Certificate ? ((X509Certificate) certificate).getSubjectX500Principal().getName() : "key";
            keyStore.setKeyEntry(alias, pk, password, certificates.toArray(new Certificate[0]));
        } else {
            // A truststore
            int i = 1;
            for (Certificate certificate : certificates) {
                String alias = certificate instanceof X509Certificate ? ((X509Certificate)certificate).getSubjectX500Principal().getName() : Integer.toString(i++);
                keyStore.setCertificateEntry(alias, certificate);
            }
        }
        return keyStore;
    }

    private static byte[] readAllBytes(InputStream inputStream) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int readBytes = inputStream.read(buffer);

        // inputStream.read() returns -1 when the end of the stream is reached
        while(readBytes != -1){
            outputStream.write(buffer, 0, readBytes);
            readBytes = inputStream.read(buffer);
        }
        return outputStream.toByteArray();
    }

    //FileInputStream does not support marking by default and buffering unknown sized file doesn't seem right
    private static class ResettableDataFileInputStream extends DataInputStream {

        private FileChannel fc;
        private long startingPosition = 0;

        public ResettableDataFileInputStream(FileInputStream is) {
            super(is);
            this.fc = is.getChannel();
            try {
                this.startingPosition = fc.position();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        @Override
        public void reset() throws IOException {
            fc.position(startingPosition);
        }

        @Override
        public long skip(long bytes) throws IOException {
            fc.position(fc.position() + bytes);
            return 0;
        }

    }
}
