/*
 * JBoss, Home of Professional Open Source
 * Copyright 2017 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.tool;

import static org.wildfly.security.credential.store.CredentialStore.CredentialSourceProtectionParameter;
import static org.wildfly.security.credential.store.CredentialStore.getInstance;
import static org.wildfly.security.tool.Params.ALIAS_PARAM;
import static org.wildfly.security.tool.Params.BULK_CONVERT_PARAM;
import static org.wildfly.security.tool.Params.CREDENTIAL_STORE_TYPE_PARAM;
import static org.wildfly.security.tool.Params.CUSTOM_CREDENTIAL_STORE_PROVIDER_PARAM;
import static org.wildfly.security.tool.Params.DEBUG_PARAM;
import static org.wildfly.security.tool.Params.FILE_SEPARATOR;
import static org.wildfly.security.tool.Params.HELP_PARAM;
import static org.wildfly.security.tool.Params.IMPLEMENTATION_PROPERTIES_PARAM;
import static org.wildfly.security.tool.Params.ITERATION_PARAM;
import static org.wildfly.security.tool.Params.KEYSTORE_PARAM;
import static org.wildfly.security.tool.Params.OTHER_PROVIDERS_PARAM;
import static org.wildfly.security.tool.Params.SALT_PARAM;
import static org.wildfly.security.tool.Params.STORE_LOCATION_PARAM;
import static org.wildfly.security.tool.Params.SUMMARY_PARAM;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.SecretKeyCredential;
import org.wildfly.security.credential.source.CredentialSource;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.impl.KeyStoreCredentialStore;
import org.wildfly.security.credential.store.impl.VaultCredentialStore;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.util.PasswordBasedEncryptionUtil;

/**
 * Command to perform conversion from former Vault storage to Credential Store (KeyStoreCredentialStore).
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 */
public class VaultCommand extends Command {

    static final String defaultKeyStoreType = "JCEKS";

    private final Options options;
    private CommandLineParser parser = new DefaultParser();
    private CommandLine cmdLine = null;

    public static final String VAULT_COMMAND = "vault";

    public static final String FAIL_IF_EXIST_PARAM = "fail-if-exist";

    // convert options
    public static final String KEYSTORE_PASSWORD_PARAM = "keystore-password";
    public static final String ENC_DIR_PARAM = "enc-dir";

    private static final class Descriptor {
        String keyStoreURL;
        String vaultPassword;
        String encryptionDirectory;
        String salt;
        int iterationCount;
        String secretKeyAlias;
        Map<String, String> implProps;
        String outputFile;
        String csType;
        String csProvider;
        String csOtherProviders;
    }

    public VaultCommand() {
        options = new Options();

        // PB vault related options
        Option o = new Option("k", KEYSTORE_PARAM, true, ElytronToolMessages.msg.cmdLineVaultKeyStoreURL());
        o.setArgName(KEYSTORE_PARAM);
        options.addOption(o);
        o = new Option("p", KEYSTORE_PASSWORD_PARAM, true, ElytronToolMessages.msg.cmdLineVaultKeyStorePassword());
        o.setArgName("pwd");
        options.addOption(o);
        o = new Option("e", ENC_DIR_PARAM, true, ElytronToolMessages.msg.cmdLineVaultEncryptionDirectory());
        o.setArgName("dir");
        options.addOption(o);
        o = new Option("s", SALT_PARAM, true, ElytronToolMessages.msg.cmdVaultLineSalt());
        o.setArgName("salt");
        options.addOption(o);
        o = new Option("i", ITERATION_PARAM, true, ElytronToolMessages.msg.cmdLineVaultIterationCount());
        options.addOption(o);
        o = new Option("v", ALIAS_PARAM, true, ElytronToolMessages.msg.cmdLineVaultKeyStoreAlias());
        options.addOption(o);

        // Credential Store generation options
        o = new Option("l", STORE_LOCATION_PARAM, true, ElytronToolMessages.msg.cmdLineVaultCSLocationDesc());
        o.setArgName("loc");
        options.addOption(o);
        o = new Option("u", IMPLEMENTATION_PROPERTIES_PARAM, true, ElytronToolMessages.msg.cmdLineVaultCSParametersDesc());
        o.setValueSeparator(';');
        o.setOptionalArg(true);
        options.addOption(o);
        o = new Option("t", CREDENTIAL_STORE_TYPE_PARAM, true, ElytronToolMessages.msg.cmdLineVaultCSTypeDesc());
        o.setArgName("type");
        options.addOption(o);
        o = new Option("o", OTHER_PROVIDERS_PARAM, true, ElytronToolMessages.msg.cmdLineOtherProvidersDesc());
        o.setArgName("providers");
        o.setOptionalArg(true);
        options.addOption(o);
        o = new Option("q", CUSTOM_CREDENTIAL_STORE_PROVIDER_PARAM, true, ElytronToolMessages.msg.cmdLineCustomCredentialStoreProviderDesc());
        o.setArgName("cs-provider");
        o.setOptionalArg(true);
        options.addOption(o);
        options.addOption("f", SUMMARY_PARAM, false, ElytronToolMessages.msg.cmdLineVaultPrintSummary());

        Option b = new Option("b", BULK_CONVERT_PARAM, true, ElytronToolMessages.msg.cliCommandBulkVaultCredentialStoreConversion());
        b.setArgName("description file");
        Option h = new Option("h", HELP_PARAM, false, ElytronToolMessages.msg.cmdLineHelp());
        Option d = new Option("d", DEBUG_PARAM, false, ElytronToolMessages.msg.cmdLineDebug());
        options.addOption(b);
        options.addOption(h);
        options.addOption(d);

    }

    @Override
    public void execute(String[] args) throws Exception {
        setStatus(GENERAL_CONFIGURATION_ERROR);
        cmdLine = parser.parse(options, args, false);
        setEnableDebug(cmdLine.hasOption(DEBUG_PARAM));
        if (cmdLine.hasOption(HELP_PARAM)) {
            help();
            setStatus(ElytronTool.ElytronToolExitStatus_OK);
            return;
        }

        boolean printSummary = cmdLine.hasOption(SUMMARY_PARAM);

        printDuplicatesWarning(cmdLine);

        String bulkConversionDescriptor = cmdLine.getOptionValue(BULK_CONVERT_PARAM);
        if (bulkConversionDescriptor != null && !bulkConversionDescriptor.isEmpty()) {
            checkInvalidOptions(KEYSTORE_PARAM, KEYSTORE_PASSWORD_PARAM, ENC_DIR_PARAM, SALT_PARAM, ITERATION_PARAM, ALIAS_PARAM, STORE_LOCATION_PARAM);

            // bulk conversion
            List<Descriptor> descriptors = parseDescriptorFile(bulkConversionDescriptor);

            if (descriptors.size() == 0) {
                throw ElytronToolMessages.msg.undefinedKeystore(bulkConversionDescriptor);
            }

            for(Descriptor d: descriptors) {
                try {
                    final HashMap<String, String> convertedOptions = convert(d.keyStoreURL, d.vaultPassword, d.encryptionDirectory, d.salt, d.iterationCount, d.secretKeyAlias, d.outputFile, d.implProps,
                            d.csType, d.csProvider, d.csOtherProviders);
                    System.out.println(ElytronToolMessages.msg.vaultConvertedToCS(d.encryptionDirectory, d.keyStoreURL, d.outputFile));
                    if (printSummary) {
                        printSummary(d.vaultPassword, d.salt, d.iterationCount, convertedOptions);
                    }
                } catch (Throwable e) {
                    throw ElytronToolMessages.msg.bulkConversionProblem(d.encryptionDirectory, d.keyStoreURL, e);
                }

            }
            setStatus(ElytronTool.ElytronToolExitStatus_OK);
        } else {
            // single Vault conversion
            // default values are from VaultTool
            String keystoreURL = cmdLine.getOptionValue(KEYSTORE_PARAM, "vault.keystore");
            String keystorePassword = cmdLine.getOptionValue(KEYSTORE_PASSWORD_PARAM);
            String encryptionDirectory = cmdLine.getOptionValue(ENC_DIR_PARAM, "vault");
            String salt = cmdLine.getOptionValue(SALT_PARAM, "12345678");
            int iterationCount = Integer.parseInt(cmdLine.getOptionValue(ITERATION_PARAM, "23"));

            String vaultSecretKeyAlias = cmdLine.getOptionValue(ALIAS_PARAM, "vault");
            String location = cmdLine.getOptionValue(STORE_LOCATION_PARAM);
            Map<String, String> implProps = CredentialStoreCommand.parseCredentialStoreProperties(cmdLine.getOptionValue(IMPLEMENTATION_PROPERTIES_PARAM));
            String csType = cmdLine.getOptionValue(CREDENTIAL_STORE_TYPE_PARAM, KeyStoreCredentialStore.KEY_STORE_CREDENTIAL_STORE);
            String csProvider = cmdLine.getOptionValue(CUSTOM_CREDENTIAL_STORE_PROVIDER_PARAM);
            String csOtherProviders = cmdLine.getOptionValue(OTHER_PROVIDERS_PARAM);

            if (location == null || location.isEmpty()) {
                location = convertedStoreName(encryptionDirectory, implProps);
            }

            if (keystorePassword == null) {
                keystorePassword = prompt(false, ElytronToolMessages.msg.vaultPasswordPrompt(), false, null);
            }

            final HashMap<String, String> convertedOptions = convert(keystoreURL, keystorePassword, encryptionDirectory, salt,
                    iterationCount, vaultSecretKeyAlias, location, implProps, csType, csProvider, csOtherProviders);
            System.out.println(ElytronToolMessages.msg.vaultConvertedToCS(encryptionDirectory, keystoreURL, location));
            setStatus(ElytronTool.ElytronToolExitStatus_OK);
            if (printSummary) {
                printSummary(keystorePassword, salt, iterationCount, convertedOptions);
            }
        }

    }

    private void checkInvalidOptions(String... invalidOptions) throws Exception {
        for (String opt: invalidOptions) {
            if (cmdLine.hasOption(opt)) {
                throw ElytronToolMessages.msg.bulkConversionInvalidOption(opt);
            }
        }
    }

    /**
     * Display help to the command.
     */
    @Override
    public void help() {
        HelpFormatter help = new HelpFormatter();
        help.setWidth(WIDTH);
        help.printHelp(ElytronToolMessages.msg.cmdHelp(getToolCommand(), VAULT_COMMAND),
                ElytronToolMessages.msg.cmdVaultHelpHeader().concat(ElytronToolMessages.msg.cmdLineActionsHelpHeader()),
                options,
                "",
                true);
    }

    private String convertedStoreName(String encryptionDirectory, Map<String, String> implProps) {
        final String implPropsLocation = implProps.get("location");
        return (implPropsLocation != null && ! implPropsLocation.isEmpty()) ? implPropsLocation : encryptionDirectory + (encryptionDirectory.isEmpty() || encryptionDirectory.endsWith(FILE_SEPARATOR) ? "" : FILE_SEPARATOR) + "converted-vault.cr-store";
    }

    private HashMap<String, String> convert(String keyStoreURL, String vaultPassword, String encryptionDirectory,
                         String salt, int iterationCount, String secretKeyAlias,
                         String outputFile, Map<String, String> csAttributes, String csType, String csProvider, String csOtherProviders)
            throws Exception {

        final HashMap<String, String> vaultInitialOptions = new HashMap<>();

        if (encryptionDirectory == null || "".equals(encryptionDirectory)) {
            throw ElytronToolMessages.msg.undefinedEncryptionDirectory();
        }

        final File locationFile = new File(encryptionDirectory, "VAULT.dat");
        if (locationFile.exists()) {
            vaultInitialOptions.put("location", encryptionDirectory);
        } else
        {
            throw ElytronToolMessages.msg.vaultFileNotFound(encryptionDirectory);
        }

        if (secretKeyAlias == null || "".equals(secretKeyAlias)) {
            throw ElytronToolMessages.msg.undefinedAlias();
        }

        if (outputFile == null || "".equals(outputFile)) {
            throw ElytronToolMessages.msg.undefinedOutputLocation();
        }

        if (vaultPassword == null || "".equals(vaultPassword)) {
            throw ElytronToolMessages.msg.undefinedVaultPassword();
        }

        CredentialStore vaultCredentialStore = getInstance(VaultCredentialStore.VAULT_CREDENTIAL_STORE);
        vaultCredentialStore.initialize(vaultInitialOptions,
                getVaultCredentialStoreProtectionParameter(keyStoreURL, vaultPassword, salt, iterationCount, secretKeyAlias));

        final HashMap<String, String> convertedOptions = new HashMap<>();
        if (!Files.exists(Paths.get(outputFile))) {
            convertedOptions.put("location", outputFile);
        } else
        {
            throw ElytronToolMessages.msg.storageFileExists(outputFile);
        }
        convertedOptions.put("modifiable", Boolean.TRUE.toString());
        convertedOptions.put("create", Boolean.TRUE.toString());
        if (csAttributes != null) {
            convertedOptions.putAll(csAttributes);
        }
        convertedOptions.put("create", Boolean.TRUE.toString());
        if (csType == null || "".equals(csType)) {
            csType = KeyStoreCredentialStore.KEY_STORE_CREDENTIAL_STORE;
        }
        if (csType.equals(KeyStoreCredentialStore.KEY_STORE_CREDENTIAL_STORE)) {
            convertedOptions.put("keyStoreType", defaultKeyStoreType);
        }
        CredentialStore convertedCredentialStore;
        if (csProvider != null) {
            convertedCredentialStore = CredentialStore.getInstance(csType, csProvider, getProvidersSupplier(csProvider));
        } else {
            try {
                convertedCredentialStore = CredentialStore.getInstance(csType);
            } catch (NoSuchAlgorithmException e) {
                // fallback to load all possible providers
                convertedCredentialStore = CredentialStore.getInstance(csType, getProvidersSupplier(null));
            }
        }
        convertedCredentialStore.initialize(convertedOptions,
                getCredentialStoreProtectionParameter(vaultPassword, salt, iterationCount),
                getProvidersSupplier(csOtherProviders).get());
        for (String alias : vaultCredentialStore.getAliases()) {
            PasswordCredential credential = vaultCredentialStore.retrieve(alias, PasswordCredential.class);
            convertedCredentialStore.store(alias, credential);
        }
        convertedCredentialStore.flush();

        return convertedOptions;
    }

    private List<Descriptor> parseDescriptorFile(String descriptorFileLocation) throws IOException {
        try (BufferedReader descriptorFile = new BufferedReader(new InputStreamReader(new FileInputStream(descriptorFileLocation), StandardCharsets.UTF_8))) {
            List<Descriptor> parsedDescriptors = new ArrayList<>();
            String line;
            int vaults = 0;
            int lineNumber = 0;
            Descriptor descriptor = new Descriptor();
            while ((line = descriptorFile.readLine()) != null) {
                lineNumber++;
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;
                int colon = line.indexOf(':');
                if (colon == -1) {
                    throw ElytronToolMessages.msg.descriptorParseMissingColon(descriptorFileLocation, Integer.toString(lineNumber));
                }
                String attribute = line.substring(0, colon).trim();
                String value = line.substring(colon + 1).trim();
                if (attribute.equals(KEYSTORE_PARAM)) {
                    if (vaults > 0) {
                        parsedDescriptors.add(descriptor);
                        descriptor = new Descriptor();
                    }
                    vaults++;
                    descriptor.keyStoreURL = value;
                } else if (attribute.equals(KEYSTORE_PASSWORD_PARAM)) {
                    descriptor.vaultPassword = value;
                } else if (attribute.equals(ENC_DIR_PARAM)) {
                    descriptor.encryptionDirectory = value;
                } else if (attribute.equals(SALT_PARAM)) {
                    descriptor.salt = value;
                } else if (attribute.equals(ITERATION_PARAM)) {
                    descriptor.iterationCount = Integer.parseInt(value);
                } else if (attribute.equals(ALIAS_PARAM)) {
                    descriptor.secretKeyAlias = value;
                } else if (attribute.equals(STORE_LOCATION_PARAM)) {
                    descriptor.outputFile = value;
                } else if (attribute.equals(IMPLEMENTATION_PROPERTIES_PARAM)) {
                    descriptor.implProps =  CredentialStoreCommand.parseCredentialStoreProperties(value);
                } else if (attribute.equals(CREDENTIAL_STORE_TYPE_PARAM)) {
                    descriptor.csType = value;
                } else if (attribute.equals(CUSTOM_CREDENTIAL_STORE_PROVIDER_PARAM)) {
                    descriptor.csProvider = value;
                } else if (attribute.equals(OTHER_PROVIDERS_PARAM)) {
                    descriptor.csOtherProviders = value;
                } else {
                    throw ElytronToolMessages.msg.unrecognizedDescriptorAttribute(Integer.toString(lineNumber));
                }
            }
            if (descriptor.keyStoreURL != null) {
                parsedDescriptors.add(descriptor);
            }
            return parsedDescriptors;
        }
    }

    private CredentialSourceProtectionParameter getCredentialStoreProtectionParameter(final String vaultPassword, final String salt, final int iterationCount) throws GeneralSecurityException {
        char[] password = vaultPassword.startsWith("MASK-") ? decodeMaskedPassword(vaultPassword.substring("MASK-".length()), salt, iterationCount)
                : vaultPassword.toCharArray();
        return new CredentialStore.CredentialSourceProtectionParameter(
                IdentityCredentials.NONE.withCredential(
                        new PasswordCredential(ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, password))));
    }

    private CredentialSourceProtectionParameter getVaultCredentialStoreProtectionParameter(final String keyStoreURL, final String vaultPassword, final String salt, final int iterationCount, final String secretKeyAlias) throws GeneralSecurityException, IOException {
        char[] password = vaultPassword.startsWith("MASK-") ? decodeMaskedPassword(vaultPassword.substring("MASK-".length()), salt, iterationCount)
                : vaultPassword.toCharArray();
        final KeyStore keyStore = KeyStore.getInstance(defaultKeyStoreType);
        try (FileInputStream in = new FileInputStream(new File(keyStoreURL))) {
            keyStore.load(in, password);
        }

        final KeyStore.Entry entry = keyStore.getEntry(secretKeyAlias, new KeyStore.PasswordProtection(password));
        if (entry instanceof KeyStore.SecretKeyEntry) {
            return new CredentialSourceProtectionParameter(new CredentialSource() {
                @Override
                public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType,
                        String algorithmName, AlgorithmParameterSpec parameterSpec) throws IOException {
                    return null;
                }

                @Override
                public <C extends Credential> C getCredential(Class<C> credentialType, String algorithmName,
                        AlgorithmParameterSpec parameterSpec) throws IOException {
                    SecretKeyCredential credential = new SecretKeyCredential(((KeyStore.SecretKeyEntry) entry).getSecretKey());
                    return credential.castAs(credentialType, algorithmName, parameterSpec);
                }
            });
        } else {
            throw ElytronToolMessages.msg.cannotLocateAdminKey(secretKeyAlias);
        }
    }

    private char[] decodeMaskedPassword(final String password, final String salt, final int iterationCount) throws GeneralSecurityException {
        PasswordBasedEncryptionUtil decryptUtil = new PasswordBasedEncryptionUtil.Builder()
                .picketBoxCompatibility()
                .salt(salt)
                .iteration(iterationCount)
                .decryptMode()
                .build();
        return decryptUtil.decodeAndDecrypt(password);
    }

    private void printSummary (String keystorePassword, String salt, int iterationCount, Map<String, String> implProps) throws GeneralSecurityException {
        StringBuilder com = new StringBuilder();
        com.append(ElytronToolMessages.msg.conversionSuccessful());
        com.append(ElytronToolMessages.msg.cliCommandToNewCredentialStore());
        String password = "";
        if (keystorePassword != null) {
            password = keystorePassword;
            if (salt != null && iterationCount > -1) {
                password = keystorePassword.startsWith("MASK-") ? keystorePassword + ";" + salt + ";" + String.valueOf(iterationCount)
                        : MaskCommand.computeMasked(keystorePassword, salt, iterationCount);
            }
        }
        CredentialStoreCommand.getCreateDefaultSummary(implProps, com, password);
        System.out.println(ElytronToolMessages.msg.vaultConversionSummary(com.toString()));
    }

}