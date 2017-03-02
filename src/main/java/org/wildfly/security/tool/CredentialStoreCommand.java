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

import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionGroup;
import org.apache.commons.cli.Options;
import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.impl.KeyStoreCredentialStore;
import org.wildfly.security.password.interfaces.ClearPassword;

/**
 * Credential Store Command
 * Performs credential store related operations.
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 */
class CredentialStoreCommand extends Command {

    public static int ACTION_NOT_DEFINED = 5;
    public static int ALIAS_NOT_FOUND = 6;
    public static int GENERAL_CONFIGURATION_ERROR = 7;

    public static final String CREDENTIAL_STORE_COMMAND = "credential-store";

    public static final String STORE_LOCATION_PARAM = "location";
    public static final String CONFIGURATION_URI_PARAM = "uri";
    public static final String CREDENTIAL_STORE_PASSWORD_PARAM = "password";
    public static final String CREDENTIAL_STORE_TYPE_PARAM = "type";
    public static final String SALT_PARAM = "salt";
    public static final String ITERATION_PARAM = "iteration";
    public static final String PASSWORD_CREDENTIAL_VALUE_PARAM = "secret";
    public static final String ADD_ALIAS_PARAM = "add";
    public static final String CHECK_ALIAS_PARAM = "exists";
    public static final String ALIASES_PARAM = "aliases";
    public static final String REMOVE_ALIAS_PARAM = "remove";
    public static final String CREATE_CREDENTIAL_STORE_PARAM = "create";
    public static final String HELP_PARAM = "help";
    public static final String PRINT_SUMMARY_PARAM = "summary";

    private final Options options;
    private CommandLineParser parser = new DefaultParser();
    private CommandLine cmdLine = null;

    private Map<String, String> credentialStoreConfigurationOptions = new HashMap<>();
    private String storageFile = null;

    CredentialStoreCommand() {
        options = new Options();
        Option opt = new Option("l", STORE_LOCATION_PARAM, true, ElytronToolMessages.msg.cmdLineStoreLocationDesc());
        opt.setArgName("loc");
        options.addOption(opt);
        opt = new Option("u", CONFIGURATION_URI_PARAM, true, ElytronToolMessages.msg.cmdLineURIDesc());
        opt.setArgName("uri");
        options.addOption(opt);
        opt = new Option("p", CREDENTIAL_STORE_PASSWORD_PARAM, true, ElytronToolMessages.msg.cmdLineCredentialStorePassword());
        opt.setArgName("pwd");
        options.addOption(opt);
        options.addOption("s", SALT_PARAM, true, ElytronToolMessages.msg.cmdLineSaltDesc());
        options.addOption("i", ITERATION_PARAM, true, ElytronToolMessages.msg.cmdLineIterationCountDesc());
        opt = new Option("x", PASSWORD_CREDENTIAL_VALUE_PARAM, true, ElytronToolMessages.msg.cmdLinePasswordCredentialValueDesc());
        opt.setArgName("secret to store");
        opt.setOptionalArg(true);
        options.addOption(opt);
        options.addOption("c", CREATE_CREDENTIAL_STORE_PARAM, false, ElytronToolMessages.msg.cmdLineCreateCredentialStoreDesc());
        opt = new Option("t", CREDENTIAL_STORE_TYPE_PARAM, true, ElytronToolMessages.msg.cmdLineCredentialStoreTypeDesc());
        opt.setArgName("type");
        options.addOption(opt);
        options.addOption("f", PRINT_SUMMARY_PARAM, false, ElytronToolMessages.msg.cmdLinePrintSummary());

        OptionGroup og = new OptionGroup();
        Option a = new Option("a", ADD_ALIAS_PARAM, true, ElytronToolMessages.msg.cmdLineAddAliasDesc());
        a.setArgName("alias");
        Option e = new Option("e", CHECK_ALIAS_PARAM, true, ElytronToolMessages.msg.cmdLineCheckAliasDesc());
        e.setArgName("alias");
        Option r = new Option("r", REMOVE_ALIAS_PARAM, true, ElytronToolMessages.msg.cmdLineRemoveAliasDesc());
        r.setArgName("alias");
        Option v = new Option("v", ALIASES_PARAM, false, ElytronToolMessages.msg.cmdLineAliasesDesc());
        Option h = new Option("h", HELP_PARAM, false, ElytronToolMessages.msg.cmdLineHelp());
        og.addOption(a);
        og.addOption(e);
        og.addOption(r);
        og.addOption(h);
        og.addOption(v);
        og.setRequired(true);
        options.addOptionGroup(og);
    }

    @Override
    public void execute(String[] args) throws Exception {
        setStatus(GENERAL_CONFIGURATION_ERROR);
        cmdLine = parser.parse(options, args, false);
        if (cmdLine.hasOption(HELP_PARAM)) {
            help();
            setStatus(ElytronTool.ElytronToolExitStatus_OK);
            return;
        }

        String location = cmdLine.getOptionValue(STORE_LOCATION_PARAM);
        String uri = cmdLine.getOptionValue(CONFIGURATION_URI_PARAM);
        String csPassword = cmdLine.getOptionValue(CREDENTIAL_STORE_PASSWORD_PARAM);
        String salt = cmdLine.getOptionValue(SALT_PARAM);
        String csType = cmdLine.getOptionValue(CREDENTIAL_STORE_TYPE_PARAM, KeyStoreCredentialStore.KEY_STORE_CREDENTIAL_STORE);
        String sIteration = cmdLine.getOptionValue(ITERATION_PARAM);
        int iterationCount = -1;
        if (sIteration != null && !sIteration.isEmpty()) {
            try {
                iterationCount = Integer.parseInt(sIteration);
            } catch (NumberFormatException e) {
                setStatus(GENERAL_CONFIGURATION_ERROR);
                throw new Exception(e);
            }
        }
        boolean createKeyStore = cmdLine.hasOption(CREATE_CREDENTIAL_STORE_PARAM);
        boolean printSummary = cmdLine.hasOption(PRINT_SUMMARY_PARAM);

        if (uri != null) {
            parse(new URI(uri));
        }
        if (location == null) {
            location = storageFile;
        }

        CredentialStore credentialStore = CredentialStore.getInstance(csType);
        credentialStoreConfigurationOptions.putIfAbsent("location", location);
        credentialStoreConfigurationOptions.putIfAbsent("modifiable", Boolean.TRUE.toString());
        credentialStoreConfigurationOptions.putIfAbsent("create", Boolean.valueOf(createKeyStore).toString());
        credentialStoreConfigurationOptions.putIfAbsent("keyStoreType", "JCEKS");

        if (csPassword == null) {
            // prompt for password
            csPassword = prompt(false, ElytronToolMessages.msg.credentialStorePasswordPrompt(), true, ElytronToolMessages.msg.credentialStorePasswordPromptConfirm());
        }
        if (csPassword != null) {
            credentialStore.initialize(credentialStoreConfigurationOptions,
                    new CredentialStore.CredentialSourceProtectionParameter(
                            IdentityCredentials.NONE.withCredential(
                                    new PasswordCredential(ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, csPassword.toCharArray())))));
        } else {
            credentialStore.initialize(credentialStoreConfigurationOptions);
        }

        if (cmdLine.hasOption(ADD_ALIAS_PARAM)) {
            String alias = cmdLine.getOptionValue(ADD_ALIAS_PARAM);
            String secret = cmdLine.getOptionValue(PASSWORD_CREDENTIAL_VALUE_PARAM);
            if (secret == null) {
                // prompt for secret
                secret = prompt(false, ElytronToolMessages.msg.secretToStorePrompt(), true, ElytronToolMessages.msg.secretToStorePromptConfirm());
            }
            credentialStore.store(alias, createCredential(secret));
            credentialStore.flush();
            System.out.println(ElytronToolMessages.msg.aliasStored(alias));
            setStatus(ElytronTool.ElytronToolExitStatus_OK);
        } else if (cmdLine.hasOption(REMOVE_ALIAS_PARAM)) {
            String alias = cmdLine.getOptionValue(REMOVE_ALIAS_PARAM);
            credentialStore.remove(alias, PasswordCredential.class);
            credentialStore.flush();
            System.out.println(ElytronToolMessages.msg.aliasRemoved(alias));
            setStatus(ElytronTool.ElytronToolExitStatus_OK);
        } else if (cmdLine.hasOption(CHECK_ALIAS_PARAM)) {
            String alias = cmdLine.getOptionValue(CHECK_ALIAS_PARAM);
            if (credentialStore.exists(alias, PasswordCredential.class)) {
                setStatus(ElytronTool.ElytronToolExitStatus_OK);
                System.out.println(ElytronToolMessages.msg.aliasExists(alias));
            } else {
                setStatus(ALIAS_NOT_FOUND);
                System.out.println(ElytronToolMessages.msg.aliasDoesNotExist(alias));
            }
        } else if (cmdLine.hasOption(ALIASES_PARAM)) {
            Set<String> aliases = credentialStore.getAliases();
            StringBuilder list = new StringBuilder();
            for (String alias: aliases) {
                list.append(alias).append(" ");
            }
            System.out.println(ElytronToolMessages.msg.aliases(list.toString()));
            setStatus(ElytronTool.ElytronToolExitStatus_OK);
        } else {
            setStatus(ACTION_NOT_DEFINED);
            throw ElytronToolMessages.msg.actionToPerformNotDefined();
        }

        if (printSummary) {
            StringBuilder com = new StringBuilder();
            com.append("/subsystem=elytron/credential-store=test:add(uri=\"");
            com.append(uri).append("\"");
            com.append(",relative-to=jboss.server.data.dir,credential-reference={");
            com.append("clear-text=\"");
            if (csPassword != null && !csPassword.startsWith("MASK-") && salt != null && iterationCount > -1) {
                com.append(MaskCommand.computeMasked(csPassword, salt, iterationCount));
            } else if (csPassword != null) {
                com.append(csPassword);
            }
            com.append("\"})");
            System.out.println(ElytronToolMessages.msg.commandSummary(com.toString()));
        }

    }

    private Credential createCredential(final String secret) {
        return new PasswordCredential(ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, secret.toCharArray()));
    }

    @Override
    protected Set<String> aliases() {
        return Stream.of("cs", "credstore").collect(Collectors.toSet());
    }

    private void parse(final URI uri) {
        String path = uri.getPath();
        if (path != null && path.length() > 1) {
            storageFile = path.substring(1);
        } else {
            storageFile = null;
        }
        parseQueryParameter(uri.getQuery(), uri.toString());
    }

    private void parseQueryParameter(final String query, final String uri) {

        if (query == null) {
            return;
        }

        int i = 0;
        int state = 0; // possible states KEY = 0 | VALUE = 1
        StringBuilder token = new StringBuilder();
        String key = null;
        String value = null;
        while (i < query.length()) {
            char c = query.charAt(i);
            if (state == 0) {   // KEY state
                if (c == '=') {
                    state = 1;
                    key = token.toString();
                    value = null;
                    token.setLength(0);
                } else {
                    token.append(c);
                }
                i++;
            } else if (state == 1) {  // VALUE state
                if (c == '\'') {
                    if (query.charAt(i - 1) != '=') {
                        throw ElytronToolMessages.msg.credentialStoreURIParameterOpeningQuote(uri);
                    }
                    int inQuotes = i + 1;
                    c = query.charAt(inQuotes);
                    while (inQuotes < query.length() && c != '\'') {
                        token.append(c);
                        inQuotes++;
                        c = query.charAt(inQuotes);
                    }
                    if (c == '\'') {
                        i = inQuotes + 1;
                        if (i < query.length() && query.charAt(i) != ';') {
                            throw ElytronToolMessages.msg.credentialStoreURIParameterClosingQuote(uri);
                        }
                    } else {
                        throw ElytronToolMessages.msg.credentialStoreURIParameterUnexpectedEnd(uri);
                    }
                } else if (c == ';') {
                    value = token.toString();
                    if (key == null) {
                        throw ElytronToolMessages.msg.credentialStoreURIParameterNameExpected(uri);
                    }
                    // put to options and reset key, value and token
                    credentialStoreConfigurationOptions.put(key, value);
                    i++;
                    key = null;
                    value = null;
                    token.setLength(0);
                    // set state to KEY
                    state = 0;
                } else {
                    token.append(c);
                    i++;
                }
            }
        }
        if (key != null && token.length() > 0) {
            credentialStoreConfigurationOptions.put(key, token.toString());
        } else {
            throw ElytronToolMessages.msg.credentialStoreURIParameterUnexpectedEnd(uri);
        }
    }

    /**
     * Display help to the command.
     */
    @Override
    public void help() {
        HelpFormatter help = new HelpFormatter();
        help.setWidth(WIDTH);
        help.printHelp(ElytronToolMessages.msg.cmdHelp(ElytronTool.TOOL_JAR, CREDENTIAL_STORE_COMMAND), options, true);
    }
}
