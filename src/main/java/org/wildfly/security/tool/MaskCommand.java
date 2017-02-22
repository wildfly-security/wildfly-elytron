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

import java.security.GeneralSecurityException;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionGroup;
import org.apache.commons.cli.Options;
import org.wildfly.security.util.Alphabet;
import org.wildfly.security.util.PasswordBasedEncryptionUtil;

/**
 * Mask Command
 *
 * This command is used for creation of masked password strings.
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 */
class MaskCommand extends Command {

    /**
     * Command string
     */
    public static final String MASK_COMMAND = "mask";

    static final String DEFAULT_ALGORITHM = "PBEWithMD5AndDES";
    static final String DEFAULT_PICKETBOX_INITIAL_KEY_MATERIAL = "somearbitrarycrazystringthatdoesnotmatter";

    static final String SALT_PARAM = "salt";
    static final String ITERATION_PARAM = "iteration";
    static final String SECRET_PARAM = "secret";
    static final String HELP_PARAM = "help";

    private final Options options;
    private CommandLineParser parser = new DefaultParser();
    private CommandLine cmdLine = null;

    MaskCommand() {
        Option salt = new Option("s", SALT_PARAM, true, ElytronToolMessages.msg.cmdMaskSaltDesc());
        Option iteration = new Option("i", ITERATION_PARAM, true, ElytronToolMessages.msg.cmdMaskIterationCountDesc());
        OptionGroup og = new OptionGroup();
        Option x = new Option("x", SECRET_PARAM, true, ElytronToolMessages.msg.cmdMaskSecretDesc());
        Option h = new Option("h", HELP_PARAM, false, ElytronToolMessages.msg.cmdLineHelp());
        og.addOption(x);
        og.addOption(h);
        og.setRequired(true);
        options = new Options();
        options.addOptionGroup(og);
        options.addOption(salt);
        options.addOption(iteration);
    }

    @Override
    public void execute(String[] args) throws Exception {
        setStatus(GENERAL_CONFIGURATION_ERROR);
        cmdLine = parser.parse(options, args, true);
        if (cmdLine.hasOption(HELP_PARAM)) {
            help();
            setStatus(ElytronTool.ElytronToolExitStatus_OK);
            return;
        }

        String salt = cmdLine.getOptionValue(SALT_PARAM);
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

        String secret = cmdLine.getOptionValue(SECRET_PARAM);
        if (secret == null) {
            setStatus(GENERAL_CONFIGURATION_ERROR);
            throw ElytronToolMessages.msg.secretNotSpecified();
        }

        final String masked = computeMasked(secret, salt, iterationCount);
        setStatus(ElytronTool.ElytronToolExitStatus_OK);
        System.out.println(masked);
    }

    static String computeMasked(String secret, String salt, int iteration) throws GeneralSecurityException {
        PasswordBasedEncryptionUtil encryptUtil = new PasswordBasedEncryptionUtil.Builder()
                .alphabet(Alphabet.Base64Alphabet.PICKETBOX_COMPATIBILITY)
                .keyAlgorithm(DEFAULT_ALGORITHM)
                .password(DEFAULT_PICKETBOX_INITIAL_KEY_MATERIAL)
                .salt(salt)
                .iteration(iteration)
                .encryptMode()
                .build();
        return "MASK-" + encryptUtil.encryptAndEncode(secret.toCharArray()) + ";" + salt + ";" + String.valueOf(iteration);
    }

    /**
     * Display help to the command.
     */
    @Override
    public void help() {
        HelpFormatter help = new HelpFormatter();
        help.printHelp("java -jar " + ElytronTool.TOOL_JAR + " " + MASK_COMMAND + " <options>",
                ElytronToolMessages.msg.cmdMaskHelpHeader(DEFAULT_ALGORITHM),
                options, "",true);
    }
}
