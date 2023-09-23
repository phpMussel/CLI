<?php
/**
 * This file is a part of the phpMussel\CLI package.
 * Homepage: https://phpmussel.github.io/
 *
 * PHPMUSSEL COPYRIGHT 2013 AND BEYOND BY THE PHPMUSSEL TEAM.
 *
 * License: GNU/GPLv2
 * @see LICENSE.txt
 *
 * This file: CLI handler (last modified: 2023.09.25).
 */

namespace phpMussel\CLI;

class CLI
{
    /**
     * @var \phpMussel\Core\Loader The instantiated loader object.
     */
    private $Loader;

    /**
     * @var \phpMussel\Core\Scanner The instantiated scanner object.
     */
    private $Scanner;

    /**
     * @var string The path to the core L10N files.
     */
    private $L10NPath = __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'l10n' . DIRECTORY_SEPARATOR;

    /**
     * @var string Used by some CLI functionality.
     */
    private $LastAlgo = '';

    /**
     * Construct the loader.
     *
     * @param \phpMussel\Core\Loader $Loader The instantiated loader object, passed by reference.
     * @param \phpMussel\Core\Scanner $Scanner The instantiated scanner object, passed by reference.
     * @return void
     */
    public function __construct(\phpMussel\Core\Loader &$Loader, \phpMussel\Core\Scanner &$Scanner)
    {
        /** Link the loader to this instance. */
        $this->Loader = &$Loader;

        /** Link the scanner to this instance. */
        $this->Scanner = &$Scanner;
        $this->Scanner->CalledFrom = 'CLI';

        /** Load phpMussel CLI handler L10N data. */
        $this->Loader->loadL10N($this->L10NPath);

        /** Maintenance mode is enabled. Exit early. */
        if ($this->Loader->Configuration['core']['maintenance_mode']) {
            return;
        }

        /**
         * Display scan progress.
         *
         * @param string $Data Not used.
         * @return true
         */
        $this->Loader->Events->addHandler('countersChanged', function (string $Data = ''): bool {
            if ($this->Loader->InstanceCache['ThisScanDone'] === $this->Loader->InstanceCache['ThisScanTotal']) {
                echo "\r";
                return true;
            }
            echo sprintf(
                "\r%d/%d %s ...",
                $this->Loader->InstanceCache['ThisScanDone'],
                $this->Loader->InstanceCache['ThisScanTotal'],
                $this->Loader->L10N->getString('response.Complete')
            );
            return true;
        });

        /** Echo the ASCII header art and CLI-mode information. */
        echo "\033[0;33m" . $this->Loader->L10N->getString('cli_ln1') . "\n" . $this->Loader->L10N->getString('cli_ln2') . "\n\n" . $this->Loader->L10N->getString('cli_ln3');

        /** Open STDIN. */
        $Handle = fopen('php://stdin', 'rb');

        /** This repeats until the client exits ("quit", "q", "exit", etc). */
        while (true) {
            /** Set CLI process title. */
            if (function_exists('cli_set_process_title')) {
                cli_set_process_title($this->Loader->ScriptIdent);
            }

            /** Echo the CLI-mode prompt. */
            echo "\n\n\033[0;92m>>\033[0m ";

            /** Wait for user input. */
            $Clean = trim(fgets($Handle));

            /** Set CLI process title with "working" notice. */
            if (function_exists('cli_set_process_title')) {
                cli_set_process_title($this->Loader->ScriptIdent . ' - ' . $this->Loader->L10N->getString('cli_working') . '...');
            }

            /** Fetch the command. */
            $CommandNatural = $this->Loader->substrBeforeFirst($Clean, ' ') ?: $Clean;
            $Command = strtolower($CommandNatural);

            /** Exit CLI-mode. */
            if (preg_match('~^(?:(?:[Qq]|ԛ)(?:[Uu][Ii][Tt])?|[Ee][Xx][Ii][Tt])$~', $CommandNatural)) {
                break;
            }

            // Yellow.
            echo "\033[0;33m";

            /** Generate a hash signature using a file or directory. */
            if (substr($Command, 0, 10) === 'hash_file:') {
                $this->LastAlgo = substr($Command, 10);
                echo "\n" . $this->hashFile($Clean);
            }

            /** Generate a CoEx signature using a file. */
            elseif ($Command === 'coex_file') {
                echo "\n" . $this->coexFile($Clean);
            }

            /** Fetch PE metadata. */
            elseif ($Command === 'pe_meta') {
                echo "\n" . $this->peMeta($Clean);
            }

            /** Generate a hash signature using a string. */
            elseif (substr($Command, 0, 5) === 'hash:') {
                $this->LastAlgo = substr($Command, 5);
                if (in_array($this->LastAlgo, hash_algos())) {
                    $TargetData = substr($Clean, strlen($Command) + 1);
                    echo "\n" . hash($this->LastAlgo, $TargetData) . ':' . strlen($TargetData) . ':' . $this->Loader->L10N->getString('cli_signature_placeholder') . "\n";
                } else {
                    echo "\n" . $this->Loader->L10N->getString('cli_algo_not_supported') . "\n";
                }
            }

            /** Generate a URL scanner signature from a URL. */
            elseif ($Command === 'url_sig') {
                echo "\n";
                $Clean = $this->Scanner->normalise(substr($Clean, strlen($Command) + 1));
                $URL = ['AvoidMe' => '', 'ForThis' => ''];
                if (
                    !preg_match_all('/(data|file|https?|ftps?|sftp|ss[hl])\:\/\/(www\d{0,3}\.)?([\da-z.-]{1,512})/i', $Clean, $URL['domain']) ||
                    !preg_match_all('/(data|file|https?|ftps?|sftp|ss[hl])\:\/\/(www\d{0,3}\.)?([\!\#\$\&-;\=\?\@-\[\]_a-z~]{1,4000})/i', $Clean, $URL['url'])
                ) {
                    echo $this->Loader->L10N->getString('invalid_url') . "\n";
                    continue;
                }
                echo 'DOMAIN:' . hash('md5', $URL['domain'][3][0]) . ':' . strlen($URL['domain'][3][0]) . ':' . $this->Loader->L10N->getString('cli_signature_placeholder') . "\n";
                $URL['ForThis'] = hash('md5', $URL['url'][3][0]) . ':' . strlen($URL['url'][3][0]);
                $URL['AvoidMe'] .= ',' . $URL['ForThis'] . ',';
                echo 'URL:' . $URL['ForThis'] . ':' . $this->Loader->L10N->getString('cli_signature_placeholder') . "\n";
                if (preg_match('/[^\da-z.-]$/i', $URL['url'][3][0])) {
                    $URL['x'] = preg_replace('/[^\da-z.-]+$/i', '', $URL['url'][3][0]);
                    $URL['ForThis'] = hash('md5', $URL['x']) . ':' . strlen($URL['x']);
                    if (strpos($URL['AvoidMe'], $URL['ForThis']) === false) {
                        $URL['AvoidMe'] .= ',' . $URL['ForThis'] . ',';
                        echo 'URL:' . $URL['ForThis'] . ':' . $this->Loader->L10N->getString('cli_signature_placeholder') . "\n";
                    }
                }
                if (strpos($URL['url'][3][0], '?') !== false) {
                    $URL['x'] = $this->Loader->substrBeforeFirst($URL['url'][3][0], '?');
                    $URL['ForThis'] = hash('md5', $URL['x']) . ':' . strlen($URL['x']);
                    if (strpos($URL['AvoidMe'], $URL['ForThis']) === false) {
                        $URL['AvoidMe'] .= ',' . $URL['ForThis'] . ',';
                        echo 'URL:' . $URL['ForThis'] . ':' . $this->Loader->L10N->getString('cli_signature_placeholder') . "\n";
                    }
                    $URL['x'] = $this->Loader->substrAfterFirst($URL['url'][3][0], '?');
                    $URL['ForThis'] = hash('md5', $URL['x']) . ':' . strlen($URL['x']);
                    if (
                        strpos($URL['AvoidMe'], $URL['ForThis']) === false &&
                        $URL['ForThis'] !== 'd41d8cd98f00b204e9800998ecf8427e:0'
                    ) {
                        $URL['AvoidMe'] .= ',' . $URL['ForThis'] . ',';
                        echo 'QUERY:' . $URL['ForThis'] . ':' . $this->Loader->L10N->getString('cli_signature_placeholder') . "\n";
                    }
                }
                unset($URL);
            }

            /** Generate a CoEx signature using a string. */
            elseif (preg_match('~^(?:(?:[Cc]|ϲ|с)(?:[Oo]|ο|о)(?:[Ee]|е)(?:[Xx]|х))$~', $CommandNatural)) {
                $TargetData = substr($Clean, strlen($Command) + 1);
                echo sprintf(
                    "\n\$sha256:%s;\$StringLength:%d;%s\n",
                    hash('sha256', $TargetData),
                    strlen($TargetData),
                    $this->Loader->L10N->getString('cli_signature_placeholder')
                );
            }

            /** Convert a binary string to a hexadecimal. */
            elseif (preg_match('~^(?:[Hh][Ee][Xx]_[Ee][Nn][Cc][Oo][Dd][Ee]|[Xx]|х)$~', $CommandNatural)) {
                $TargetData = substr($Clean, strlen($Command) + 1);
                echo "\n" . bin2hex($TargetData) . "\n";
            }

            /** Convert a hexadecimal to a binary string. */
            elseif ($Command === 'hex_decode') {
                $TargetData = substr($Clean, strlen($Command) + 1);
                echo "\n" . ($this->Loader->hexSafe($TargetData) ?: $this->Loader->L10N->getString('response.Invalid data')) . "\n";
            }

            /** Convert a binary string to a base64 string. */
            elseif ($Command === 'base64_encode' || $Command === 'b') {
                $TargetData = substr($Clean, strlen($Command) + 1);
                echo "\n" . base64_encode($TargetData) . "\n";
            }

            /** Convert a base64 string to a binary string. */
            elseif ($Command === 'base64_decode') {
                $TargetData = substr($Clean, strlen($Command) + 1);
                echo "\n" . (base64_decode($TargetData) ?: $this->Loader->L10N->getString('response.Invalid data')) . "\n";
            }

            /** Scan a file or directory. */
            elseif (preg_match('~^(?:[Ss][Cc][Aa][Nn]|[Ss]|ѕ)$~', $CommandNatural)) {
                $TargetData = substr($Clean, strlen($Command) + 1);
                echo "\n";
                echo $this->Scanner->scan($TargetData) . "\n";
            }

            /** Print the command list. */
            elseif (preg_match('~^(?:[Cc]|ϲ|с)$~', $CommandNatural)) {
                echo "\n" . $this->Loader->L10N->getString('cli_commands');
            }

            /** Print a list of supported algorithms. */
            elseif ($Command === 'algo') {
                echo "\n";
                $Algos = hash_algos();
                $Pos = 1;
                foreach ($Algos as $Algo) {
                    if ($Pos === 1) {
                        echo ' ';
                    }
                    echo $Algo;
                    $Pos += 16;
                    if ($Pos < 76) {
                        echo str_repeat(' ', 16 - strlen($Algo));
                    } else {
                        $Pos = 1;
                        echo "\n";
                    }
                }
                echo "\n";
            }

            /** Bad command notice. */
            else {
                echo "\n" . $this->Loader->L10N->getString('bad_command') . "\n";
            }
        }
    }

    /**
     * Runs CLI-mode commands recursively.
     *
     * @param string $Command Command with parameters for the action to be taken.
     * @param callable $Callable The callback to execute.
     * @return string Returnable data to be echoed to the CLI output.
     */
    public function recursiveCommand(string $Command, callable $Callable): string
    {
        [$Command, $Params] = explode(' ', $Command);
        if (is_dir($Params)) {
            if (!is_readable($Params)) {
                return sprintf($this->Loader->L10N->getString('response.Failed to access %s'), $Params) . "\n";
            }
            $Decal = [':-) - (-:', ':-) \\ (-:', ':-) | (-:', ':-) / (-:'];
            $Frame = 0;
            $Params = realpath($Params);
            $List = $this->Scanner->directoryRecursiveList($Params);
            $Returnable = '';
            foreach ($List as $Item) {
                echo "\r" . $Decal[$Frame];
                $Returnable .= is_file($Params . $Item) ? $Callable($Params . $Item) : sprintf($this->Loader->L10N->getString('cli_is_not_a'), $Params . $Item) . "\n";
                $Frame = $Frame < 3 ? $Frame + 1 : 0;
            }
            echo "\r         ";
            return $Returnable;
        }
        return is_file($Params) || filter_var($Params, FILTER_VALIDATE_URL) ? $Callable($Params) : sprintf($this->Loader->L10N->getString('cli_is_not_a'), $Params) . "\n";
    }

    /**
     * Generate PE metadata signatures.
     *
     * @param string $File The file to generate signatures from.
     * @return string The generated signatures.
     */
    private function peMeta(string $File): string
    {
        return $this->recursiveCommand($File, function ($Params) {
            $Data = $this->Loader->readFileContent($Params);
            $Returnable = '';
            if (substr($Data, 0, 2) !== 'MZ') {
                return $this->Loader->L10N->getString('cli_pe1') . "\n";
            }
            $PELength = strlen($Data);
            $Offset = $this->Loader->unpackSafe('S', substr($Data, 60, 4));
            $Offset = $Offset[1];
            while (true) {
                $Valid = true;
                if ($Offset < 1 || $Offset > 16384 || $Offset > $PELength) {
                    $Valid = false;
                    break;
                }
                $Magic = substr($Data, $Offset, 2);
                if ($Magic !== 'PE') {
                    $Valid = false;
                    break;
                }
                $Proc = $this->Loader->unpackSafe('S', substr($Data, $Offset + 4, 2));
                $Proc = $Proc[1];
                if ($Proc != 0x14c && $Proc != 0x8664) {
                    $Valid = false;
                    break;
                }
                $NumberOfSections = $this->Loader->unpackSafe('S', substr($Data, $Offset + 6, 2));
                $NumberOfSections = $NumberOfSections[1];
                if ($NumberOfSections < 1 || $NumberOfSections > 40) {
                    $Valid = false;
                }
                break;
            }
            if (!$Valid) {
                return $this->Loader->L10N->getString('cli_pe1') . "\n";
            }
            $OptHdrSize = $this->Loader->unpackSafe('S', substr($Data, $Offset + 20, 2));
            $OptHdrSize = $OptHdrSize[1];
            $Returnable .= $this->Loader->L10N->getString('cli_pe2') . "\n";
            for ($PECaret = 0; $PECaret < $NumberOfSections; $PECaret++) {
                $SectionHead = substr($Data, $Offset + 24 + $OptHdrSize + ($PECaret * 40), $NumberOfSections * 40);
                $SectionName = str_ireplace("\0", '', substr($SectionHead, 0, 8));
                $VirtualSize = $this->Loader->unpackSafe('S', substr($SectionHead, 8, 4));
                $VirtualSize = $VirtualSize[1];
                $VirtualAddress = $this->Loader->unpackSafe('S', substr($SectionHead, 12, 4));
                $VirtualAddress = $VirtualAddress[1];
                $SizeOfRawData = $this->Loader->unpackSafe('S', substr($SectionHead, 16, 4));
                $SizeOfRawData = $SizeOfRawData[1];
                $PointerToRawData = $this->Loader->unpackSafe('S', substr($SectionHead, 20, 4));
                $PointerToRawData = $PointerToRawData[1];
                $SectionData = substr($Data, $PointerToRawData, $SizeOfRawData);
                $SHA256 = hash('sha256', $SectionData);
                $Returnable .= $SizeOfRawData . ':' . $SHA256 . ':' . $SectionName . "\n";
            }
            $Returnable .= "\n";
            if (strpos($Data, "V\0a\0r\0F\0i\0l\0e\0I\0n\0f\0o\0\0\0\0\0\x24") !== false) {
                $PEParts = $this->Loader->substrAfterLast($Data, "V\0a\0r\0F\0i\0l\0e\0I\0n\0f\0o\0\0\0\0\0\x24");
                foreach ([
                    ["F\0i\0l\0e\0D\0e\0s\0c\0r\0i\0p\0t\0i\0o\0n\0\0\0", 'PEFileDescription'],
                    ["F\0i\0l\0e\0V\0e\0r\0s\0i\0o\0n\0\0\0", 'PEFileVersion'],
                    ["P\0r\0o\0d\0u\0c\0t\0N\0a\0m\0e\0\0\0", 'PEProductName'],
                    ["P\0r\0o\0d\0u\0c\0t\0V\0e\0r\0s\0i\0o\0n\0\0\0", 'PEProductVersion'],
                    ["L\0e\0g\0a\0l\0C\0o\0p\0y\0r\0i\0g\0h\0t\0\0\0", 'PECopyright'],
                    ["O\0r\0i\0g\0i\0n\0a\0l\0F\0i\0l\0e\0n\0a\0m\0e\0\0\0", 'PEOriginalFilename'],
                    ["C\0o\0m\0p\0a\0n\0y\0N\0a\0m\0e\0\0\0", 'PECompanyName'],
                ] as $PEVars) {
                    if (strpos($PEParts, $PEVars[0]) !== false && (
                        $ThisPEData = trim(str_ireplace("\0", '', $this->Loader->substrBeforeFirst(
                            $this->Loader->substrAfterLast($PEParts, $PEVars[0]),
                            "\0\0\0"
                        )))
                    )) {
                        $Returnable .= sprintf(
                            "\$%s:%s:%d:%s\n",
                            $PEVars[1],
                            hash('sha256', $ThisPEData),
                            strlen($ThisPEData),
                            $this->Loader->L10N->getString('cli_signature_placeholder')
                        );
                    }
                }
            }
            return $Returnable;
        });
    }

    /**
     * Generate a "complex extended signature".
     *
     * @param string $Clean The file's given path.
     * @return string The generated signature.
     */
    private function coexFile(string $Clean): string
    {
        return $this->recursiveCommand($Clean, function ($Params) {
            if (filter_var($Params, FILTER_VALIDATE_URL)) {
                $Data = $this->Loader->Request->request($Params);
            } elseif (is_file($Params) && is_readable($Params)) {
                $Data = $this->Loader->readFileContent($Params);
            }
            if (empty($Data)) {
                return $this->Loader->L10N->getString('response.Invalid data') . "\n";
            }
            return sprintf(
                "\$sha256:%s;\$StringLength:%d;%s\n",
                hash('sha256', $Data),
                strlen($Data),
                $this->Loader->L10N->getString('cli_signature_placeholder')
            );
        });
    }

    /**
     * Generate a "complex extended signature".
     *
     * @param string $Clean The file's given path.
     * @return string The generated signature.
     */
    private function hashFile(string $Clean): string
    {
        if (in_array($this->LastAlgo, hash_algos())) {
            return $this->recursiveCommand($Clean, function ($Params) {
                if (filter_var($Params, FILTER_VALIDATE_URL)) {
                    $Data = $this->Loader->Request->request($Params);
                } elseif (is_file($Params) && is_readable($Params)) {
                    $Data = $this->Loader->readFileContent($Params);
                }
                if (empty($Data)) {
                    return $this->Loader->L10N->getString('response.Invalid data') . "\n";
                }
                return hash($this->LastAlgo, $Data) . ':' . strlen($Data) . ':' . $this->Loader->L10N->getString('cli_signature_placeholder') . "\n";
            });
        }
        return $this->Loader->L10N->getString('cli_algo_not_supported') . "\n";
    }
}
