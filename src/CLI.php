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
 * This file: CLI handler (last modified: 2020.07.04).
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
                $this->Loader->L10N->getString('scan_complete')
            );
            return true;
        });

        /** Echo the ASCII header art and CLI-mode information. */
        echo $this->Loader->L10N->getString('cli_ln1') . "\n" . $this->Loader->L10N->getString('cli_ln2') . "\n\n" . $this->Loader->L10N->getString('cli_ln3');

        /** Open STDIN. */
        $Handle = fopen('php://stdin', 'r');

        /** This repeats until the client exits ("quit", "q", "exit", etc). */
        while (true) {
            /** Set CLI process title. */
            if (function_exists('cli_set_process_title')) {
                cli_set_process_title($this->Loader->ScriptIdent);
            }

            /** Echo the CLI-mode prompt. */
            echo "\n\n>> ";

            /** Wait for user input. */
            $Clean = trim(fgets($Handle));

            /** Set CLI process title with "working" notice. */
            if (function_exists('cli_set_process_title')) {
                cli_set_process_title($this->Loader->ScriptIdent . ' - ' . $this->Loader->L10N->getString('cli_working') . '...');
            }

            /** Fetch the command. */
            $Command = strtolower($this->Loader->substrBeforeFirst($Clean, ' ') ?: $Clean);

            /** Exit CLI-mode. */
            if ($Command === 'quit' || $Command === 'q' || $Command === 'exit') {
                break;
            }

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
            elseif ($Command === 'coex') {
                $TargetData = substr($Clean, strlen($Command) + 1);
                echo sprintf(
                    "\n\$sha256:%s;\$StringLength:%d;%s\n",
                    hash('sha256', $TargetData),
                    strlen($TargetData),
                    $this->Loader->L10N->getString('cli_signature_placeholder')
                );
            }

            /** Convert a binary string to a hexadecimal. */
            elseif ($Command === 'hex_encode' || $Command === 'x') {
                $TargetData = substr($Clean, strlen($Command) + 1);
                echo "\n" . bin2hex($TargetData) . "\n";
            }

            /** Convert a hexadecimal to a binary string. */
            elseif ($Command === 'hex_decode') {
                $TargetData = substr($Clean, strlen($Command) + 1);
                echo "\n" . ($this->Loader->hexSafe($TargetData) ?: $this->Loader->L10N->getString('invalid_data')) . "\n";
            }

            /** Convert a binary string to a base64 string. */
            elseif ($Command === 'base64_encode' || $Command === 'b') {
                $TargetData = substr($Clean, strlen($Command) + 1);
                echo "\n" . base64_encode($TargetData) . "\n";
            }

            /** Convert a base64 string to a binary string. */
            elseif ($Command === 'base64_decode') {
                $TargetData = substr($Clean, strlen($Command) + 1);
                echo "\n" . (base64_decode($TargetData) ?: $this->Loader->L10N->getString('invalid_data')) . "\n";
            }

            /** Scan a file or directory. */
            elseif ($Command === 'scan' || $Command === 's') {
                $TargetData = substr($Clean, strlen($Command) + 1);
                echo "\n";
                echo $this->Scanner->scan($TargetData, true, true) . "\n";
            }

            /** Print the command list. */
            elseif ($Command === 'c') {
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
                return sprintf($this->Loader->L10N->getString('failed_to_access'), $Params) . "\n";
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
            $Data = $this->Loader->readFileBlocks($Params, 0, true);
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
                $SectionName = str_ireplace("\x00", '', substr($SectionHead, 0, 8));
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
            if (strpos($Data, "V\x00a\x00r\x00F\x00i\x00l\x00e\x00I\x00n\x00f\x00o\x00\x00\x00\x00\x00\x24") !== false) {
                $PEParts = $this->Loader->substrAfterLast($Data, "V\x00a\x00r\x00F\x00i\x00l\x00e\x00I\x00n\x00f\x00o\x00\x00\x00\x00\x00\x24");
                foreach ([
                    ["F\x00i\x00l\x00e\x00D\x00e\x00s\x00c\x00r\x00i\x00p\x00t\x00i\x00o\x00n\x00\x00\x00", 'PEFileDescription'],
                    ["F\x00i\x00l\x00e\x00V\x00e\x00r\x00s\x00i\x00o\x00n\x00\x00\x00", 'PEFileVersion'],
                    ["P\x00r\x00o\x00d\x00u\x00c\x00t\x00N\x00a\x00m\x00e\x00\x00\x00", 'PEProductName'],
                    ["P\x00r\x00o\x00d\x00u\x00c\x00t\x00V\x00e\x00r\x00s\x00i\x00o\x00n\x00\x00\x00", 'PEProductVersion'],
                    ["L\x00e\x00g\x00a\x00l\x00C\x00o\x00p\x00y\x00r\x00i\x00g\x00h\x00t\x00\x00\x00", 'PECopyright'],
                    ["O\x00r\x00i\x00g\x00i\x00n\x00a\x00l\x00F\x00i\x00l\x00e\x00n\x00a\x00m\x00e\x00\x00\x00", 'PEOriginalFilename'],
                    ["C\x00o\x00m\x00p\x00a\x00n\x00y\x00N\x00a\x00m\x00e\x00\x00\x00", 'PECompanyName'],
                ] as $PEVars) {
                    if (strpos($PEParts, $PEVars[0]) !== false && (
                        $ThisPEData = trim(str_ireplace("\x00", '', $this->Loader->substrBeforeFirst(
                            $this->Loader->substrAfterLast($PEParts, $PEVars[0]),
                            "\x00\x00\x00"
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
                $Data = $this->Loader->request($Params);
            } elseif (is_file($Params) && is_readable($Params)) {
                $Data = $this->Loader->readFileBlocks($Params, 0, true);
            }
            if (empty($Data)) {
                return $this->Loader->L10N->getString('invalid_data') . "\n";
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
                    $Data = $this->Loader->request($Params);
                } elseif (is_file($Params) && is_readable($Params)) {
                    $Data = $this->Loader->readFileBlocks($Params, 0, true);
                }
                if (empty($Data)) {
                    return $this->Loader->L10N->getString('invalid_data') . "\n";
                }
                return hash($this->LastAlgo, $Data) . ':' . strlen($Data) . ':' . $this->Loader->L10N->getString('cli_signature_placeholder') . "\n";
            });
        }
        return $this->Loader->L10N->getString('cli_algo_not_supported') . "\n";
    }
}
