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
     * @var string The path to the core asset files.
     */
    private $AssetsPath = __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'assets' . DIRECTORY_SEPARATOR;

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

        /** Load phpMussel CLI handler configuration defaults and perform fallbacks. */
        if (
            is_readable($this->AssetsPath . 'config.yml') &&
            $Configuration = $this->Loader->readFile($this->AssetsPath . 'config.yml')
        ) {
            $Defaults = [];
            $this->Loader->YAML->process($Configuration, $Defaults);
            if (isset($Defaults)) {
                $this->Loader->fallback($Defaults);
                $this->Loader->ConfigurationDefaults = array_merge_recursive($this->Loader->ConfigurationDefaults, $Defaults);
            }
        }

        /** Load phpMussel CLI handler L10N data. */
        $this->Loader->loadL10N($this->L10NPath);

        /** Maintenance mode is enabled. Exit early. */
        if ($this->Loader->Configuration['core']['maintenance_mode']) {
            return;
        }

        /** Get CLI arguments (if available). */
        if (empty($argv)) {
            $ForkState = '';
            $ForkCommand = '';
            $ForkWorkingOn = '';
        } else {
            $ForkState = $argv[1] ?? '';
            $ForkCommand = $argv[2] ?? '';
            $ForkWorkingOn = $argv[3] ?? '';
        }

        /** Triggered by the forked child process in CLI-mode. */
        if ($ForkState === 'cli_scan') {
            /** Fetch the command. */
            $Command = strtolower($this->Loader->substrBeforeFirst($ForkCommand, ' ') ?: $ForkCommand);

            /** Scan a file or directory. */
            if ($Command === 'scan') {
                echo $this->scan($ForkCommand, $ForkWorkingOn);
            }

            /** Generate a hash signature using a file or directory. */
            if (substr($Command, 0, 10) === 'hash_file:') {
                $this->LastAlgo = substr($Command, 10);
                echo $this->hashFile($ForkCommand);
                return;
            }

            /** Generate a CoEx signature using a file. */
            if ($Command === 'coex_file') {
                echo $this->coexFile($ForkCommand);
                return;
            }

            /** Fetch PE metadata. */
            if ($Command === 'pe_meta') {
                echo $this->peMeta($ForkCommand);
                return;
            }

            /** End the child process. */
            return;
        }

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
                $URL = ['avoidme' => '', 'forthis' => ''];
                if (
                    !preg_match_all('/(data|file|https?|ftps?|sftp|ss[hl])\:\/\/(www\d{0,3}\.)?([\da-z.-]{1,512})/i', $Clean, $URL['domain']) ||
                    !preg_match_all('/(data|file|https?|ftps?|sftp|ss[hl])\:\/\/(www\d{0,3}\.)?([\!\#\$\&-;\=\?\@-\[\]_a-z~]{1,4000})/i', $Clean, $URL['url'])
                ) {
                    echo $this->Loader->L10N->getString('invalid_url') . "\n";
                } else {
                    echo 'DOMAIN:' . md5($URL['domain'][3][0]) . ':' . strlen($URL['domain'][3][0]) . ':' . $this->Loader->L10N->getString('cli_signature_placeholder') . "\n";
                    $URL['forthis'] = md5($URL['url'][3][0]) . ':' . strlen($URL['url'][3][0]);
                    $URL['avoidme'] .= ',' . $URL['forthis'] . ',';
                    echo 'URL:' . $URL['forthis'] . ':' . $this->Loader->L10N->getString('cli_signature_placeholder') . "\n";
                    if (preg_match('/[^\da-z.-]$/i', $URL['url'][3][0])) {
                        $URL['x'] = preg_replace('/[^\da-z.-]+$/i', '', $URL['url'][3][0]);
                        $URL['forthis'] = md5($URL['x']) . ':' . strlen($URL['x']);
                        if (strpos($URL['avoidme'], $URL['forthis']) === false) {
                            $URL['avoidme'] .= ',' . $URL['forthis'] . ',';
                            echo 'URL:' . $URL['forthis'] . ':' . $this->Loader->L10N->getString('cli_signature_placeholder') . "\n";
                        }
                    }
                    if (strpos($URL['url'][3][0], '?') !== false) {
                        $URL['x'] = $this->Loader->substrBeforeFirst($URL['url'][3][0], '?');
                        $URL['forthis'] = md5($URL['x']) . ':' . strlen($URL['x']);
                        if (strpos($URL['avoidme'], $URL['forthis']) === false) {
                            $URL['avoidme'] .= ',' . $URL['forthis'] . ',';
                            echo 'URL:' . $URL['forthis'] . ':' . $this->Loader->L10N->getString('cli_signature_placeholder') . "\n";
                        }
                        $URL['x'] = $this->Loader->substrAfterFirst($URL['url'][3][0], '?');
                        $URL['forthis'] = md5($URL['x']) . ':' . strlen($URL['x']);
                        if (
                            strpos($URL['avoidme'], $URL['forthis']) === false &&
                            $URL['forthis'] != 'd41d8cd98f00b204e9800998ecf8427e:0'
                        ) {
                            $URL['avoidme'] .= ',' . $URL['forthis'] . ',';
                            echo 'QUERY:' . $URL['forthis'] . ':' . $this->Loader->L10N->getString('cli_signature_placeholder') . "\n";
                        }
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
                echo "\n" . ($this->Scanner->hexSafe($TargetData) ?: $this->Loader->L10N->getString('invalid_data')) . "\n";
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
                echo "\n";
                $Clean = substr($Clean, strlen($Command) + 1);
                $Out = $r = '';
                $this->Loader->InstanceCache['StartTime'] = time() + ($this->Loader->Configuration['core']['time_offset'] * 60);
                $this->Loader->InstanceCache['start_time_2822'] = $this->Loader->timeFormat(
                    $this->Loader->InstanceCache['StartTime'],
                    $this->Loader->Configuration['core']['time_format']
                );
                echo $s = $this->Loader->InstanceCache['start_time_2822'] . ' ' . $this->Loader->L10N->getString('started') . $this->Loader->L10N->getString('_fullstop_final') . "\n";
                if (is_dir($Clean)) {
                    if (!is_readable($Clean)) {
                        $Out = '> ' . sprintf($this->Loader->L10N->getString('failed_to_access'), $Clean) . "\n";
                    } else {
                        $Terminal = substr($Params, -1);
                        $Gap = ($Terminal !== "\\" && $Terminal !== '/') ? DIRECTORY_SEPARATOR : '';
                        $List = $this->Scanner->directoryRecursiveList($Clean);
                        $Total = count($List);
                        $Current = 0;
                        foreach ($List as $Item) {
                            $Percent = round(($Current / $Total) * 100, 2) . '%';
                            echo $Percent . ' ' . $this->Loader->L10N->getString('scan_complete') . $this->Loader->L10N->getString('_fullstop_final');
                            if ($this->Loader->Configuration['cli']['allow_process_forking']) {
                                $Out = $this->fork('scan ' . $Clean . $Gap . $Item, $Item);
                            } else {
                                $Out = $this->scan($Clean . $Gap . $Item, $Item);
                            }
                            if (!$Out) {
                                $Out = '> ' . sprintf(
                                    $this->Loader->L10N->getString('_exclamation_final'),
                                    $this->Loader->L10N->getString('cli_failed_to_complete') . ' (' . $Item . ')'
                                ) . "\n";
                            }
                            $r .= $Out;
                            echo "\r" . $this->Scanner->prescanDecode($Out);
                            $Out = '';
                        }
                    }
                } elseif (is_file($Clean)) {
                    if ($this->Loader->Configuration['cli']['allow_process_forking']) {
                        $Out = $this->fork('scan ' . $Clean, $Clean);
                    } else {
                        $Out = $this->scan($Clean, $Clean);
                    }
                    if (!$Out) {
                        $Out = '> ' . sprintf(
                            $this->Loader->L10N->getString('_exclamation_final'),
                            $this->Loader->L10N->getString('cli_failed_to_complete')
                        ) . "\n";
                    }
                } elseif (!$Out) {
                    $Out = '> ' . sprintf($this->Loader->L10N->getString('cli_is_not_a'), $Clean) . "\n";
                }
                $r .= $Out;
                if ($Out) {
                    echo $this->Scanner->prescanDecode($Out);
                    $Out = '';
                }
                $this->Loader->InstanceCache['EndTime'] = time() + ($this->Loader->Configuration['core']['time_offset'] * 60);
                $this->Loader->InstanceCache['end_time_2822'] = $this->Loader->timeFormat(
                    $this->Loader->InstanceCache['EndTime'],
                    $this->Loader->Configuration['core']['time_format']
                );
                $r = $s . $r;
                $s = $this->Loader->InstanceCache['end_time_2822'] . ' ' . $this->Loader->L10N->getString('finished') . $this->Loader->L10N->getString('_fullstop_final') . "\n";
                echo $s;
                $r .= $s;
                $this->Loader->Events->fireEvent('writeToScanLog', $r);
                $this->Loader->Events->fireEvent('writeToSerialLog');
                unset($r, $s);
            }

            /** Print the command list. */
            elseif ($Command === 'c') {
                echo $this->Loader->L10N->getString('cli_commands');
            }

            /** Print a list of supported algorithms. */
            elseif ($Command === 'algo') {
                $this->LastAlgos = hash_algos();
                $Pos = 1;
                foreach ($this->LastAlgos as $this->LastAlgo) {
                    if ($Pos === 1) {
                        echo ' ';
                    }
                    echo $this->LastAlgo;
                    $Pos += 16;
                    if ($Pos < 76) {
                        echo str_repeat(' ', 16 - strlen($this->LastAlgo));
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
     * Forks the PHP process when scanning in CLI mode. This ensures that if
     * PHP crashes during scanning, phpMussel can continue to scan any
     * remaining items queued for scanning (because if the parent process
     * handles the scan queue and the child process handles the actual scanning
     * of each item queued for scanning, if the child process crashes, the
     * parent process can simply create a new child process to continue
     * iterating through the queue).
     *
     * @param string $Item The name of the item to be scanned w/ its path.
     * @param string $OriginalFilename The name of the item to be scanned w/o its path.
     * @return string The scan results to pipe back to the parent.
     */
    private function fork(string $Item = '', string $OriginalFilename = ''): string
    {
        /** Guard. */
        if (!$this->Loader->Configuration['cli']['allow_process_forking']) {
            return '';
        }

        /** Calculate binary path, or fail if not available. */
        if (!($BinaryPath = defined('PHP_BINARY') ? PHP_BINARY : '')) {
            return '';
        }

        /** Calculate which file to target when forking. */
        $Target = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 2);
        if (is_array($Target) && isset($Target[0], $Target[0]['file'])) {
            $Target = $Target[0]['file'];
        } else {
            return '';
        }

        /** Open the pipe. */
        $Handle = popen($BinaryPath . ' "' . $Target . '" "cli_scan" "' . $Item . '" "' . $OriginalFilename . '"', 'r');

        $Output = '';
        while ($Data = fgets($Handle)) {
            $Output .= $Data;
        }
        pclose($Handle);
        return $Output;
    }

    /**
     * Duplication avoidance (forking the process via recursive CLI mode commands).
     *
     * @param string $Command Command with parameters for the action to be taken.
     * @param callable $Callable Executed normally when not forking the process.
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
            $Terminal = substr($Params, -1);
            $Gap = ($Terminal !== "\\" && $Terminal !== '/') ? DIRECTORY_SEPARATOR : '';
            $List = $this->Scanner->directoryRecursiveList($Params);
            $Returnable = '';
            foreach ($List as $Item) {
                echo "\r" . $Decal[$Frame];
                if ($this->Loader->Configuration['cli']['allow_process_forking']) {
                    $Returnable .= $this->fork($Command . ' ' . $Params . $Gap . $Item, $Item) . "\n";
                } else {
                    $Returnable .= is_file($Params . $Gap . $Item) ? $Callable($Params . $Gap . $Item) : sprintf($this->Loader->L10N->getString('cli_is_not_a'), $Params . $Gap . $Item) . "\n";
                }
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
            $PEArr = ['Len' => strlen($Data)];
            $PEArr['Offset'] = $this->Loader->unpackSafe('S', substr($Data, 60, 4));
            $PEArr['Offset'] = $PEArr['Offset'][1];
            while (true) {
                $PEArr['DoScan'] = true;
                if ($PEArr['Offset'] < 1 || $PEArr['Offset'] > 16384 || $PEArr['Offset'] > $PEArr['Len']) {
                    $PEArr['DoScan'] = false;
                    break;
                }
                $PEArr['Magic'] = substr($Data, $PEArr['Offset'], 2);
                if ($PEArr['Magic'] !== 'PE') {
                    $PEArr['DoScan'] = false;
                    break;
                }
                $PEArr['Proc'] = $this->Loader->unpackSafe('S', substr($Data, $PEArr['Offset'] + 4, 2));
                $PEArr['Proc'] = $PEArr['Proc'][1];
                if ($PEArr['Proc'] != 0x14c && $PEArr['Proc'] != 0x8664) {
                    $PEArr['DoScan'] = false;
                    break;
                }
                $PEArr['NumOfSections'] = $this->Loader->unpackSafe('S', substr($Data, $PEArr['Offset'] + 6, 2));
                $PEArr['NumOfSections'] = $PEArr['NumOfSections'][1];
                if ($PEArr['NumOfSections'] < 1 || $PEArr['NumOfSections'] > 40) {
                    $PEArr['DoScan'] = false;
                }
                break;
            }
            if (!$PEArr['DoScan']) {
                return $this->Loader->L10N->getString('cli_pe1') . "\n";
            }
            $PEArr['OptHdrSize'] = $this->Loader->unpackSafe('S', substr($Data, $PEArr['Offset'] + 20, 2));
            $PEArr['OptHdrSize'] = $PEArr['OptHdrSize'][1];
            $Returnable .= $this->Loader->L10N->getString('cli_pe2') . "\n";
            for ($PEArr['k'] = 0; $PEArr['k'] < $PEArr['NumOfSections']; $PEArr['k']++) {
                $PEArr['SectionHead'] = substr($Data, $PEArr['Offset'] + 24 + $PEArr['OptHdrSize'] + ($PEArr['k'] * 40), $PEArr['NumOfSections'] * 40);
                $PEArr['SectionName'] = str_ireplace("\x00", '', substr($PEArr['SectionHead'], 0, 8));
                $PEArr['VirtualSize'] = $this->Loader->unpackSafe('S', substr($PEArr['SectionHead'], 8, 4));
                $PEArr['VirtualSize'] = $PEArr['VirtualSize'][1];
                $PEArr['VirtualAddress'] = $this->Loader->unpackSafe('S', substr($PEArr['SectionHead'], 12, 4));
                $PEArr['VirtualAddress'] = $PEArr['VirtualAddress'][1];
                $PEArr['SizeOfRawData'] = $this->Loader->unpackSafe('S', substr($PEArr['SectionHead'], 16, 4));
                $PEArr['SizeOfRawData'] = $PEArr['SizeOfRawData'][1];
                $PEArr['PointerToRawData'] = $this->Loader->unpackSafe('S', substr($PEArr['SectionHead'], 20, 4));
                $PEArr['PointerToRawData'] = $PEArr['PointerToRawData'][1];
                $PEArr['SectionData'] = substr($Data, $PEArr['PointerToRawData'], $PEArr['SizeOfRawData']);
                $PEArr['SHA256'] = hash('sha256', $PEArr['SectionData']);
                $Returnable .= $PEArr['SizeOfRawData'] . ':' . $PEArr['SHA256'] . ':' . $PEArr['SectionName'] . "\n";
            }
            $Returnable .= "\n";
            if (strpos($Data, "V\x00a\x00r\x00F\x00i\x00l\x00e\x00I\x00n\x00f\x00o\x00\x00\x00\x00\x00\x24") !== false) {
                $PEArr['Parts'] = $this->Loader->substrAfterLast($Data, "V\x00a\x00r\x00F\x00i\x00l\x00e\x00I\x00n\x00f\x00o\x00\x00\x00\x00\x00\x24");
                $PEArr['FINFO'] = [];
                foreach ([
                    ["F\x00i\x00l\x00e\x00D\x00e\x00s\x00c\x00r\x00i\x00p\x00t\x00i\x00o\x00n\x00\x00\x00", 'PEFileDescription'],
                    ["F\x00i\x00l\x00e\x00V\x00e\x00r\x00s\x00i\x00o\x00n\x00\x00\x00", 'PEFileVersion'],
                    ["P\x00r\x00o\x00d\x00u\x00c\x00t\x00N\x00a\x00m\x00e\x00\x00\x00", 'PEProductName'],
                    ["P\x00r\x00o\x00d\x00u\x00c\x00t\x00V\x00e\x00r\x00s\x00i\x00o\x00n\x00\x00\x00", 'PEProductVersion'],
                    ["L\x00e\x00g\x00a\x00l\x00C\x00o\x00p\x00y\x00r\x00i\x00g\x00h\x00t\x00\x00\x00", 'PECopyright'],
                    ["O\x00r\x00i\x00g\x00i\x00n\x00a\x00l\x00F\x00i\x00l\x00e\x00n\x00a\x00m\x00e\x00\x00\x00", 'PEOriginalFilename'],
                    ["C\x00o\x00m\x00p\x00a\x00n\x00y\x00N\x00a\x00m\x00e\x00\x00\x00", 'PECompanyName'],
                ] as $PEVars) {
                    if (strpos($PEArr['Parts'], $PEVars[0]) !== false && (
                        $PEArr['ThisData'] = trim(str_ireplace("\x00", '', $this->Loader->substrBeforeFirst(
                            $this->Loader->substrAfterLast($PEArr['Parts'], $PEVars[0]),
                            "\x00\x00\x00"
                        )))
                    )) {
                        $Returnable .= sprintf(
                            "\$%s:%s:%d:%s\n",
                            $PEVars[1],
                            hash('sha256', $PEArr['ThisData']),
                            strlen($PEArr['ThisData']),
                            $this->Loader->L10N->getString('cli_signature_placeholder')
                        );
                    }
                }
            }
            return $Returnable;
        });
    }

    /**
     * Initiate a scan.
     *
     * @param string $Clean The file's given path.
     * @param string $ForkWorkingOn The file's original given name.
     * @return string The scan results.
     */
    private function scan(string $Clean, string $ForkWorkingOn): string
    {
        /** Initialise statistics if they've been enabled. */
        $this->Scanner->statsInitialise();

        /** Register scan event. */
        $this->Scanner->statsIncrement('CLI-Events', 1);

        /** Call recursor. */
        $Out = $this->Scanner->Recursor(substr($Clean, 5), true, true, 0, $ForkWorkingOn);

        /** Update statistics. */
        if (!empty($this->Loader->InstanceCache['StatisticsModified'])) {
            $this->Loader->InstanceCache['Statistics'] = $this->Loader->Cache->setEntry(
                'Statistics',
                serialize($this->Loader->InstanceCache['Statistics']),
                0
            );
        }

        /** Exit. */
        return $Out;
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
