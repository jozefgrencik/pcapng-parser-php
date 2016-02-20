<?php

namespace pcapng_parser;

use Exception;
use InvalidArgumentException;

/**
 * Class PcapngParser
 * @package pcapng_parser
 * @link https://github.com/pcapng/pcapng
 */
class PcapngParser {
    //Pcapng library internals
    const VERSION = 0.10;

    // Section Header Block
    const SHB_TYPE = '0a0d0d0a';
    const SHB_BYTE_ORDER_MAGIC = '1a2b3c4d';

    // Interface Description Block
    const IDB_TYPE = '00000001';

    // Custom Block
    const CB_TYPE1 = '00000bad';
    const CB_TYPE2 = '40000bad';

    private $endian = 0;

    /**
     * Parse file content.
     * @param string $raw
     * @return bool
     * @throws Exception
     */
    public function parse($raw) {
        $currentPosition = 0;
        $blockType = bin2hex(substr($raw, $currentPosition, 4));

        switch ($blockType) {
            case self::SHB_TYPE:
                $this->parseSectionHeaderBlock($raw, $currentPosition);
                break;
            case self::CB_TYPE1:
            case self::CB_TYPE2:
                //todo
                break;
            case self::IDB_TYPE:

                break;
            default:
                trigger_error('Unknown type of block', E_USER_NOTICE);
        }


//        $hex = $this->bin2hexEndian(substr($raw, $currentPosition, 45));
//        $array = explode(',', chunk_split($hex, 2, ','));
//        krsort($array);
//        foreach ($array as $index => $item) {
//            echo $item . ' ' . chr(hexdec($item)) . PHP_EOL;
//        }

//        $packet = new Packet();
        echo PHP_EOL . 'done';

        return TRUE;
    }

    /**
     * Parse file.
     * @param string $filePath
     * @return bool
     * @throws InvalidArgumentException
     */
    public function parseFile($filePath) {
        if (!file_exists($filePath)) {
            throw new InvalidArgumentException('File doesn\'t exist');
        }
        if (!is_readable($filePath)) {
            throw new InvalidArgumentException('File is unreadable. Check permissions of file.');
        }

        $raw = file_get_contents($filePath); //todo for big files
//        http://php.net/manual/en/function.fread.php
//        $handle = fopen($filePath, 'rb');

        if (empty($raw)) {
            throw new InvalidArgumentException('File doesn\'t exist or isn\'t readable');
        }

        return $this->parse($raw);
    }

    private function parseSectionHeaderBlock($raw, &$currentPosition) {
        // Section Header Block - Block Type
        $fileStart = bin2hex(substr($raw, $currentPosition, 4));
        if ($fileStart !== self::SHB_TYPE) {
            throw new Exception('Unknown format');
        }

        // Section Header Block - Block Total Length
        $shbLength = $this->rawToDecimal(substr($raw, $currentPosition + 4, 4));
        echo 'SHB lenght:' . $shbLength . PHP_EOL;

        // Section Header Block - Byte-Order Magic
        $byteOrderMagic = substr($raw, $currentPosition + 8, 4);
        if (bin2hex($byteOrderMagic) === self::SHB_BYTE_ORDER_MAGIC) {
            $this->endian = 0;
        } else if ($this->bin2hexEndian($byteOrderMagic) === self::SHB_BYTE_ORDER_MAGIC) {
            $this->endian = 1;
        } else {
            throw new Exception('Unknown format');
        }

        // Section Header Block - Major Version
        $majorVersion = $this->rawToDecimal(substr($raw, $currentPosition + 12, 2));
        echo 'Major:' . $majorVersion . PHP_EOL;

        // Section Header Block - Minor Version
        $minorVersion = $this->rawToDecimal(substr($raw, $currentPosition + 14, 2));
        echo 'Minor:' . $minorVersion . PHP_EOL;

        // Section Header Block - Section Length
        //https://en.wikipedia.org/wiki/Signed_number_representations
        $sectionLength = substr($raw, $currentPosition + 16, 8);
        echo 'Raw section length:' . bin2hex($sectionLength) . PHP_EOL;

        // Section Header Block - Options
        $currentPosition += 16 + 8;
        $this->parseOptions($raw, $currentPosition);

        $shbLengthEnd = $this->rawToDecimal(substr($raw, $currentPosition, 4));
        if ($shbLengthEnd !== $shbLength) {
            throw new Exception('Unknown format');
        }
        $currentPosition += 4; //closing Block Total Length
    }


    /**
     * Parse Options.
     * @param string $raw Binary string
     * @param int $currentPosition
     */
    private function parseOptions($raw, &$currentPosition) {
        $i = 0;
        while ($optionCode = substr($raw, $currentPosition, 2) !== chr(0) . chr(0)) {
            ++$i;

            //Option Code
            echo 'Option code[' . $i . ']:' . $this->rawToDecimal($optionCode) . PHP_EOL;

            //Option Length
            $optionLength = $this->rawToDecimal(substr($raw, $currentPosition + 2, 2));
            echo 'Option length[' . $i . ']:' . $optionLength . PHP_EOL;

            //Option Value
            $optionValue = substr($raw, $currentPosition + 4, $optionLength);
            echo 'Option value[' . $i . ']:' . ($optionValue) . PHP_EOL;

            $optionLengthWithPadding = ceil($optionLength / 4) * 4;
            $currentPosition += 4 + $optionLengthWithPadding;
        }

        $currentPosition += 4; //closing Option code + Option length
    }

    /**
     * Convert binary string to hexadecimal.
     * @param string $raw Binary string
     * @return string HEX string
     */
    private function bin2hexEndian($raw) {
        if (strlen($raw) < 2) {
            return $raw;
        }
        $rawArray = unpack('H*', strrev($raw));

        return $rawArray[1];
    }

    /**
     * Convert binary string to decimal.
     * @param string $raw
     * @return number
     */
    private function rawToDecimal($raw) {
        $raw = $this->bin2hexEndian($raw);

        return hexdec($raw);
    }

}