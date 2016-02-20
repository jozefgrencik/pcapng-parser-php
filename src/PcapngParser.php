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

    const VERSION = 0.10;

    const SHB_BLOCK_TYPE = '0a0d0d0a';
    const SHB_BYTE_ORDER_MAGIC = '1a2b3c4d';

    const CUSTOM_BLOCK_TYPE1 = '00000bad';
    const CUSTOM_BLOCK_TYPE2 = '40000bad';

    private $endian = 0;

    /**
     * Parse file content.
     * @param string $raw
     * @return bool
     * @throws Exception
     */
    public function parse($raw) {
        // Section Header Block - Block Type
        $fileStart = bin2hex(substr($raw, 0, 4));
        if ($fileStart !== self::SHB_BLOCK_TYPE) {
            throw new Exception('Unknown format');
        }

        // Section Header Block - Block Total Length
        $shbLength = $this->rawToDecimal(substr($raw, 4, 4));
        echo 'SHB lenght:' . $shbLength . PHP_EOL;

        // Section Header Block - Byte-Order Magic
        $byteOrderMagic = substr($raw, 8, 4);
        if (bin2hex($byteOrderMagic) === self::SHB_BYTE_ORDER_MAGIC) {
            $this->endian = 0;
        } else if ($this->bin2hexEndian($byteOrderMagic) === self::SHB_BYTE_ORDER_MAGIC) {
            $this->endian = 1;
        } else {
            throw new Exception('Unknown format');
        }

        // Section Header Block - Major Version
        $majorVersion = $this->rawToDecimal(substr($raw, 12, 2));
        echo 'Major:' . $majorVersion . PHP_EOL;

        // Section Header Block - Minor Version
        $minorVersion = $this->rawToDecimal(substr($raw, 14, 2));
        echo 'Minor:' . $minorVersion . PHP_EOL;

        // Section Header Block - Section Length
        //https://en.wikipedia.org/wiki/Signed_number_representations
        $sectionLength = substr($raw, 16, 8);
        echo 'Raw section length:' . bin2hex($sectionLength) . PHP_EOL;

        // Section Header Block - Options
        $currentPosition = 24;
        $i = 0;
        while ($optionCode = substr($raw, $currentPosition, 2) !== chr(0) . chr(0)) {
            ++$i;

            //Option Code
            echo 'Option code[' . $i . ']:' . $this->rawToDecimal($optionCode) . PHP_EOL;

            //Option Length
            $optionLength = $this->rawToDecimal(substr($raw, $currentPosition + 2, 2));
            echo 'Option length[' . $i . ']:' . $optionLength . PHP_EOL;

            $optionLengthWithPadding = ceil($optionLength / 4) * 4;

            //Option Value
            $optionValue = substr($raw, $currentPosition + 4, $optionLength);
            echo 'Option value[' . $i . ']:' . ($optionValue) . PHP_EOL;

            $currentPosition += 4 + $optionLengthWithPadding;
        }


//        $packet = new Packet();
        echo 'done';

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

//        if (empty($raw)) {
//            throw new InvalidArgumentException('File doesn\'t exist or isn\'t readable');
//        }

        return $this->parse($raw);
    }

    /**
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
     * @param string $raw
     * @return number
     */
    private function rawToDecimal($raw) {
        $raw = $this->bin2hexEndian($raw);

        return hexdec($raw);
    }

}