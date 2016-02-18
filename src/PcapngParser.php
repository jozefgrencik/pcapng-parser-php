<?php

namespace pcapng_parser;

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
    const SHB_BYTE_ORDER_MAGIC2 = '4d3c2b1a';

    /**
     * @param string $raw
     * @return bool
     * @throws \Exception
     */
    public function parse($raw) {
        //echo $raw;

        //check SHB beginning
//        if (strpos($raw, self::SHB_BLOCK_TYPE) !== 0) {
//            throw new \Exception('Invalid file');
//        }


        $begin1 = substr($raw, 0, 4);
        echo bin2hex($begin1);
        echo PHP_EOL;

        $shbLength = substr($raw, 4, 4);
//        echo bin2hex($shbLength);
//        ECHO bindec(trim($shbLength, '0'));
        $shbLength = trim(bin2hex($shbLength), '0');
        echo hexdec($shbLength);
        echo PHP_EOL;

        $magic1 = substr($raw, 8,4);
        echo bin2hex($magic1);
        echo PHP_EOL;

//        echo PHP_EOL;
//        echo dechex(self::SHB_BLOCK_TYPE);
//        echo self::SHB_BYTE_ORDER_MAGIC;

        echo 'done';

        return TRUE;
    }

    /**
     * @param string $filePath
     * @return bool
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

}