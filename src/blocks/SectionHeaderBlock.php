<?php

namespace Pcapng\Blocks;

use Exception;
use Pcapng\PcapngParser;

class SectionHeaderBlock extends Block {

    const TYPE = 'SHB';

    const BYTE_TYPE = '0a0d0d0a';

    const BYTE_ORDER_MAGIC = '1a2b3c4d';

    private $majorVersion = NULL;
    private $minorVersion = NULL;

    private $endian = NULL;
    private $sectionLength;

    protected $optionsTypeCustom = array(
        2 => array(
            'name' => 'shb_hardware',
            'description' => 'UTF-8 string containing the description of the hardware used to create this section',
        ),
        3 => array(
            'name' => 'shb_os',
            'description' => 'UTF-8 string containing the name of the operating system used to create this section',
        ),
        4 => array(
            'name' => 'shb_userappl',
            'description' => 'UTF-8 string containing the name of the application used to create this section',
        ),
    );

    /**
     * Parse Section Header Block (SHB).
     * @param string $raw Binary string
     * @param int $currentPosition Current position in file
     * @return array
     * @throws Exception
     */
    public function parse($raw, &$currentPosition) {
        // Section Header Block - Block Type
        $blockStart = PcapngParser::bin2hexEndian(substr($raw, $currentPosition, 4));
        if ($blockStart !== static::BYTE_TYPE) {
            throw new Exception('Unknown format of Section Header Block');
        }

        // Section Header Block - Block Total Length
        $shbLength = PcapngParser::rawToDecimal(substr($raw, $currentPosition + 4, 4));

        // Section Header Block - Byte-Order Magic
        $byteOrderMagic = substr($raw, $currentPosition + 8, 4);
        if (bin2hex($byteOrderMagic) === static::BYTE_ORDER_MAGIC) {
            $this->endian = 0;
        } else if (PcapngParser::bin2hexEndian($byteOrderMagic) === static::BYTE_ORDER_MAGIC) {
            $this->endian = 1;
        } else {
            throw new Exception('Unknown format');
        }

        // Section Header Block - Major Version
        $this->majorVersion = PcapngParser::rawToDecimal(substr($raw, $currentPosition + 12, 2));

        // Section Header Block - Minor Version
        $this->minorVersion = PcapngParser::rawToDecimal(substr($raw, $currentPosition + 14, 2));

        // Section Header Block - Section Length
        //https://en.wikipedia.org/wiki/Signed_number_representations
        $sectionLength = substr($raw, $currentPosition + 16, 8);
        $this->sectionLength = bin2hex($sectionLength); //todo make numeric

        // Section Header Block - Options
        $currentPosition += 16 + 8;
        $this->parseOptions($raw, $currentPosition);

        $shbLengthEnd = PcapngParser::rawToDecimal(substr($raw, $currentPosition, 4));
        if ($shbLengthEnd !== $shbLength) {
            throw new Exception('Unknown format');
        }
        $currentPosition += 4; //closing Block Total Length
    }

    /**
     * Get the basic information about block.
     * @return array
     */
    public function getInfo() {
        return array(
            'type' => static::TYPE,
            'major_version' => $this->majorVersion,
            'minor_version' => $this->minorVersion,
            'options' => $this->options
        );
    }

    /**
     * Get extended information about block.
     * @return array
     */
    public function getExtendedInfo() {
        // TODO: Implement getExtendedInfo() method.
    }
}