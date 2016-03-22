<?php

namespace Pcapng\Blocks;


use Exception;
use Pcapng\PcapngParser;

class InterfaceDescriptionBlock extends Block {
    const TYPE = 'IDB';

    const BYTE_TYPE = '00000001';

    private $linkType;

    /**
     * Parse XX Block.
     * @param string $raw Binary string
     * @param int $currentPosition Current position in file
     * @return array
     * @throws Exception
     */
    public function parse($raw, &$currentPosition) {
        $blockStart = PcapngParser::bin2hexEndian(substr($raw, $currentPosition, 4));
        if ($blockStart !== static::BYTE_TYPE) {
            throw new Exception('Unknown format of Interface Description Block');
        }

        // Block Total Length
        $totalLength = PcapngParser::rawToDecimal(substr($raw, $currentPosition + 4, 4));
        $block['length'] = $totalLength;

        //LinkType
        $linkType = PcapngParser::rawToDecimal(substr($raw, $currentPosition + 8, 2));
        $this->linkType = $linkType;

        $reserved = PcapngParser::bin2hexEndian(substr($raw, $currentPosition + 10, 2));
        if ($reserved !== '0000') {
            trigger_error('Reserved field in Interface Description Block must by 0', E_USER_NOTICE);
        }

        $snapLen = PcapngParser::rawToDecimal(substr($raw, $currentPosition + 12, 4));
        $block['snap_length'] = $snapLen;

        $currentPosition += 16;
        $this->options = $this->parseOptions($raw, $currentPosition);

        $lengthEnd = PcapngParser::rawToDecimal(substr($raw, $currentPosition, 4));
        if ($lengthEnd !== $totalLength) {
            throw new Exception('Unknown format');
        }

        $currentPosition += 4;
    }

    /**
     * Get the basic information about block.
     * @return array
     */
    public function getInfo() {
        return array(
            'type' => static::TYPE,
            'link_type' => $this->linkType,
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