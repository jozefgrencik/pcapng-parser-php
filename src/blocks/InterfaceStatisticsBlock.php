<?php

namespace Pcapng\Blocks;
use Exception;
use Pcapng\PcapngParser;

/**
 * Parse Interface Statistics Block.
 *
 * The Interface Statistics Block (ISB) contains the capture statistics for a given interface and it is optional.
 * The statistics are referred to the interface defined in the current Section identified by the Interface ID field.
 * An Interface Statistics Block is normally placed at the end of the file, but no assumptions can be taken
 * about its position - it can even appear multiple times for the same interface.
 *
 * @package Pcapng\Blocks
 */
class InterfaceStatisticsBlock extends Block {
    const TYPE = 'ISB';

    const BYTE_TYPE = '00000005';

    /**
     * Parse Interface Statistics Block.
     * @param string $raw Binary string
     * @param int $currentPosition Current position in file
     * @return array
     * @throws Exception
     */
    public function parse($raw, &$currentPosition) {
        $blockStart = PcapngParser::bin2hexEndian(substr($raw, $currentPosition, 4));
        if ($blockStart !== static::BYTE_TYPE) {
            throw new Exception('Unknown format of Interface Statistics Block');
        }

        // Block Total Length
        $totalLength = PcapngParser::rawToDecimal(substr($raw, $currentPosition + 4, 4));
        $block['length'] = $totalLength;

        $interfaceId = PcapngParser::rawToDecimal(substr($raw, $currentPosition + 8, 4));
        $block['interface_id'] = $interfaceId;

        $timestampHigh = PcapngParser::rawToFloat(substr($raw, $currentPosition + 12, 4)); //todo wrong representation
        $block['timestamp_high'] = $timestampHigh;

        $timestampLow = PcapngParser::rawToFloat(substr($raw, $currentPosition + 16, 4)); //todo wrong representation
        $block['timestamp_low'] = $timestampLow;

        $currentPosition += 20;
        $this->parseOptions($raw, $currentPosition);

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