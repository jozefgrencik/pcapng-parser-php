<?php

namespace Pcapng\Blocks;


class CustomBlock extends Block {
    const TYPE = 'CB';


    const BYTE_TYPE1 = '00000bad';
    const BYTE_TYPE2 = '40000bad';

    /**
     * Parse Section Header Block.
     * @param string $raw Binary string
     * @param int $currentPosition
     * @return array
     */
    public function parse($raw, &$currentPosition) {
        // TODO: Implement parse() method.
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