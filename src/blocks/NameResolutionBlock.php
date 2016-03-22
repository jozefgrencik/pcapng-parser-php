<?php

namespace Pcapng\Blocks;


class NameResolutionBlock extends Block {

    const TYPE = 'NRB';

    /**
     * Parse XX Block.
     * @param string $raw Binary string
     * @param int $currentPosition Current position in file
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