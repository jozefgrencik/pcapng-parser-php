<?php

namespace Pcapng\Blocks;


use Exception;
use Pcapng\PcapngParser;

abstract class Block {

    protected $optionType = array(
        0 => array(
            'name' => 'opt_endofopt',
            'description' => 'Delimits the end of the optional fields',
        ),
        1 => array(
            'name' => 'opt_comment',
            'description' => 'UTF-8 string containing human-readable comment text that is associated to the current block',
        ),
        2988 => array(
            'name' => 'opt_custom',
            'description' => '', //todo
        ),
        2989 => array(
            'name' => 'opt_custom',
            'description' => '', //todo
        ),
        19372 => array(
            'name' => 'opt_custom',
            'description' => '', //todo
        ),
        19373 => array(
            'name' => 'opt_custom',
            'description' => '', //todo
        )
    );

    //for extended classes
    protected $optionsTypeCustom = array();

    public $options = array();

    /**
     * Parse Options.
     * @param string $raw Binary string
     * @param int $currentPosition
     * @return array
     * @throws Exception
     */
    protected function parseOptions($raw, &$currentPosition) {
        //Option Code
        while ($optionCode = substr($raw, $currentPosition, 2) !== chr(0) . chr(0)) {

            $optionCode = PcapngParser::rawToDecimal($optionCode);

            //Option Length
            $optionLength = PcapngParser::rawToDecimal(substr($raw, $currentPosition + 2, 2));

            if (array_key_exists($optionCode, $this->optionType)) {
                //PEN = Private Enterprise Number
                if ($this->optionType[$optionCode]['name'] === 'opt_custom') {
                    $penRaw = substr($raw, $currentPosition + 4, 4); //todo ??
                    $currentPosition += 4;
                }
            } else if (array_key_exists($optionCode, $this->optionsTypeCustom)) {

            } else {
                throw new Exception('Unknow type of option');
            }

            //Option Value
            $this->options[] = array(
                'code' => $optionCode,
                'value' => substr($raw, $currentPosition + 4, $optionLength)
            );

            $currentPosition += 4 + ceil($optionLength / 4) * 4; //4 = Option code + Option length
        }

        $currentPosition += 4; //closing Option code + closing Option length
        return $this->options;
    }

    /**
     * Parse XX Block.
     * @param string $raw Binary string
     * @param int $currentPosition Current position in file
     * @return array
     */
    abstract public function parse($raw, &$currentPosition);

    /**
     * Get the basic information about block.
     * @return array
     */
    abstract public function getInfo();

    /**
     * Get extended information about block.
     * @return array
     */
    abstract public function getExtendedInfo();

}