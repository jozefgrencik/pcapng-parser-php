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

    // Enhanced Packet Block
    const EPB_TYPE = '00000006';

    // Custom Block
    const CB_TYPE1 = '00000bad';
    const CB_TYPE2 = '40000bad';

    static private $linkLayerTypes = array(
        0 => array(
            'link_type_name' => 'LINKTYPE_NULL',
            'data_link_name' => 'DLT_NULL',
            'description' => 'BSD loopback encapsulation; the link layer header is a 4-byte field, in host byte order, containing a PF_ value from socket.h for the network-layer protocol of the packet. Note that "host byte order" is the byte order of the machine on which the packets are captured, and the PF_ values are for the OS of the machine on which the packets are captured; if a live capture is being done, "host byte order" is the byte order of the machine capturing the packets, and the PF_ values are those of the OS of the machine capturing the packets, but if a "savefile" is being read, the byte order and PF_ values are not necessarily those of the machine reading the capture file.'),
        1 => array(
            'link_type_name' => 'LINKTYPE_ETHERNET',
            'data_link_name' => 'DLT_EN10MB',
            'description' => 'IEEE 802.3 Ethernet (10Mb, 100Mb, 1000Mb, and up); the 10MB in the DLT_ name is historical.'),
        3 => array(
            'link_type_name' => 'LINKTYPE_AX25',
            'data_link_name' => 'DLT_AX25',
            'description' => 'AX.25 packet, with nothing preceding it.'),
        6 => array(
            'link_type_name' => 'LINKTYPE_IEEE802_5',
            'data_link_name' => 'DLT_IEEE802',
            'description' => 'IEEE 802.5 Token Ring; the IEEE802, without _5, in the DLT_ name is historical.'),
        7 => array(
            'link_type_name' => 'LINKTYPE_ARCNET_BSD',
            'data_link_name' => 'DLT_ARCNET',
            'description' => 'ARCNET Data Packets, as described by the ARCNET Trade Association standard ATA 878.1-1999, but without the Starting Delimiter, Information Length, or Frame Check Sequence fields, and with only the first ISU of the Destination Identifier. For most packet types, ARCNET Trade Association draft standard ATA 878.2 is also used. See also RFC 1051 and RFC 1201; for RFC 1051 frames, ATA 878.2 is not used.'),
        8 => array(
            'link_type_name' => 'LINKTYPE_SLIP',
            'data_link_name' => 'DLT_SLIP',
            'description' => 'SLIP, encapsulated with a LINKTYPE_SLIP header.'),
        9 => array(
            'link_type_name' => 'LINKTYPE_PPP',
            'data_link_name' => 'DLT_PPP',
            'description' => 'PPP, as per RFC 1661 and RFC 1662; if the first 2 bytes are 0xff and 0x03, it\'s PPP in HDLC-like framing, with the PPP header following those two bytes, otherwise it\'s PPP without framing, and the packet begins with the PPP header. The data in the frame is not octet-stuffed or bit-stuffed.'),
        10 => array(
            'link_type_name' => 'LINKTYPE_FDDI',
            'data_link_name' => 'DLT_FDDI',
            'description' => 'FDDI, as specified by ANSI INCITS 239-1994.'),
        50 => array(
            'link_type_name' => 'LINKTYPE_PPP_HDLC',
            'data_link_name' => 'DLT_PPP_SERIAL',
            'description' => 'PPP in HDLC-like framing, as per RFC 1662, or Cisco PPP with HDLC framing, as per section 4.3.1 of RFC 1547; the first byte will be 0xFF for PPP in HDLC-like framing, and will be 0x0F or 0x8F for Cisco PPP with HDLC framing. The data in the frame is not octet-stuffed or bit-stuffed.'),
        51 => array(
            'link_type_name' => 'LINKTYPE_PPP_ETHER',
            'data_link_name' => 'DLT_PPP_ETHER',
            'description' => 'PPPoE; the packet begins with a PPPoE header, as per RFC 2516.'),
        100 => array(
            'link_type_name' => 'LINKTYPE_ATM_RFC1483',
            'data_link_name' => 'DLT_ATM_RFC1483',
            'description' => 'RFC 1483 LLC/SNAP-encapsulated ATM; the packet begins with an IEEE 802.2 LLC header.'),
        101 => array(
            'link_type_name' => 'LINKTYPE_RAW',
            'data_link_name' => 'DLT_RAW',
            'description' => 'Raw IP; the packet begins with an IPv4 or IPv6 header, with the "version" field of the header indicating whether it\'s an IPv4 or IPv6 header.'),
        104 => array(
            'link_type_name' => 'LINKTYPE_C_HDLC',
            'data_link_name' => 'DLT_C_HDLC',
            'description' => 'Cisco PPP with HDLC framing, as per section 4.3.1 of RFC 1547.'),
        105 => array(
            'link_type_name' => 'LINKTYPE_IEEE802_11',
            'data_link_name' => 'DLT_IEEE802_11',
            'description' => 'IEEE 802.11 wireless LAN.'),
        107 => array(
            'link_type_name' => 'LINKTYPE_FRELAY',
            'data_link_name' => 'DLT_FRELAY',
            'description' => 'Frame Relay'),
        108 => array(
            'link_type_name' => 'LINKTYPE_LOOP',
            'data_link_name' => 'DLT_LOOP',
            'description' => 'OpenBSD loopback encapsulation; the link-layer header is a 4-byte field, in network byte order, containing a PF_ value from OpenBSD\'s socket.h for the network-layer protocol of the packet. Note that, if a "savefile" is being read, those PF_ values are not necessarily those of the machine reading the capture file.'),
        113 => array(
            'link_type_name' => 'LINKTYPE_LINUX_SLL',
            'data_link_name' => 'DLT_LINUX_SLL',
            'description' => 'Linux "cooked" capture encapsulation.'),
        114 => array(
            'link_type_name' => 'LINKTYPE_LTALK',
            'data_link_name' => 'DLT_LTALK',
            'description' => 'Apple LocalTalk; the packet begins with an AppleTalk LocalTalk Link Access Protocol header, as described in chapter 1 of Inside AppleTalk, Second Edition.'),
        117 => array(
            'link_type_name' => 'LINKTYPE_PFLOG',
            'data_link_name' => 'DLT_PFLOG',
            'description' => 'OpenBSD pflog; the link-layer header contains a "struct pfloghdr" structure, as defined by the host on which the file was saved. (This differs from operating system to operating system and release to release; there is nothing in the file to indicate what the layout of that structure is.)'),
        119 => array(
            'link_type_name' => 'LINKTYPE_IEEE802_11_PRISM',
            'data_link_name' => 'DLT_PRISM_HEADER',
            'description' => 'Prism monitor mode information followed by an 802.11 header.'),
        122 => array(
            'link_type_name' => 'LINKTYPE_IP_OVER_FC',
            'data_link_name' => 'DLT_IP_OVER_FC',
            'description' => 'RFC 2625 IP-over-Fibre Channel, with the link-layer header being the Network_Header as described in that RFC.'),
        123 => array(
            'link_type_name' => 'LINKTYPE_SUNATM',
            'data_link_name' => 'DLT_SUNATM',
            'description' => 'ATM traffic, encapsulated as per the scheme used by SunATM devices.'),
        127 => array(
            'link_type_name' => 'LINKTYPE_IEEE802_11_RADIOTAP',
            'data_link_name' => 'DLT_IEEE802_11_RADIO',
            'description' => 'Radiotap link-layer information followed by an 802.11 header.'),
        129 => array(
            'link_type_name' => 'LINKTYPE_ARCNET_LINUX',
            'data_link_name' => 'DLT_ARCNET_LINUX',
            'description' => 'ARCNET Data Packets, as described by the ARCNET Trade Association standard ATA 878.1-1999, but without the Starting Delimiter, Information Length, or Frame Check Sequence fields, with only the first ISU of the Destination Identifier, and with an extra two-ISU "offset" field following the Destination Identifier. For most packet types, ARCNET Trade Association draft standard ATA 878.2 is also used; however, no exception frames are supplied, and reassembled frames, rather than fragments, are supplied. See also RFC 1051 and RFC 1201; for RFC 1051 frames, ATA 878.2 is not used.'),
        138 => array(
            'link_type_name' => 'LINKTYPE_APPLE_IP_OVER_IEEE1394',
            'data_link_name' => 'DLT_APPLE_IP_OVER_IEEE1394',
            'description' => 'Apple IP-over-IEEE 1394 cooked header.'),
        139 => array(
            'link_type_name' => 'LINKTYPE_MTP2_WITH_PHDR',
            'data_link_name' => 'DLT_MTP2_WITH_PHDR',
            'description' => 'Signaling System 7 Message Transfer Part Level 2, as specified by ITU-T Recommendation Q.703, preceded by a pseudo-header.'),
        140 => array(
            'link_type_name' => 'LINKTYPE_MTP2',
            'data_link_name' => 'DLT_MTP2',
            'description' => 'Signaling System 7 Message Transfer Part Level 2, as specified by ITU-T Recommendation Q.703.'),
        141 => array(
            'link_type_name' => 'LINKTYPE_MTP3',
            'data_link_name' => 'DLT_MTP3',
            'description' => 'Signaling System 7 Message Transfer Part Level 3, as specified by ITU-T Recommendation Q.704, with no MTP2 header preceding the MTP3 packet.'),
        142 => array(
            'link_type_name' => 'LINKTYPE_SCCP',
            'data_link_name' => 'DLT_SCCP',
            'description' => 'Signaling System 7 Signalling Connection Control Part, as specified by ITU-T Recommendation Q.711, ITU-T Recommendation Q.712, ITU-T Recommendation Q.713, and ITU-T Recommendation Q.714, with no MTP3 or MTP2 headers preceding the SCCP packet.'),
        143 => array(
            'link_type_name' => 'LINKTYPE_DOCSIS',
            'data_link_name' => 'DLT_DOCSIS',
            'description' => 'DOCSIS MAC frames, as described by the DOCSIS 3.0 MAC and Upper Layer Protocols Interface Specification.'),
        144 => array(
            'link_type_name' => 'LINKTYPE_LINUX_IRDA',
            'data_link_name' => 'DLT_LINUX_IRDA',
            'description' => 'Linux-IrDA packets, with a LINKTYPE_LINUX_IRDA header, with the payload for IrDA frames beginning with by the IrLAP header as defined by IrDA Data Specifications, including the IrDA Link Access Protocol specification.'),
        147 => array(
            'link_type_name' => 'LINKTYPE_USER0',
            'data_link_name' => 'DLT_USER0',
            'description' => 'Reserved for private use'),
        148 => array(
            'link_type_name' => 'LINKTYPE_USER1',
            'data_link_name' => 'DLT_USER1',
            'description' => 'Reserved for private use'),
        149 => array(
            'link_type_name' => 'LINKTYPE_USER2',
            'data_link_name' => 'DLT_USER2',
            'description' => 'Reserved for private use'),
        150 => array(
            'link_type_name' => 'LINKTYPE_USER3',
            'data_link_name' => 'DLT_USER3',
            'description' => 'Reserved for private use'),
        151 => array(
            'link_type_name' => 'LINKTYPE_USER4',
            'data_link_name' => 'DLT_USER4',
            'description' => 'Reserved for private use'),
        152 => array(
            'link_type_name' => 'LINKTYPE_USER5',
            'data_link_name' => 'DLT_USER5',
            'description' => 'Reserved for private use'),
        153 => array(
            'link_type_name' => 'LINKTYPE_USER6',
            'data_link_name' => 'DLT_USER6',
            'description' => 'Reserved for private use'),
        154 => array(
            'link_type_name' => 'LINKTYPE_USER7',
            'data_link_name' => 'DLT_USER7',
            'description' => 'Reserved for private use'),
        155 => array(
            'link_type_name' => 'LINKTYPE_USER8',
            'data_link_name' => 'DLT_USER8',
            'description' => 'Reserved for private use'),
        156 => array(
            'link_type_name' => 'LINKTYPE_USER9',
            'data_link_name' => 'DLT_USER9',
            'description' => 'Reserved for private use'),
        157 => array(
            'link_type_name' => 'LINKTYPE_USER10',
            'data_link_name' => 'DLT_USER10',
            'description' => 'Reserved for private use'),
        158 => array(
            'link_type_name' => 'LINKTYPE_USER11',
            'data_link_name' => 'DLT_USER11',
            'description' => 'Reserved for private use'),
        159 => array(
            'link_type_name' => 'LINKTYPE_USER12',
            'data_link_name' => 'DLT_USER12',
            'description' => 'Reserved for private use'),
        160 => array(
            'link_type_name' => 'LINKTYPE_USER13',
            'data_link_name' => 'DLT_USER13',
            'description' => 'Reserved for private use'),
        161 => array(
            'link_type_name' => 'LINKTYPE_USER14',
            'data_link_name' => 'DLT_USER14',
            'description' => 'Reserved for private use'),
        162 => array(
            'link_type_name' => 'LINKTYPE_USER15',
            'data_link_name' => 'DLT_USER15',
            'description' => 'Reserved for private use'),
        163 => array(
            'link_type_name' => 'LINKTYPE_IEEE802_11_AVS',
            'data_link_name' => 'DLT_IEEE802_11_RADIO_AVS',
            'description' => 'AVS monitor mode information followed by an 802.11 header.'),
        165 => array(
            'link_type_name' => 'LINKTYPE_BACNET_MS_TP',
            'data_link_name' => 'DLT_BACNET_MS_TP',
            'description' => 'BACnet MS/TP frames, as specified by section 9.3 MS/TP Frame Format of ANSI/ASHRAE Standard 135, BACnet® - A Data Communication Protocol for Building Automation and Control Networks, including the preamble and, if present, the Data CRC.'),
        166 => array(
            'link_type_name' => 'LINKTYPE_PPP_PPPD',
            'data_link_name' => 'DLT_PPP_PPPD',
            'description' => 'PPP in HDLC-like encapsulation, like LINKTYPE_PPP_HDLC, but with the 0xff address byte replaced by a direction indication - 0x00 for incoming and 0x01 for outgoing.'),
        169 => array(
            'link_type_name' => 'LINKTYPE_GPRS_LLC',
            'data_link_name' => 'DLT_GPRS_LLC',
            'description' => 'General Packet Radio Service Logical Link Control, as defined by 3GPP TS 04.64.'),
        170 => array(
            'link_type_name' => 'LINKTYPE_GPF_T',
            'data_link_name' => 'DLT_GPF_T',
            'description' => 'Transparent-mapped generic framing procedure, as specified by ITU-T Recommendation G.7041/Y.1303.'),
        171 => array(
            'link_type_name' => 'LINKTYPE_GPF_F',
            'data_link_name' => 'DLT_GPF_F',
            'description' => 'Frame-mapped generic framing procedure, as specified by ITU-T Recommendation G.7041/Y.1303.'),
        177 => array(
            'link_type_name' => 'LINKTYPE_LINUX_LAPD',
            'data_link_name' => 'DLT_LINUX_LAPD',
            'description' => 'Link Access Procedures on the D Channel (LAPD) frames, as specified by ITU-T Recommendation Q.920 and ITU-T Recommendation Q.921, captured via vISDN, with a LINKTYPE_LINUX_LAPD header, followed by the Q.921 frame, starting with the address field.'),
        187 => array(
            'link_type_name' => 'LINKTYPE_BLUETOOTH_HCI_H4',
            'data_link_name' => 'DLT_BLUETOOTH_HCI_H4',
            'description' => 'Bluetooth HCI UART transport layer; the frame contains an HCI packet indicator byte, as specified by the UART Transport Layer portion of the most recent Bluetooth Core specification, followed by an HCI packet of the specified packet type, as specified by the Host Controller Interface Functional Specification portion of the most recent Bluetooth Core Specification.'),
        189 => array(
            'link_type_name' => 'LINKTYPE_USB_LINUX',
            'data_link_name' => 'DLT_USB_LINUX',
            'description' => 'USB packets, beginning with a Linux USB header, as specified by the struct usbmon_packet in the Documentation/usb/usbmon.txt file in the Linux source tree. Only the first 48 bytes of that header are present. All fields in the header are in the host byte order for the pcap file, as specified by the file\'s magic number, or for the section of the pcap-ng file, as specified by the Section Header Block.'),
        192 => array(
            'link_type_name' => 'LINKTYPE_PPI',
            'data_link_name' => 'DLT_PPI',
            'description' => 'Per-Packet Information information, as specified by the Per-Packet Information Header Specification, followed by a packet with the LINKTYPE_ value specified by the pph_dlt field of that header.'),
        195 => array(
            'link_type_name' => 'LINKTYPE_IEEE802_15_4',
            'data_link_name' => 'DLT_IEEE802_15_4',
            'description' => 'IEEE 802.15.4 wireless Personal Area Network, with each packet having the FCS at the end of the frame.'),
        196 => array(
            'link_type_name' => 'LINKTYPE_SITA',
            'data_link_name' => 'DLT_SITA',
            'description' => 'Various link-layer types, with a pseudo-header, for SITA.'),
        197 => array(
            'link_type_name' => 'LINKTYPE_ERF',
            'data_link_name' => 'DLT_ERF',
            'description' => 'Various link-layer types, with a pseudo-header, for Endace DAG cards; encapsulates Endace ERF records.'),
        201 => array(
            'link_type_name' => 'LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR',
            'data_link_name' => 'DLT_BLUETOOTH_HCI_H4_WITH_PHDR',
            'description' => 'Bluetooth HCI UART transport layer; the frame contains a 4-byte direction field, in network byte order (big-endian), the low-order bit of which is set if the frame was sent from the host to the controller and clear if the frame was received by the host from the controller, followed by an HCI packet indicator byte, as specified by the UART Transport Layer portion of the most recent Bluetooth Core specification, followed by an HCI packet of the specified packet type, as specified by the Host Controller Interface Functional Specification portion of the most recent Bluetooth Core Specification.'),
        202 => array(
            'link_type_name' => 'LINKTYPE_AX25_KISS',
            'data_link_name' => 'DLT_AX25_KISS',
            'description' => 'AX.25 packet, with a 1-byte KISS header containing a type indicator.'),
        203 => array(
            'link_type_name' => 'LINKTYPE_LAPD',
            'data_link_name' => 'DLT_LAPD',
            'description' => 'Link Access Procedures on the D Channel (LAPD) frames, as specified by ITU-T Recommendation Q.920 and ITU-T Recommendation Q.921, starting with the address field, with no pseudo-header.'),
        204 => array(
            'link_type_name' => 'LINKTYPE_PPP_WITH_DIR',
            'data_link_name' => 'DLT_PPP_WITH_DIR',
            'description' => 'PPP, as per RFC 1661 and RFC 1662, preceded with a one-byte pseudo-header with a zero value meaning "received by this host" and a non-zero value meaning "sent by this host"; if the first 2 bytes are 0xff and 0x03, it\'s PPP in HDLC-like framing, with the PPP header following those two bytes, otherwise it\'s PPP without framing, and the packet begins with the PPP header. The data in the frame is not octet-stuffed or bit-stuffed.'),
        205 => array(
            'link_type_name' => 'LINKTYPE_C_HDLC_WITH_DIR',
            'data_link_name' => 'DLT_C_HDLC_WITH_DIR',
            'description' => 'Cisco PPP with HDLC framing, as per section 4.3.1 of RFC 1547, preceded with a one-byte pseudo-header with a zero value meaning "received by this host" and a non-zero value meaning "sent by this host".'),
        206 => array(
            'link_type_name' => 'LINKTYPE_FRELAY_WITH_DIR',
            'data_link_name' => 'DLT_FRELAY_WITH_DIR',
            'description' => 'Frame Relay, preceded with a one-byte pseudo-header with a zero value meaning "received by this host" and a non-zero value meaning "sent by this host".'),
        209 => array(
            'link_type_name' => 'LINKTYPE_IPMB_LINUX',
            'data_link_name' => 'DLT_IPMB_LINUX',
            'description' => 'IPMB over an I2C circuit, with a Linux-specific pseudo-header.'),
        215 => array(
            'link_type_name' => 'LINKTYPE_IEEE802_15_4_NONASK_PHY',
            'data_link_name' => 'DLT_IEEE802_15_4_NONASK_PHY',
            'description' => 'IEEE 802.15.4 wireless Personal Area Network, with each packet having the FCS at the end of the frame, and with the PHY-level data for non-ASK PHYs (4 octets of 0 as preamble, one octet of SFD, one octet of frame length + reserved bit) preceding the MAC-layer data (starting with the frame control field).'),
        220 => array(
            'link_type_name' => 'LINKTYPE_USB_LINUX_MMAPPED',
            'data_link_name' => 'DLT_USB_LINUX_MMAPPED',
            'description' => 'USB packets, beginning with a Linux USB header, as specified by the struct usbmon_packet in the Documentation/usb/usbmon.txt file in the Linux source tree. All 64 bytes of the header are present. All fields in the header are in the host byte order for the pcap file, as specified by the file\'s magic number, or for the section of the pcap-ng file, as specified by the Section Header Block. For isochronous transfers, the ndesc field specifies the number of isochronous descriptors that follow.'),
        224 => array(
            'link_type_name' => 'LINKTYPE_FC_2',
            'data_link_name' => 'DLT_FC_2',
            'description' => 'Fibre Channel FC-2 frames, beginning with a Frame_Header.'),
        225 => array(
            'link_type_name' => 'LINKTYPE_FC_2_WITH_FRAME_DELIMS',
            'data_link_name' => 'DLT_FC_2_WITH_FRAME_DELIMS',
            'description' => 'Fibre Channel FC-2 frames, beginning an encoding of the SOF, followed by a Frame_Header, and ending with an encoding of the SOF. The encodings represent the frame delimiters as 4-byte sequences representing the corresponding ordered sets, with K28.5 represented as 0xBC, and the D symbols as the corresponding byte values; for example, SOFi2, which is K28.5 - D21.5 - D1.2 - D21.2, is represented as 0xBC 0xB5 0x55 0x55.'),
        226 => array(
            'link_type_name' => 'LINKTYPE_IPNET',
            'data_link_name' => 'DLT_IPNET',
            'description' => 'Solaris ipnet pseudo-header, followed by an IPv4 or IPv6 datagram.'),
        227 => array(
            'link_type_name' => 'LINKTYPE_CAN_SOCKETCAN',
            'data_link_name' => 'DLT_CAN_SOCKETCAN',
            'description' => 'CAN (Controller Area Network) frames, with a pseudo-header as supplied by Linux SocketCAN.'),
        228 => array(
            'link_type_name' => 'LINKTYPE_IPV4',
            'data_link_name' => 'DLT_IPV4',
            'description' => 'Raw IPv4; the packet begins with an IPv4 header.'),
        229 => array(
            'link_type_name' => 'LINKTYPE_IPV6',
            'data_link_name' => 'DLT_IPV6',
            'description' => 'Raw IPv6; the packet begins with an IPv6 header.'),
        230 => array(
            'link_type_name' => 'LINKTYPE_IEEE802_15_4_NOFCS',
            'data_link_name' => 'DLT_IEEE802_15_4_NOFCS',
            'description' => 'IEEE 802.15.4 wireless Personal Area Network, without the FCS at the end of the frame.'),
        231 => array(
            'link_type_name' => 'LINKTYPE_DBUS',
            'data_link_name' => 'DLT_DBUS',
            'description' => 'Raw D-Bus messages, starting with the endianness flag, followed by the message type, etc., but without the authentication handshake before the message sequence.'),
        235 => array(
            'link_type_name' => 'LINKTYPE_DVB_CI',
            'data_link_name' => 'DLT_DVB_CI',
            'description' => 'DVB-CI (DVB Common Interface for communication between a PC Card module and a DVB receiver), with the message format specified by the PCAP format for DVB-CI specification.'),
        236 => array(
            'link_type_name' => 'LINKTYPE_MUX27010',
            'data_link_name' => 'DLT_MUX27010',
            'description' => 'Variant of 3GPP TS 27.010 multiplexing protocol (similar to, but not the same as, 27.010).'),
        237 => array(
            'link_type_name' => 'LINKTYPE_STANAG_5066_D_PDU',
            'data_link_name' => 'DLT_STANAG_5066_D_PDU',
            'description' => 'D_PDUs as described by NATO standard STANAG 5066, starting with the synchronization sequence, and including both header and data CRCs. The current version of STANAG 5066 is backwards-compatible with the 1.0.2 version, although newer versions are classified.'),
        239 => array(
            'link_type_name' => 'LINKTYPE_NFLOG',
            'data_link_name' => 'DLT_NFLOG',
            'description' => 'Linux netlink NETLINK NFLOG socket log messages.'),
        240 => array(
            'link_type_name' => 'LINKTYPE_NETANALYZER',
            'data_link_name' => 'DLT_NETANALYZER',
            'description' => 'Pseudo-header for Hilscher Gesellschaft für Systemautomation mbH netANALYZER devices, followed by an Ethernet frame, beginning with the MAC header and ending with the FCS.'),
        241 => array(
            'link_type_name' => 'LINKTYPE_NETANALYZER_TRANSPARENT',
            'data_link_name' => 'DLT_NETANALYZER_TRANSPARENT',
            'description' => 'Pseudo-header for Hilscher Gesellschaft für Systemautomation mbH netANALYZER devices, followed by an Ethernet frame, beginning with the preamble, SFD, and MAC header, and ending with the FCS.'),
        242 => array(
            'link_type_name' => 'LINKTYPE_IPOIB',
            'data_link_name' => 'DLT_IPOIB',
            'description' => 'IP-over-InfiniBand, as specified by RFC 4391 section 6.'),
        243 => array(
            'link_type_name' => 'LINKTYPE_MPEG_2_TS',
            'data_link_name' => 'DLT_MPEG_2_TS',
            'description' => 'MPEG-2 Transport Stream transport packets, as specified by ISO 13818-1/ITU-T Recommendation H.222.0 (see table 2-2 of section 2.4.3.2 "Transport Stream packet layer").'),
        244 => array(
            'link_type_name' => 'LINKTYPE_NG40',
            'data_link_name' => 'DLT_NG40',
            'description' => 'Pseudo-header for ng4T GmbH\'s UMTS Iub/Iur-over-ATM and Iub/Iur-over-IP format as used by their ng40 protocol tester, followed by frames for the Frame Protocol as specified by 3GPP TS 25.427 for dedicated channels and 3GPP TS 25.435 for common/shared channels in the case of ATM AAL2 or UDP traffic, by SSCOP packets as specified by ITU-T Recommendation Q.2110 for ATM AAL5 traffic, and by NBAP packets for SCTP traffic.'),
        245 => array(
            'link_type_name' => 'LINKTYPE_NFC_LLCP',
            'data_link_name' => 'DLT_NFC_LLCP',
            'description' => 'Pseudo-header for NFC LLCP packet captures, followed by frame data for the LLCP Protocol as specified by NFCForum-TS-LLCP_1.1.'),
        247 => array(
            'link_type_name' => 'LINKTYPE_INFINIBAND',
            'data_link_name' => 'DLT_INFINIBAND',
            'description' => 'Raw InfiniBand frames, starting with the Local Routing Header, as specified in Chapter 5 "Data packet format" of InfiniBand™ Architectural Specification Release 1.2.1 Volume 1 - General Specifications.'),
        248 => array(
            'link_type_name' => 'LINKTYPE_SCTP',
            'data_link_name' => 'DLT_SCTP',
            'description' => 'SCTP packets, as defined by RFC 4960, with no lower-level protocols such as IPv4 or IPv6.'),
        249 => array(
            'link_type_name' => 'LINKTYPE_USBPCAP',
            'data_link_name' => 'DLT_USBPCAP',
            'description' => 'USB packets, beginning with a USBPcap header.'),
        250 => array(
            'link_type_name' => 'LINKTYPE_RTAC_SERIAL',
            'data_link_name' => 'DLT_RTAC_SERIAL',
            'description' => 'Serial-line packet header for the Schweitzer Engineering Laboratories "RTAC" product, followed by a payload for one of a number of industrial control protocols.'),
        251 => array(
            'link_type_name' => 'LINKTYPE_BLUETOOTH_LE_LL',
            'data_link_name' => 'DLT_BLUETOOTH_LE_LL',
            'description' => 'Bluetooth Low Energy air interface Link Layer packets, in the format described in section 2.1 "PACKET FORMAT" of volume 6 of the Bluetooth Specification Version 4.0 (see PDF page 2200), but without the Preamble.'),
        253 => array(
            'link_type_name' => 'LINKTYPE_NETLINK',
            'data_link_name' => 'DLT_NETLINK',
            'description' => 'Linux Netlink capture encapsulation.'),
        254 => array(
            'link_type_name' => 'LINKTYPE_BLUETOOTH_LINUX_MONITOR',
            'data_link_name' => 'DLT_BLUETOOTH_LINUX_MONITOR',
            'description' => 'Bluetooth Linux Monitor encapsulation of traffic for the BlueZ stack.'),
        255 => array(
            'link_type_name' => 'LINKTYPE_BLUETOOTH_BREDR_BB',
            'data_link_name' => 'DLT_BLUETOOTH_BREDR_BB',
            'description' => 'Bluetooth Basic Rate and Enhanced Data Rate baseband packets.'),
        256 => array(
            'link_type_name' => 'LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR',
            'data_link_name' => 'DLT_BLUETOOTH_LE_LL_WITH_PHDR',
            'description' => 'Bluetooth Low Energy link-layer packets.'),
        257 => array(
            'link_type_name' => 'LINKTYPE_PROFIBUS_DL',
            'data_link_name' => 'DLT_PROFIBUS_DL',
            'description' => 'PROFIBUS data link layer packets, as specified by IEC standard 61158-6-3, beginning with the start delimiter, ending with the end delimiter, and including all octets between them.'),
        258 => array(
            'link_type_name' => 'LINKTYPE_PKTAP',
            'data_link_name' => 'DLT_PKTAP',
            'description' => 'Apple PKTAP capture encapsulation.'),
        259 => array(
            'link_type_name' => 'LINKTYPE_EPON',
            'data_link_name' => 'DLT_EPON',
            'description' => 'Ethernet-over-passive-optical-network packets, starting with the last 6 octets of the modified preamble as specified by 65.1.3.2 "Transmit" in Clause 65 of Section 5 of IEEE 802.3, followed immediately by an Ethernet frame.'),
        260 => array(
            'link_type_name' => 'LINKTYPE_IPMI_HPM_2',
            'data_link_name' => 'DLT_IPMI_HPM_2',
            'description' => 'IPMI trace packets, as specified by Table 3-20 "Trace Data Block Format" in the PICMG HPM.2 specification. The time stamps for packets in this format must match the time stamps in the Trace Data Blocks.'),
        261 => array(
            'link_type_name' => 'LINKTYPE_ZWAVE_R1_R2',
            'data_link_name' => 'DLT_ZWAVE_R1_R2',
            'description' => 'Per Joshua Wright, formats for Z-Wave RF profiles R1 and R2 captures.'),
        262 => array(
            'link_type_name' => 'LINKTYPE_ZWAVE_R3',
            'data_link_name' => 'DLT_ZWAVE_R3',
            'description' => 'Per Joshua Wright, formats for Z-Wave RF profile R3 captures.'),
        263 => array(
            'link_type_name' => 'LINKTYPE_WATTSTOPPER_DLM',
            'data_link_name' => 'DLT_WATTSTOPPER_DLM',
            'description' => 'Formats for WattStopper Digital Lighting Management (DLM) and Legrand Nitoo Open protocol common packet structure captures.'),
        264 => array(
            'link_type_name' => 'LINKTYPE_ISO_14443',
            'data_link_name' => 'DLT_ISO_14443',
            'description' => 'Messages between ISO 14443 contactless smartcards (Proximity Integrated Circuit Card, PICC) and card readers (Proximity Coupling Device, PCD), with the message format specified by the PCAP format for ISO14443 specification.'),
    );

    private $endian = 0;

    /**
     * Parse file content.
     * @param string $raw
     * @return bool
     * @throws Exception
     */
    public function parse($raw) {
        $currentPosition = 0;

        while ($currentPosition < strlen($raw)) {
            $blockType = $this->bin2hexEndian(substr($raw, $currentPosition, 4));
            switch ($blockType) {
                case self::SHB_TYPE:
                    $this->parseSectionHeaderBlock($raw, $currentPosition);
                    break;
                case self::CB_TYPE1:
                case self::CB_TYPE2:
                    //todo
                    break;
                case self::IDB_TYPE:
                    $this->parseInterfaceDescriptionBlock($raw, $currentPosition);
                    break;
                case self::EPB_TYPE:
                    $this->parseEnhancedPacketBlock($raw, $currentPosition);
                    break;
                default:
                    $this->showNextBytes($raw, $currentPosition, 30);
                    throw new Exception('Unknown type');
                    trigger_error('Unknown type of block', E_USER_NOTICE);
            }
        }

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

    /**
     * Parse Section Header Block.
     * @param string $raw Binary string
     * @param int $currentPosition
     * @throws Exception
     */
    private function parseSectionHeaderBlock($raw, &$currentPosition) {
        echo '---------- SHB ------------' . PHP_EOL;

        // Section Header Block - Block Type
        $blockStart = $this->bin2hexEndian(substr($raw, $currentPosition, 4));
        if ($blockStart !== self::SHB_TYPE) {
            throw new Exception('Unknown format of Section Header Block');
        }

        // Section Header Block - Block Total Length
        $shbLength = $this->rawToDecimal(substr($raw, $currentPosition + 4, 4));
        echo 'SHB length:' . $shbLength . PHP_EOL;

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
     * Parse Interface Description Block.
     * @param string $raw Binary string
     * @param int $currentPosition
     * @throws Exception
     */
    private function parseInterfaceDescriptionBlock($raw, &$currentPosition) {
        echo '---------- IDB ------------' . PHP_EOL;

        $blockStart = $this->bin2hexEndian(substr($raw, $currentPosition, 4));
        if ($blockStart !== self::IDB_TYPE) {
            throw new Exception('Unknown format of Interface Description Block');
        }

        // Section Header Block - Block Total Length
        $totalLength = $this->rawToDecimal(substr($raw, $currentPosition + 4, 4));
        echo 'IDB length:' . $totalLength . PHP_EOL;

        $linkType = $this->rawToDecimal(substr($raw, $currentPosition + 8, 2));
        echo 'IDB link type:' . $linkType . PHP_EOL;

        $reserved = $this->bin2hexEndian(substr($raw, $currentPosition + 10, 2));
        if ($reserved !== '0000') {
            trigger_error('Reserved field in Interface Description Block must by 0', E_USER_NOTICE);
        }

        $snapLen = $this->rawToDecimal(substr($raw, $currentPosition + 12, 4));
        echo 'IDB snap length:' . $snapLen . PHP_EOL;

        $currentPosition += 16;
        $this->parseOptions($raw, $currentPosition);

        $lengthEnd = $this->rawToDecimal(substr($raw, $currentPosition, 4));
        if ($lengthEnd !== $totalLength) {
            throw new Exception('Unknown format');
        }

        $currentPosition += 4;
    }

    /**
     * Parse Enhanced Packet Block.
     *
     * An Enhanced Packet Block (EPB) is the standard container for storing the packets coming from the network.
     * The Enhanced Packet Block is optional because packets can be stored either by means of this block or
     * the Simple Packet Block, which can be used to speed up capture file generation.
     *
     * @param string $raw Binary string
     * @param int $currentPosition
     * @throws Exception
     */
    private function parseEnhancedPacketBlock($raw, &$currentPosition) {
        echo '---------- EPB ------------' . PHP_EOL;

        $blockStart = $this->bin2hexEndian(substr($raw, $currentPosition, 4));
        if ($blockStart !== self::EPB_TYPE) {
            throw new Exception('Unknown format of Enhanced Packet Block');
        }

        // Section Header Block - Block Total Length
        $totalLength = $this->rawToDecimal(substr($raw, $currentPosition + 4, 4));
        echo 'Length:' . $totalLength . PHP_EOL;

        $interfaceId = $this->rawToDecimal(substr($raw, $currentPosition + 8, 4));
        echo 'Interface ID:' . $interfaceId . PHP_EOL;

        $timestampHigh = $this->rawToFloat(substr($raw, $currentPosition + 12, 4)); //todo wrong representation
        echo 'Timestamp(high):' . $timestampHigh . PHP_EOL;

        $timestampLow = $this->rawToFloat(substr($raw, $currentPosition + 16, 4)); //todo wrong representation
        echo 'Timestamp(low):' . $timestampLow . PHP_EOL;

        $capturedLength = $this->rawToDecimal(substr($raw, $currentPosition + 20, 4));
        echo 'Captured Packet Length:' . $capturedLength . PHP_EOL;

        $originalLength = $this->rawToDecimal(substr($raw, $currentPosition + 24, 4));
        echo 'Original Packet Length:' . $originalLength . PHP_EOL;

        $packetData = substr($raw, $currentPosition, $capturedLength);
        echo 'Packet data:' . $packetData . PHP_EOL;

        $paddedLength = ceil($capturedLength / 4) * 4;
        $currentPosition = $currentPosition + 28 + $paddedLength;

        if ($totalLength - (28 + $paddedLength + 4) >= 8) { //there is some space for Options //8 = minimal Options size
            $this->parseOptions($raw, $currentPosition);
        }

        $lengthEnd = $this->rawToDecimal(substr($raw, $currentPosition, 4));
        if ($lengthEnd !== $totalLength) {
            throw new Exception('Unknown format');
        }

        $currentPosition += 4;
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

    /**
     * Convert binary string to float.
     * @param string $raw
     * @return float
     */
    public function rawToFloat($raw) {
        $data = unpack('f', strrev($raw));

        return $data[1];
    }

    /**
     * Display following bytes. Only for development.
     * @param string $raw
     * @param int $currentPosition
     * @param int $length
     * @internal Only for development
     */
    private function showNextBytes($raw, $currentPosition, $length) {
        $hex = $this->bin2hexEndian(substr($raw, $currentPosition, $length));
        $array = explode(',', chunk_split($hex, 2, ','));
        krsort($array);
        foreach ($array as $index => $item) {
            echo $item . ' ' . chr(hexdec($item)) . PHP_EOL;
        }
    }

}