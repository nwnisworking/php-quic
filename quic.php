<?php
require_once 'quic/quic.php';
require_once 'quic/packet.php';
require_once 'quic/packets/initialpacket.php';
require_once 'quic/hkdf.php';
require_once 'quic/keys.php';

use QUIC\Packets\InitialPacket;
use QUIC\QUIC;
use QUIC\Keys;

// /**
//  * Test key evaluation 
//  * @link https://datatracker.ietf.org/doc/html/rfc9001#name-client-initial
//  */
// $test_key = Keys::client(hex2bin('38762cf7f55934b34d179ae6a4c80cadccbb7f0a'), hex2bin('8394c8f03e515708'), true);
// var_dump($test_key);

$quic = new QUIC('::1', 4000);

$quic->start();
