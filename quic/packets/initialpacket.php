<?php
namespace QUIC\Packets;
use QUIC\Packet;
use QUIC\Keys;

class InitialPacket extends Packet{
  public int $token_len = 0;

  public string $token;

  public int $length;

  public int $packet_number = 0;

  public static string $salt = "38762cf7f55934b34d179ae6a4c80cadccbb7f0a";

  public function __construct(string $data){
    parent::__construct($data);
    /**
     * Initial Packet
     * 
     * 1 byte - Information
     * 4 byte - Version
     * 1 byte - DCID length
     * x byte - DCID
     * 1 byte - SCID length
     * x byte - SCID
     * 1 byte - Token length
     * x byte - Token
     * 2 byte - length
     * 4 byte - Packet number
     */

    $header = substr($data, 0, 
      1 + 4 + 
      $this->dest_id_len + 1 + 
      $this->src_id_len + 1 + 
      $this->token_len + 1 + 
      2 + 4
    );
    $sample = substr($data, strlen($header), 16);
    $client_keys = Keys::client(hex2bin(self::$salt), hex2bin($this->dest_id));
    $mask = openssl_encrypt($sample, 'aes-128-ecb', $client_keys->hp, OPENSSL_RAW_DATA);
    $length = substr($header, -6, 2);

    $this->length = self::var_uint8(ord($length[0])) & unpack('n', $length)[1];

    /** Decode Packet Number */
    $packet_byte = substr($header, -4);
    $mask = substr($mask, 0, 5);

    $packet_0 = ord($header[0]);

    if(($packet_0 & 0x80) === 0x80)
      $packet_0^= ord($mask[0]) & 0x0f;

    $packet_len = ($packet_0 & 0x3) + 1;

    for($i = 0; $i < $packet_len; $i++){
      $this->packet_number|= ord($packet_byte[$i] ^ $mask[$i + 1]) << (8 * ($packet_len - 1 - $i));
    }

    // Dump this to reveal the header
    // var_dump($this);

    
    $header[0] = chr($packet_0);
    $header = substr($header, 0, -3);
    $header[strlen($header) - 1] = chr($this->packet_number);
    $payload = substr($data, strlen($header), -16);
    $aad = substr($data, -16);
    var_dump('header:', bin2hex($header));
    echo "\n";
    var_dump("payload:", bin2hex($payload));
    echo "\n";
    var_dump("aad:", bin2hex($aad));

    var_dump(openssl_decrypt(
      $payload, 
      'aes-128-gcm', 
      $client_keys->key, 
      OPENSSL_RAW_DATA, 
      $client_keys->iv ^ str_pad(chr($this->packet_number), strlen($client_keys->iv), "\x0", STR_PAD_LEFT),
      $aad,
      $header
    ));
    // var_dump(bin2hex(substr($data, strlen($header) - 3)));

    
    // /** Decode payload */
    // $payload = substr($data, strlen($header) - 3);
    // $tag = substr($data, -16);
    // $iv = $client_keys->iv;
    // $nonce = $iv ^ str_pad(chr($this->packet_number), strlen($iv), "\x0", STR_PAD_LEFT);
    // $aad = $header;

    // $aad[0] = chr(0xc0);

    // // alt 1 - override 1 byte of data
    // // for($i = 0; $i < $packet_len; $i++){
    // //   $aad[strlen($aad) - 1 - $i] = chr($this->packet_number >> (8 * $i));
    // // }

    // // alt 2 - clears 4 bytes and write 1 byte of data
    // for($i = 0; $i < 4; $i++){
    //   $aad[strlen($aad) - 1 - $i] = chr($this->packet_number >> (8 * $i));
    // }

    // var_dump(bin2hex($payload));
    // var_dump(openssl_decrypt($payload, 'aes-128-gcm', $client_keys->key, OPENSSL_RAW_DATA, $nonce, $tag, $aad));
    // var_dump(openssl_error_string());
    // // var_dump(openssl_decrypt($payload, 'aes-128-gcm', $client_keys->key, OPENSSL_RAW_DATA, bin2hex($iv ^ str_pad(chr($this->packet_number), strlen($iv), "\x0", STR_PAD_LEFT)), $tag));
  }

}