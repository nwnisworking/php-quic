<?php
namespace QUIC;

class HKDF{
  public static function label(string $label, int $length){
    $label = 'tls13 '.$label;
    return pack('nCa*C', $length, strlen($label), $label, 0);
  }

  public static function extract(string $salt, string $connection_id){
    return hash_hmac('sha256', $connection_id, $salt, true);
  }

  public static function expand(string $prk, string $label, string $length){
    $label = HKDF::label($label, $length);
    $hash_len = 32;
    $output = '';

    for($i = 1; $i <= ceil($length / $hash_len); $i++)
      $output.= hash_hmac('sha256', $label.pack('C', $i), $prk, true);
    
    return substr($output, 0, $length);
  }
}