<?php
namespace QUIC;

final class Keys{
  public string $in;

  public string $key;

  public string $iv;

  public string $hp;

  public string $secret;

  public static function server(string $salt, string $dest_conn_id, bool $as_hex = false){
    $keys = new self;
    $secret = HKDF::extract($salt, $dest_conn_id);
    
    $keys->secret = $secret;
    $keys->in = HKDF::expand($secret, 'server in', 32);
    $keys->key = HKDF::expand($keys->in, 'quic key', 16);
    $keys->iv = HKDF::expand($keys->in, 'quic iv', 12);
    $keys->hp = HKDF::expand($keys->in, 'quic hp', 16);

    if($as_hex){
      $keys->in = bin2hex($keys->in);
      $keys->key = bin2hex($keys->key);
      $keys->iv = bin2hex($keys->iv);
      $keys->hp = bin2hex($keys->hp);
    }

    return $keys;
  }

  public static function client(string $salt, string $dest_conn_id, bool $as_hex = false){
    $keys = new self;
    $secret = HKDF::extract($salt, $dest_conn_id);
    

    $keys->secret = $secret;
    $keys->in = HKDF::expand($secret, 'client in', 32);
    $keys->key = HKDF::expand($keys->in, 'quic key', 16);
    $keys->iv = HKDF::expand($keys->in, 'quic iv', 12);
    $keys->hp = HKDF::expand($keys->in, 'quic hp', 16);

    if($as_hex){
      $keys->secret = bin2hex($keys->secret);
      $keys->in = bin2hex($keys->in);
      $keys->key = bin2hex($keys->key);
      $keys->iv = bin2hex($keys->iv);
      $keys->hp = bin2hex($keys->hp);
    }

    return $keys;
  }
}