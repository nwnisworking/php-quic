<?php
namespace QUIC;

abstract class Packet{
  public int $header_form;

  public int $fixed_bit;

  public int $packet_type;
  
  public int $version;

  public int $dest_id_len = 0;

  public string $dest_id;

  public int $src_id_len = 0;

  public string $src_id;

  public function __construct(string $data){
    ['info'=>$info, 'version'=>$version] = unpack('Cinfo/Nversion', $data);
    
    $this->header_form = !!($info & 0x80);
    $this->fixed_bit = !!($info & 0x40);
    $this->packet_type = $info & 0x30;
    $this->version = $version;
    
    $data = substr($data, 5);

    /** Destination connection length + id  */
    if(ord($data[0])){
      $this->dest_id_len = ord($data[0]);
      $this->dest_id = unpack("H".($this->dest_id_len * 2), substr($data, 1))[1];
      $data = substr($data, $this->dest_id_len + 1);
    }
    else
      $data = substr($data, 1);

    /** Source connection length + id  */
    if(ord($data[0])){
      $this->src_id_len = ord($data[0]);
      $this->src_id = unpack("H".($this->src_id_len * 2), substr($data, 1))[1];
      $data = substr($data, $this->src_id_len + 1);
    }
    else
      $data = substr($data, 1);
  }

  public static function var_uint8(int $data){
    switch($data >> 6){
      case 0 : 
        return 0x3f;
      case 1 : 
        return 0x3fff;
      case 2 : 
        return 0x3FFFFFFF;
      case 3 : 
        return 0x3FFFFFFFFFFFFFFF;
      default : 
        return 0;
    }
  }
}