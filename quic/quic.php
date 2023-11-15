<?php
namespace QUIC;

use Socket;

final class QUIC{
  /**
   * @var Packet[]
   */
  public array $packets;

  public string $host;

  public int $port;

  public Socket $socket;

  public static int $size = 1024 * 1024;

  public function __construct(string $host, int $port){
    $this->host = $host;
    $this->port = $port;
  }

  public function start(){
    if(isset($this->socket))
      socket_close($this->socket);

    $this->socket = socket_create(AF_INET6, SOCK_DGRAM, SOL_UDP);
    socket_bind($this->socket, $this->host, $this->port);
    
    while(true){
      if(socket_recvfrom($this->socket, $data, self::$size, 0, $addr, $port)){
        switch(ord($data) & 0x30){
          // Initial Packet 
          case 0 : $this->packets[] = new \QUIC\Packets\InitialPacket($data); break;
        }
      }
    }
  }
}
