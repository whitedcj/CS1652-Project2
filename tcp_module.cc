#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <iostream>

#include "Minet.h"
#include "tcp.h"
#include "tcpstate.h"
#include "packet.h"

using namespace std;

//workaround because SetLastAcked and GetLastAcked doesn't work
unsigned int lastAckReceived; //from mux
unsigned int lastAckSent; //to mux

void create_packet(Packet *p, Connection c, int data_len, int seq, int ack, int window, unsigned char flags);

int main(int argc, char * argv[]) {
	
	//setup for minet modules
	MinetHandle mux;
	MinetHandle sock;
	
	ConnectionList<TCPState> clist;

	MinetInit(MINET_TCP_MODULE);

	mux = MinetIsModuleInConfig(MINET_IP_MUX) ?  
	MinetConnect(MINET_IP_MUX) : 
	MINET_NOHANDLE;
	
	sock = MinetIsModuleInConfig(MINET_SOCK_MODULE) ? 
	MinetAccept(MINET_SOCK_MODULE) : 
	MINET_NOHANDLE;

	if ( (mux == MINET_NOHANDLE) && 
	 (MinetIsModuleInConfig(MINET_IP_MUX)) ) {

	MinetSendToMonitor(MinetMonitoringEvent("Can't connect to ip_mux"));

	return -1;
	}

	if ( (sock == MINET_NOHANDLE) && 
	 (MinetIsModuleInConfig(MINET_SOCK_MODULE)) ) {

	MinetSendToMonitor(MinetMonitoringEvent("Can't accept from sock_module"));

	return -1;
	}
	
	cerr << "tcp_module STUB VERSION handling tcp traffic.......\n";

	MinetSendToMonitor(MinetMonitoringEvent("tcp_module STUB VERSION handling tcp traffic........"));

	//event handlers
	MinetEvent event;
	double timeout = 1;
	while (MinetGetNextEvent(event, timeout) == 0)
	{
		if ((event.eventtype == MinetEvent::Dataflow) && (event.direction == MinetEvent::IN)) 
		{
	  
			if (event.handle == mux) // ip packet has arrived
			{	
				Packet p;
				unsigned short len;
				unsigned int seq_num;
				unsigned int ack_num;
				bool checksumok;
				MinetReceive(mux,p);
				unsigned int headerLen = TCPHeader::EstimateTCPHeaderLength(p);
				p.ExtractHeaderFromPayload<TCPHeader>(headerLen);
	
				TCPHeader tcph;

				//get seq num
				tcph=p.FindHeader(Headers::TCPHeader);
				tcph.GetSeqNum(seq_num);
				unsigned char f1;
				tcph.GetFlags(f1);
	
				checksumok=tcph.IsCorrectChecksum(p);

				IPHeader iph;
				iph=p.FindHeader(Headers::IPHeader);
		
				Connection c;
				// note that this is flipped around because
				// "source" is interepreted as "this machine"
				iph.GetDestIP(c.src);
				iph.GetSourceIP(c.dest);
				iph.GetProtocol(c.protocol);
				tcph.GetDestPort(c.srcport);
				tcph.GetSourcePort(c.destport);
	
				ConnectionList<TCPState>::iterator cs = clist.FindMatching(c);
				if (cs!=clist.end())
				{
					switch ((*cs).state.GetState())
					{
						case SYN_SENT :
						{
							(*cs).state.SetLastRecvd(seq_num);

							tcph.GetAckNum(ack_num);

							(*cs).state.SetLastAcked(ack_num);
							lastAckReceived = ack_num;
							if (ack_num == (*cs).state.GetLastSent() + 1)
							{
								(*cs).state.SetState(ESTABLISHED);

								Connection c = (*cs).connection;
			
								//assign flags and create ack packet
								Packet packet;
								Packet *pptr = &packet;
								unsigned char f = 0;
								SET_ACK(f);
								lastAckSent = seq_num + 1;

								create_packet(pptr, c, 0, lastAckReceived, lastAckSent, 14600, f);
								MinetSend(mux, *pptr);

								//send to sock that the connection was successful
								SockRequestResponse repl;
								repl.type=WRITE;
								repl.connection=(*cs).connection;
								repl.error=EOK;
								repl.bytes=0;
								MinetSend(sock,repl);
							}
							break;
						}

						case LISTEN :
						{
							(*cs).state.SetLastRecvd(seq_num);
							(*cs).state.SetLastSent(999);
							(*cs).connection = c;

							if (IS_SYN(f1))
							{
								//assign flags and create syn ack packet
								Packet packet;
								Packet *pptr = &packet;
								unsigned char f = 0;
								SET_SYN(f);
								SET_ACK(f);
								(*cs).state.SetState(SYN_RCVD);
								lastAckSent = seq_num + 1;

								create_packet(pptr, c, 0, (*cs).state.GetLastSent() + 1, lastAckSent, 14600, f);
								(*cs).state.SetLastSent((*cs).state.GetLastSent() + 1);
								MinetSend(mux, *pptr);
							}

							break;
						}
			
						case SYN_RCVD :
						{
							(*cs).state.SetLastRecvd(seq_num);
							tcph.GetAckNum(ack_num);
							(*cs).state.SetLastAcked(ack_num);
							lastAckReceived = ack_num;

							if (ack_num == (*cs).state.GetLastSent() + 1)
							{
								(*cs).state.SetState(ESTABLISHED);
					
								SockRequestResponse repl;
								repl.type=WRITE;
								repl.connection=(*cs).connection;
								repl.error=EOK;
								repl.bytes=0;
								MinetSend(sock,repl);
							} 
							else 
							{
								printf("in SYN_RCVD but the ack num they sent was not acking our last seq num");
							}
		  
							break;

						} 
			
						case FIN_WAIT1 :
						{

							tcph.GetAckNum(ack_num);						
							(*cs).state.SetLastRecvd(seq_num);
							(*cs).state.SetLastAcked(ack_num);
				
							if (ack_num == lastAckReceived + 1 && IS_FIN(f1) && IS_ACK(f1))
							{
								//assign flags and create ack packet
								Packet packet;
								Packet *pptr = &packet;
								unsigned char f = 0;
								SET_ACK(f);
								lastAckReceived = ack_num;
								lastAckSent = seq_num + 1;
								create_packet(pptr, c, 0, lastAckReceived, lastAckSent, 14600, f);
								MinetSend(mux, *pptr);

								SockRequestResponse repl;
								repl.type=STATUS;
								repl.connection=(*cs).connection;
								repl.error=EOK;
								repl.bytes=0;
								MinetSend(sock,repl);
			
								clist.erase(cs);

							}
							else
							{
								printf("If this is printing, in FIN_WAIT1 we did not get\
									the expected ack_num OR it wasn't FIN OR it wasn't ACK\n");
							}

							break;
						} 
						case FIN_WAIT2 :
						{
							(*cs).state.SetLastRecvd(seq_num);

							tcph.GetAckNum(ack_num);

							(*cs).state.SetLastAcked(ack_num);
							if(IS_ACK(f1) && lastAckReceived + 1 == ack_num)
							{
								(*cs).state.SetState(CLOSING);							
								SockRequestResponse repl;
					
								repl.type=WRITE;
								repl.connection=(*cs).connection;
								repl.error=EOK;
								repl.bytes=0;
								MinetSend(sock,repl);
							}
				
							break;
						}
						case ESTABLISHED :
						{
							(*cs).state.SetLastRecvd(seq_num);
							tcph.GetAckNum(ack_num);
							lastAckReceived = ack_num;
							if(IS_FIN(f1))
							{
								//set the state
								(*cs).state.SetState(FIN_WAIT2);
								//ack their seq + 1
								// send their ack
								(*cs).state.SetLastRecvd(seq_num);

								tcph.GetAckNum(ack_num);

								(*cs).state.SetLastAcked(ack_num);

								Packet packet;
								Packet *pptr = &packet;
								unsigned char f = 0;
								SET_FIN(f);
								SET_ACK(f);

								lastAckSent = seq_num + 1;
								create_packet(pptr, c, 0, lastAckReceived, lastAckSent, 14600, f);
								MinetSend(mux, *pptr);
							}
							else if(IS_PSH(f1) && IS_ACK(f1))
							{
								tcph.GetAckNum(ack_num);
								(*cs).state.SetLastAcked(ack_num);
								lastAckReceived=ack_num;

								if(lastAckSent==seq_num)
								{
									//server side receiving data				
									unsigned char iph_len, tcph_len;
									iph.GetTotalLength(len);
									iph.GetHeaderLength(iph_len);
									iph_len *= 4;
									tcph.GetHeaderLen(tcph_len);
									tcph_len *= 4;
									len-=(iph_len + tcph_len);

									Buffer &data = p.GetPayload().ExtractFront(len);
									lastAckSent = seq_num + len;

									//assign flags and create ack packet
									Packet packet;
									Packet *pptr = &packet;

									unsigned short window;
									tcph.GetWinSize(window);

									unsigned char f = 0;
									SET_ACK(f);
									create_packet(pptr, c, 0, lastAckReceived, lastAckSent, window, f);
									MinetSend(mux, *pptr);
					
									SockRequestResponse write(WRITE, (*cs).connection, data, len, EOK);

									MinetSend(sock,write);	
								}
							}

							break;					
						}	
						default :
						{
							printf("default\n");
							printf("case is %d\n", (*cs).state.GetState());
							break;
						}
					}

					if (!checksumok) 
					{
						MinetSendToMonitor(MinetMonitoringEvent("forwarding packet to sock even though checksum failed"));
					}
				}
				else
				{
				  MinetSendToMonitor(MinetMonitoringEvent("Unknown port, sending ICMP error message"));
				  IPAddress source; iph.GetSourceIP(source);
				  ICMPPacket error(source,DESTINATION_UNREACHABLE,PORT_UNREACHABLE,p);
				  MinetSendToMonitor(MinetMonitoringEvent("ICMP error message has been sent to host"));
				  MinetSend(mux, error);
				}

			}

			if (event.handle == sock) 
			{	// socket request or response has arrived
				SockRequestResponse req;
				MinetReceive(sock,req);
				switch (req.type) 
				{
					case CONNECT:
					{
						ConnectionToStateMapping<TCPState> m;
						TCPState tstate(123456789, SYN_SENT, 100);
			   
						m.connection = req.connection;
						m.state = tstate;
			
						clist.push_back(m);

						Connection c = req.connection;
						Packet packet;
						unsigned int new_seq = 123456789; //should be generated but ok for test
			
						Packet *pptr = &packet;
						unsigned char f = 0;
						SET_SYN(f);
	
						create_packet(pptr, c, 0, new_seq, lastAckSent, 0, f);
						MinetSend(mux, *pptr);
						sleep(2);
						MinetSend(mux, *pptr);

						SockRequestResponse repl;
						repl.type=STATUS;
						repl.connection=req.connection;
						repl.error=EOK;
						repl.bytes=0;
						MinetSend(sock,repl);

						break;
					}
					case ACCEPT:
					{
						SockRequestResponse repl;
						repl.type=STATUS;
						repl.connection=req.connection;
						repl.error=EOK;
						repl.bytes=0;
						MinetSend(sock,repl);
			
						ConnectionToStateMapping<TCPState> m;
						TCPState tstate(0, LISTEN, 100);				
						m.connection = req.connection;
						m.state = tstate;
						clist.push_back(m);
						break;
					}
					case STATUS:
					{
						break;
					}
					case WRITE:
					{
						Connection c = req.connection;
						ConnectionList<TCPState>::iterator cs = clist.FindMatching(c);
		
						if (cs!=clist.end())
						{
							Packet packet(req.data);

							Packet *pptr = &packet;
							unsigned char f = 0;
							SET_ACK(f);
							SET_PSH(f);
	
							create_packet(pptr, c, req.data.GetSize(), lastAckReceived, lastAckSent, 14600, f);
							MinetSend(mux, *pptr);

							SockRequestResponse repl;
							repl.type=STATUS;
							repl.connection=req.connection;
							repl.bytes=req.data.GetSize();
							repl.error=EOK;
							MinetSend(sock,repl);
						}
						break;
					}
					case FORWARD:
					{
						//ignore this and send 0 status
						SockRequestResponse repl;
						repl.type=STATUS;
						repl.connection=req.connection;
						repl.error=EOK;
						repl.bytes=0;
						MinetSend(sock,repl);
						break;
					}
					case CLOSE:
					{
						ConnectionList<TCPState>::iterator cs = clist.FindMatching(req.connection); 
			
						if (cs != clist.end())
						{
							if ((*cs).state.GetState() != CLOSING)
							{
								Connection c = req.connection;

								SockRequestResponse repl;
								repl.connection = req.connection;
								repl.type = STATUS;

								if (cs == clist.end())
								{
									repl.error = ENOMATCH;
								}
								else
								{
									repl.error = EOK;
									(*cs).state.SetState(FIN_WAIT1);

									Packet packet;
									Packet *pptr = &packet;
									unsigned char f = 0;
									SET_ACK(f);
									SET_FIN(f);
									create_packet(pptr, c, 0, lastAckReceived, lastAckSent, 14600, f);
									MinetSend(mux, *pptr);
								}
								MinetSend(sock, repl);
							}
							else
							{
								SockRequestResponse repl;
								repl.type = STATUS;
								repl.connection = (*cs).connection;
								repl.bytes = 0;
								MinetSend(sock, repl);
								clist.erase(cs);
							}
						}
						break;
					}
					default:
					{
						printf("Sock DEFAULT\n");
						SockRequestResponse repl;
						repl.type=STATUS;
						repl.error=EWHAT;
						MinetSend(sock,repl);
						break;
					}
				}
			}
		}

		if (event.eventtype == MinetEvent::Timeout) {
			//timeout not handled
		}

	}

	MinetDeinit();

	return 0;
}
void create_packet(Packet *pptr, Connection c, int data_len, int seq, int ack, int window, unsigned char flags)
{
	Packet packet = *pptr;

	IPHeader ih;
	ih.SetProtocol(IP_PROTO_TCP);
	ih.SetSourceIP(c.src);
	ih.SetDestIP(c.dest);
	ih.SetTotalLength(TCP_HEADER_BASE_LENGTH+IP_HEADER_BASE_LENGTH+data_len);
	packet.PushFrontHeader(ih);
				
	TCPHeader th;
	th.SetSourcePort(c.srcport,packet);
	th.SetDestPort(c.destport,packet);
	th.SetHeaderLen(TCP_HEADER_BASE_LENGTH,packet);

	th.SetSeqNum(seq, packet);
	th.SetAckNum(ack, packet);	
				
	th.SetFlags(flags, packet);
	
	th.SetWinSize(window, packet);
	packet.PushBackHeader(th);
	*pptr = packet;

}
