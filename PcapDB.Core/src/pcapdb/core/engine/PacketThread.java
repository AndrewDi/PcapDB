package pcapdb.core.engine;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pcapdb.core.frame.DrdaCodePointType;
import pcapdb.core.packet.*;

import java.util.concurrent.ConcurrentLinkedQueue;

public class PacketThread implements Runnable {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass().getName());

    private String packetKey;
    private ConcurrentLinkedQueue<Packet> packetsQueue;


    private boolean isTransactionStart = false;
    private boolean isConnectionStart = false;
    private DrdaPacket statingDrdaPacket=null;

    public PacketThread(ConcurrentLinkedQueue<Packet> packets,String packetKey){
        this.packetsQueue = packets;
        this.packetKey = packetKey;
    }

    @Override
    public void run() {
        while (!this.packetsQueue.isEmpty()){
            Packet packet = this.packetsQueue.poll();
            AbstractPacket abstractPacket = packet.Decoder();
            if(abstractPacket instanceof DrdaPacketList){
                DrdaPacketList drdaPacketList = (DrdaPacketList)abstractPacket;
                TcpPacket tcpPacket = (TcpPacket)drdaPacketList.getParent();
                Ipv4Packet ipv4Packet = (Ipv4Packet) tcpPacket.getParent();
                EthernetPacket ethernetPacket = (EthernetPacket)ipv4Packet.getParent();

                //Connection decoding reassembly
                if(drdaPacketList.getDrdaPacketList().containsKey(DrdaCodePointType.SECCHK)&&!isConnectionStart){
                    isConnectionStart = true;
                    this.statingDrdaPacket = drdaPacketList.getDrdaPacketList().get(DrdaCodePointType.SECCHK);
                }
                else if (isConnectionStart&&drdaPacketList.getDrdaPacketList().containsKey(DrdaCodePointType.SECCHKRM)&&this.statingDrdaPacket!=null){
                    isConnectionStart = false;
                    StringBuilder sb = new StringBuilder();
                    DrdaPacketList statingDrdaPacketParent = (DrdaPacketList)this.statingDrdaPacket.getParent();
                    TcpPacket statingTcpPacket = (TcpPacket)statingDrdaPacketParent.getParent();
                    Ipv4Packet statingIpv4Packet = (Ipv4Packet) statingTcpPacket.getParent();
                    EthernetPacket statingEthernetPacket = (EthernetPacket)statingIpv4Packet.getParent();
                    Packet statingPacket = (Packet)statingEthernetPacket.getParent();
                    sb.append("Connect|");

                    sb.append(statingTcpPacket.getKey());
                    sb.append("|");
                    sb.append(statingPacket.getFullArrivalTime().toString());
                    sb.append("|");
                    sb.append(packet.getFullArrivalTime().toString());
                    sb.append("|");
                    sb.append(statingDrdaPacket.getDrdaDDMParameters().get(DrdaCodePointType.RDBNAM).getData());
                    sb.append("|");
                    sb.append(statingDrdaPacket.getDrdaDDMParameters().get(DrdaCodePointType.USRID).getData());
                    sb.append("|");
                    if(drdaPacketList.getDrdaPacketList().containsKey(DrdaCodePointType.SQLCARD)){
                        DrdaPacket sqlcardDrdaPacket = drdaPacketList.getDrdaPacketList().get(DrdaCodePointType.SQLCARD);
                        if(sqlcardDrdaPacket.getDrdaDDMParameters().size()>0){
                            SQLResult sqlResult = (SQLResult)sqlcardDrdaPacket.getDrdaDDMParameters().get(DrdaCodePointType.SQLCARD).getData();
                            sb.append(sqlResult.getSqlCode());
                            sb.append("|");
                            sb.append(sqlResult.getSqlState());
                        }
                    }
                    logger.debug(sb.toString());
                }
            }
            //if not drda packet,do nothing
        }
    }
}
