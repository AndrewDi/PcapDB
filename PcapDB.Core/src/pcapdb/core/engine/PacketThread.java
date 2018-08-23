package pcapdb.core.engine;

import com.google.common.collect.ListMultimap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pcapdb.core.frame.DrdaCodePointType;
import pcapdb.core.packet.*;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.concurrent.ConcurrentLinkedQueue;

public class PacketThread implements Runnable {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass().getName());

    private String packetKey;
    private ConcurrentLinkedQueue<Packet> packetsQueue;

    private int transactionID=0;

    private boolean isTransactionStart = false;
    private boolean isConnectionStart = false;
    private DrdaPacketList statingDrdaPacketList=null;
    private LocalDateTime transactionStartTime=null;
    private String dbname=null;

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
                    this.statingDrdaPacketList = drdaPacketList;
                }
                else if (isConnectionStart&&drdaPacketList.getDrdaPacketList().containsKey(DrdaCodePointType.SECCHKRM)&&this.statingDrdaPacketList!=null){
                    isConnectionStart = false;
                    StringBuilder sb = new StringBuilder();
                    DrdaPacket statingDrdaPacket = this.statingDrdaPacketList.getDrdaPacketList().get(DrdaCodePointType.SECCHK).get(0);
                    TcpPacket statingTcpPacket = (TcpPacket)this.statingDrdaPacketList.getParent();
                    Ipv4Packet statingIpv4Packet = (Ipv4Packet) statingTcpPacket.getParent();
                    EthernetPacket statingEthernetPacket = (EthernetPacket)statingIpv4Packet.getParent();
                    Packet statingPacket = (Packet)statingEthernetPacket.getParent();
                    sb.append(statingDrdaPacket.getDrdaDDMParameters().get(DrdaCodePointType.RDBNAM).get(0).getData());
                    sb.append("|");
                    sb.append("CONNECT|");
                    sb.append(statingTcpPacket.getKey());
                    sb.append("|");
                    sb.append(statingPacket.getFullArrivalTime().toString());
                    sb.append("|");
                    sb.append(packet.getFullArrivalTime().toString());
                    sb.append("|");
                    sb.append(Duration.between(statingPacket.getFullArrivalTime(),packet.getFullArrivalTime()).toMillis());


                    this.dbname = statingDrdaPacket.getDrdaDDMParameters().get(DrdaCodePointType.RDBNAM).get(0).getData().toString().toUpperCase();
                    sb.append("|");
                    sb.append(statingDrdaPacket.getDrdaDDMParameters().get(DrdaCodePointType.USRID).get(0).getData());
                    sb.append("|");
                    DrdaPacket secchkrmPacket = drdaPacketList.getDrdaPacketList().get(DrdaCodePointType.SECCHKRM).get(0);
                    sb.append(secchkrmPacket.getDrdaDDMParameters().get(DrdaCodePointType.SVRCOD).get(0).getData());
                    sb.append("|");
                    sb.append(secchkrmPacket.getDrdaDDMParameters().get(DrdaCodePointType.SECCHKCD).get(0).getData());
                    this.statingDrdaPacketList = null;
                    this.transactionID=0;
                    logger.info(sb.toString());
                }

                //Decode SELECT/UPDATE/INSERT/DELETE Statement
                if((drdaPacketList.getDrdaPacketList().containsKey(DrdaCodePointType.PRPSQLSTT)||
                        drdaPacketList.getDrdaPacketList().containsKey(DrdaCodePointType.EXCSQLSET) ||
                        drdaPacketList.getDrdaPacketList().containsKey(DrdaCodePointType.EXCSQLIMM))&&
                        !isTransactionStart){
                    //Mark Transaction Start
                    this.isTransactionStart=true;
                    this.statingDrdaPacketList = drdaPacketList;
                    //Set dbname
                    if(this.dbname==null){
                        if(drdaPacketList.getDrdaPacketList().containsKey(DrdaCodePointType.EXCSQLSET)){
                            this.dbname = drdaPacketList.getDrdaPacketList().get(DrdaCodePointType.EXCSQLSET).get(0).getDrdaDDMParameters().get(DrdaCodePointType.PKGNAMCSN).get(0).getData().toString().split(" ")[0].trim().toUpperCase();
                        }
                        else if(drdaPacketList.getDrdaPacketList().containsKey(DrdaCodePointType.PRPSQLSTT)){
                            this.dbname = drdaPacketList.getDrdaPacketList().get(DrdaCodePointType.PRPSQLSTT).get(0).getDrdaDDMParameters().get(DrdaCodePointType.PKGNAMCSN).get(0).getData().toString().split(" ")[0].trim().toUpperCase();
                        }
                    }

                    StringBuilder sb = new StringBuilder();
                    sb.append(this.dbname);
                    sb.append("|");
                    sb.append("TRANSACTION|");
                    sb.append("START|");
                    sb.append(this.transactionID);
                    sb.append("|");
                    sb.append(tcpPacket.getKey());
                    sb.append("|");
                    sb.append(packet.getFullArrivalTime().toString());
                    this.transactionStartTime=packet.getFullArrivalTime();
                    logger.info(sb.toString());

                }
                else if((drdaPacketList.getDrdaPacketList().containsKey(DrdaCodePointType.PRPSQLSTT)||
                        drdaPacketList.getDrdaPacketList().containsKey(DrdaCodePointType.EXCSQLSET) ||
                        drdaPacketList.getDrdaPacketList().containsKey(DrdaCodePointType.EXCSQLIMM))&&
                        isTransactionStart){
                    this.statingDrdaPacketList = drdaPacketList;
                }
                else if(isTransactionStart&&
                        !drdaPacketList.getDrdaPacketList().containsKey(DrdaCodePointType.RDBCMM)&&!drdaPacketList.getDrdaPacketList().containsKey(DrdaCodePointType.RDBRLLBCK)){
                    TcpPacket statingTcpPacket = (TcpPacket)this.statingDrdaPacketList.getParent();
                    Ipv4Packet statingIpv4Packet = (Ipv4Packet) statingTcpPacket.getParent();
                    EthernetPacket statingEthernetPacket = (EthernetPacket)statingIpv4Packet.getParent();
                    Packet statingPacket = (Packet)statingEthernetPacket.getParent();

                    ListMultimap<DrdaCodePointType,DrdaPacket> statingDrdaPacketListMap = this.statingDrdaPacketList.getDrdaPacketList();
                    String SQL="";
                    if(statingDrdaPacketListMap.containsKey(DrdaCodePointType.EXCSQLSET)||
                    statingDrdaPacketListMap.containsKey(DrdaCodePointType.EXCSQLIMM)||
                            statingDrdaPacketListMap.containsKey(DrdaCodePointType.SQLSTT)){
                        if(statingDrdaPacketListMap.containsKey(DrdaCodePointType.SQLSTT)){
                            SQL = statingDrdaPacketListMap.get(DrdaCodePointType.SQLSTT).get(statingDrdaPacketListMap.get(DrdaCodePointType.SQLSTT).size()-1).getDrdaDDMParameters().get(DrdaCodePointType.DATA).get(0).getData().toString();
                        }
                        if(drdaPacketList.getDrdaPacketList().containsKey(DrdaCodePointType.SQLCARD)){
                            ListMultimap<DrdaCodePointType,DrdaPacket> drdaPacketListMap = drdaPacketList.getDrdaPacketList();
                            SQLResult sqlResult =  (SQLResult)drdaPacketListMap.get(DrdaCodePointType.SQLCARD).get(drdaPacketListMap.get(DrdaCodePointType.SQLCARD).size()-1).getDrdaDDMParameters().get(DrdaCodePointType.SQLCARD).get(0).getData();
                            StringBuilder sb = new StringBuilder();
                            sb.append(this.dbname);
                            sb.append("|");
                            sb.append("SQL|");
                            sb.append(this.transactionID);
                            sb.append("|");
                            sb.append(statingTcpPacket.getKey());
                            sb.append("|");
                            sb.append(statingPacket.getFullArrivalTime().toString());
                            sb.append("|");
                            sb.append(packet.getFullArrivalTime().toString());
                            sb.append("|");
                            sb.append(Duration.between(statingPacket.getFullArrivalTime(),packet.getFullArrivalTime()).toMillis());
                            sb.append("|");
                            sb.append(sqlResult.getSqlCode());
                            sb.append("|");
                            sb.append(sqlResult.getSqlState());
                            sb.append("|");
                            sb.append(SQL.length());
                            sb.append("|");
                            sb.append(SQL);

                            this.statingDrdaPacketList = null;
                            logger.info(sb.toString());
                        }
                    }
                }

                //Commit or rollback process
                if(drdaPacketList.getDrdaPacketList().containsKey(DrdaCodePointType.RDBCMM)||drdaPacketList.getDrdaPacketList().containsKey(DrdaCodePointType.RDBRLLBCK)){
                    this.statingDrdaPacketList=drdaPacketList;
                }
                else if (drdaPacketList.getDrdaPacketList().containsKey(DrdaCodePointType.ENDUOWRM)){
                    TcpPacket statingTcpPacket = (TcpPacket)this.statingDrdaPacketList.getParent();
                    Ipv4Packet statingIpv4Packet = (Ipv4Packet) statingTcpPacket.getParent();
                    EthernetPacket statingEthernetPacket = (EthernetPacket)statingIpv4Packet.getParent();
                    Packet statingPacket = (Packet)statingEthernetPacket.getParent();

                    StringBuilder sb = new StringBuilder();
                    sb.append(this.dbname);
                    sb.append("|");
                    sb.append("TRANSACTION|");
                    if(statingDrdaPacketList.getDrdaPacketList().containsKey(DrdaCodePointType.RDBCMM)) {
                        sb.append("COMMIT|");
                    }
                    else if(statingDrdaPacketList.getDrdaPacketList().containsKey(DrdaCodePointType.RDBRLLBCK)){
                        sb.append("ROLLBACK|");
                    }
                    sb.append(this.transactionID);
                    sb.append("|");
                    sb.append(statingTcpPacket.getKey());
                    sb.append("|");
                    sb.append(statingPacket.getFullArrivalTime().toString());
                    sb.append("|");
                    sb.append(packet.getFullArrivalTime().toString());
                    sb.append("|");
                    sb.append(Duration.between(statingPacket.getFullArrivalTime(),packet.getFullArrivalTime()).toMillis());
                    sb.append("|");
                    sb.append(Duration.between(this.transactionStartTime,packet.getFullArrivalTime()).toMillis());
                    logger.info(sb.toString());

                    this.transactionID++;
                    this.isTransactionStart=false;
                    this.statingDrdaPacketList = null;
                }

                //logger.debug(drdaPacketList.getDDMListString());
            }
            //if not drda packet,do nothing
        }
    }
}
