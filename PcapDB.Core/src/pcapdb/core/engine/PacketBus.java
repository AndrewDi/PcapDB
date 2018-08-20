package pcapdb.core.engine;


import org.jnetpcap.PcapHeader;
import org.jnetpcap.packet.PcapPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pcapdb.core.packet.*;

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.concurrent.*;

public class PacketBus {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass().getName());

    private ScheduledThreadPoolExecutor scheduledExecutorService;
    private ConcurrentHashMap<String,PacketThread> packetThreadHashMap;
    private ConcurrentHashMap<String, ConcurrentLinkedQueue<Packet>> packetHashMaps;

    public PacketBus(){
        this.scheduledExecutorService = new ScheduledThreadPoolExecutor(8);
        this.packetThreadHashMap = new ConcurrentHashMap<>();
        this.packetHashMaps = new ConcurrentHashMap<>();
    }

    public void Dispatch(PcapPacket pcapPacket){
        //Convert PcapPacket to Standard ByteBuffer
        int caplen = pcapPacket.getCaptureHeader().caplen();
        ByteBuffer byteBuffer = ByteBuffer.allocate(caplen);
        int state = pcapPacket.transferTo(byteBuffer);
        PcapHeader pcapHeader = pcapPacket.getCaptureHeader();
        Packet packet = new Packet(byteBuffer,pcapHeader.hdr_sec(),pcapHeader.hdr_usec(),pcapHeader.caplen(),pcapHeader.hdr_len());
        AbstractPacket abstractPacket = packet.Decoder();
        if(abstractPacket instanceof DrdaPacketList){
            TcpPacket tcpPacket = (TcpPacket)abstractPacket.getParent();
            String packetKey = tcpPacket.getKey();
            String reversalPacketKey = tcpPacket.getReversalKey();
            if(!packetHashMaps.containsKey(packetKey)&&!packetHashMaps.containsKey(reversalPacketKey)){
                ConcurrentLinkedQueue<Packet> packets = new ConcurrentLinkedQueue<>();
                PacketThread packetThread = new PacketThread(packets,packetKey);
                this.packetHashMaps.put(packetKey,packets);
                this.packetThreadHashMap.put(packetKey,packetThread);
                this.scheduledExecutorService.scheduleAtFixedRate(packetThread,0,1000, TimeUnit.MICROSECONDS);
            }
            boolean result;
            if(packetHashMaps.containsKey(reversalPacketKey)){
                result = packetHashMaps.get(reversalPacketKey).offer(packet);
            }
            else {
                result=packetHashMaps.get(packetKey).offer(packet);
            }
            if(!result){
                logger.error("Error put packets {}",packet.toString());
            }
        }
    }

    public void stop(){
        this.scheduledExecutorService.shutdown();
    }
}
