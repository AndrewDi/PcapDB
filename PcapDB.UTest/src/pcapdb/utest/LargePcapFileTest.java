package pcapdb.utest;

import org.jnetpcap.Pcap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pcapdb.core.buffer.MappedByteBufferLocater;
import pcapdb.core.engine.CapturePcapFile;
import pcapdb.core.packet.AbstractPacket;
import pcapdb.core.packet.Packet;
import pcapdb.core.packet.PcapHeader;

import java.time.Duration;
import java.time.LocalDateTime;

public class LargePcapFileTest {
    protected final static Logger logger = LoggerFactory.getLogger(LargePcapFileTest.class.getName());

    public static void main(String[] args) {
        /**
        MappedByteBufferLocater mappedByteBufferLocater = CapturePcapFile.OpenFile("/home/andrew/Developer/pcap4j/Dump10");
        AbstractPacket pcapHeader = new PcapHeader(mappedByteBufferLocater);
        logger.info(pcapHeader.toString());
        MappedByteBufferLocater payload = pcapHeader.getPayload();
        int i=0;
        LocalDateTime startTime = LocalDateTime.now();
        while (payload.hasRemaining()){
            Packet packet = new Packet(payload);
            i++;
            logger.info(packet.toString());
            packet.Decoder();
            payload=packet.getNextPacket();
        }
        LocalDateTime endTime = LocalDateTime.now();
        logger.info("Process {} packges in {} seconds",i, Duration.between(startTime,endTime).getSeconds());
         **/
        LocalDateTime startTime = LocalDateTime.now();
        String file = "/home/andrew/Developer/pcap4j/Dump10";
        Pcap pcap = CapturePcapFile.PcapOpenFile(file);
        LocalDateTime endTime = LocalDateTime.now();
        logger.info("Process in {} milliseconds", Duration.between(startTime,endTime).toMillis());
    }
}
