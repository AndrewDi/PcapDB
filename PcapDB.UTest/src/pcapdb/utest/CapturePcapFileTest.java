package pcapdb.utest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import pcapdb.core.buffer.MappedByteBufferLocater;
import pcapdb.core.engine.CapturePcapFile;
import pcapdb.core.packet.AbstractPacket;
import pcapdb.core.packet.Packet;
import pcapdb.core.packet.PcapHeader;


public class CapturePcapFileTest {

    protected final static Logger logger = LoggerFactory.getLogger(CapturePcapFile.class.getName());

    public static void main(String[] args) {
        MappedByteBufferLocater mappedByteBufferLocater = CapturePcapFile.OpenFile("PcapDB.UTest/Pcaps/drda_db2_sample.cap");
        AbstractPacket pcapHeader = new PcapHeader(mappedByteBufferLocater);
        MappedByteBufferLocater payload = pcapHeader.getPayload();
        while (payload.hasRemaining()){
            Packet packet = new Packet(payload);
            logger.info(packet.toString());
            payload=packet.getNextPacket();
        }
    }
}
