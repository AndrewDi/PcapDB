package pcapdb.utest;

import org.jnetpcap.Pcap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import pcapdb.core.engine.CapturePcapDevice;


public class CapturePcapFileTest {

    final static Logger logger = LoggerFactory.getLogger(CapturePcapDevice.class.getName());

    public static void main(String[] args) {
        /**
        MappedByteBufferLocater mappedByteBufferLocater = CapturePcapDevice.OpenFile("PcapDB.UTest/Pcaps/drda_db2_sample.cap");
        AbstractPacket pcapHeader = new PcapHeader(mappedByteBufferLocater);
        logger.info(pcapHeader.toString());
        MappedByteBufferLocater payload = pcapHeader.getPayload();
        while (payload.hasRemaining()){
            Packet packet = new Packet(payload);

            logger.info(packet.toString());
            packet.Decoder();
            payload=packet.getNextPacket();
        }
         **/
        String file = "PcapDB.UTest/Pcaps/drda_db2_sample.cap";
        Pcap pcap = CapturePcapDevice.PcapOpenFile(file);
    }
}
