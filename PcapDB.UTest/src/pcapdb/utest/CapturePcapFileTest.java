package pcapdb.utest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import pcapdb.core.buffer.MappedByteBufferLocater;
import pcapdb.core.engine.CapturePcapFile;
import pcapdb.core.frame.PcapHeaderFrame;
import pcapdb.core.packet.PcapHeader;

import java.io.File;

public class CapturePcapFileTest {

    protected final static Logger logger = LoggerFactory.getLogger(CapturePcapFile.class.getName());

    public static void main(String[] args) {
        MappedByteBufferLocater mappedByteBufferLocater = CapturePcapFile.OpenFile("PcapDB.UTest/Pcaps/drda_db2_sample.cap");
        PcapHeader pcapHeader = new PcapHeader(mappedByteBufferLocater);

        logger.info(pcapHeader.toString());


    }
}
