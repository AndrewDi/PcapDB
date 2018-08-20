package pcapdb.core.engine;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapDumper;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pcapdb.core.buffer.MappedByteBufferLocater;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;

/**
 * This class is used to Open Pcap files
 *
 * @author PanDi(anonymous-oss@outlook.com)
 */
public class CapturePcapFile {

    final static Logger logger = LoggerFactory.getLogger(CapturePcapFile.class.getName());

    /**
     * Open file with MappedByteBuffer
     * @param path Full file path
     * @return Basic MappedByteBufferLocater object
     */
    public static MappedByteBufferLocater OpenFile(String path){
        try {
            logger.debug("Open Capture File: {}", path);
            RandomAccessFile randomAccessFile = new RandomAccessFile(path,"r");
            FileChannel fileChannel = randomAccessFile.getChannel();
            long fileSize = fileChannel.size();
            MappedByteBuffer mappedByteBuffer = fileChannel.map(FileChannel.MapMode.READ_ONLY,0,fileSize);
            return new MappedByteBufferLocater(mappedByteBuffer,0);
        }
        catch (IOException ex){
            logger.error(ex.getLocalizedMessage());
            return null;
        }
    }

    public static Pcap PcapOpenFile(String path){
        StringBuilder errbuf = new StringBuilder();
        Pcap pcap = Pcap.openOffline(path,errbuf);
        if(pcap==null){
            logger.error("Error while opening device for capture: {}",errbuf.toString());
            return null;
        }

        PacketBus packetBus = new PacketBus();
        PcapDBPacketHandler packetBusPcapDBPacketHandler = new PcapDBPacketHandler();
        try {
            pcap.loop(Pcap.LOOP_INFINITE,packetBusPcapDBPacketHandler,packetBus);
        }
        finally {
            pcap.close();
            //packetBus.stop();
        }
        return pcap;
    }
}
