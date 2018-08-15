package pcapdb.core.engine;

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

    protected final static Logger logger = LoggerFactory.getLogger(CapturePcapFile.class.getName());

    /**
     * Open file with MappedByteBuffer
     * @param _path Full file path
     * @return Basic MappedByteBufferLocater object
     */
    public static MappedByteBufferLocater OpenFile(String _path){
        try {
            logger.debug("Open Capture File: {}", _path);
            RandomAccessFile randomAccessFile = new RandomAccessFile(_path,"r");
            FileChannel fileChannel = randomAccessFile.getChannel();
            long fileSize = fileChannel.size();
            MappedByteBuffer mappedByteBuffer = fileChannel.map(FileChannel.MapMode.READ_ONLY,0,fileSize);
            MappedByteBufferLocater mappedByteBufferLocater = new MappedByteBufferLocater(mappedByteBuffer,0);
            return mappedByteBufferLocater;
        }
        catch (IOException ex){
            logger.error(ex.getLocalizedMessage());
            return null;
        }
    }
}
