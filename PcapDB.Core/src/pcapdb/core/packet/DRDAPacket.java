package pcapdb.core.packet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pcapdb.core.buffer.MappedByteBufferLocater;

public class DRDAPacket extends AbstractPacket {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass().getName());

    public DRDAPacket(MappedByteBufferLocater _mappedByteBufferLocater, AbstractPacket _packet) {
        super(_mappedByteBufferLocater, _packet);
    }

    @Override
    public MappedByteBufferLocater getPayload() {
        return null;
    }
}
