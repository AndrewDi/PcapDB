package pcapdb.core.packet;

import pcapdb.core.buffer.ByteBufferLocater;
import pcapdb.core.buffer.MappedByteBufferLocater;

/**
 * All packet should extends on this abstract packets
 *
 * @author PanDi(anonymous-oss@outlook.com)
 */
public abstract class AbstractPacket {
    ByteBufferLocater byteBufferLocater;

    AbstractPacket parent =null;

    public AbstractPacket getParent() {
        return parent;
    }

    AbstractPacket(){}

    AbstractPacket(ByteBufferLocater byteBufferLocater, AbstractPacket abstractPacket){
        this.byteBufferLocater = byteBufferLocater;
        this.parent = abstractPacket;
    }

    AbstractPacket(ByteBufferLocater byteBufferLocater){
        this.byteBufferLocater = byteBufferLocater;
    }

    public abstract ByteBufferLocater getPayload();

}
