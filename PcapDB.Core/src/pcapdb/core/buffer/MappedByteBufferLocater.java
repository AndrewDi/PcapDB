package pcapdb.core.buffer;

import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;

public class MappedByteBufferLocater extends AbstractLocater {
    private MappedByteBuffer mappedByteBuffer;

    private int baseOffset;
    private int currentRelativeOffset;

    public MappedByteBufferLocater(MappedByteBuffer _mappedByteBuffer, int _baseOffset, int _currentRelativeOffset){
        this.mappedByteBuffer=_mappedByteBuffer;
        this.baseOffset=_baseOffset;
        this.currentRelativeOffset=_currentRelativeOffset;
    }

    public int getRemainLength(){
        return this.mappedByteBuffer.array().length-this.mappedByteBuffer.arrayOffset();
    }

    public int getInt(){
        return this.mappedByteBuffer.getInt();
    }

    public short getShort(){
        return this.mappedByteBuffer.getShort();
    }

    public long getLong(){
        return this.mappedByteBuffer.getLong();
    }

    public ByteBuffer getByteBuffer(byte[] bytes, int offset,int length){
        return this.mappedByteBuffer.get(bytes,offset,length);
    }

    public char getChar(){
        return this.mappedByteBuffer.getChar();
    }

    public MappedByteBufferLocater getPayload(){
        return new MappedByteBufferLocater(this.mappedByteBuffer,this.currentRelativeOffset,0);
    }
}
