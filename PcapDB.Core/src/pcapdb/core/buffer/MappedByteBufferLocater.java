package pcapdb.core.buffer;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.MappedByteBuffer;

public class MappedByteBufferLocater extends AbstractLocater {
    private MappedByteBuffer mappedByteBuffer;

    private int baseOffset;

    public MappedByteBufferLocater(MappedByteBuffer _mappedByteBuffer, int _baseOffset){
        this.mappedByteBuffer=_mappedByteBuffer;
        this.baseOffset=_baseOffset;

        //Current only support little endian
        this.mappedByteBuffer.order(ByteOrder.LITTLE_ENDIAN);
    }

    public void resetBaseOffset(){
        this.baseOffset=0;
    }

    public int getRemainLength(){
        return this.mappedByteBuffer.remaining();
    }

    public int getInt(int _offset){
        return this.mappedByteBuffer.getInt(this.baseOffset+_offset);
    }

    public short getShort(int _offset){
        return this.mappedByteBuffer.getShort(this.baseOffset+_offset);
    }

    public long getLong(int _offset){
        return this.mappedByteBuffer.getLong(this.baseOffset+_offset);
    }

    public ByteBuffer getByteBuffer(byte[] bytes, int offset,int length){
        return this.mappedByteBuffer.get(bytes,offset,length);
    }

    public String getByteString(int offset,int length){
        char[] hexArray = "0123456789ABCDEF".toCharArray();
        byte[] bytes = new byte[length];
        this.mappedByteBuffer.get(bytes,offset,length);
        char[] hexChars = new char[length * 2];
        for ( int j = 0; j < length; j++ ) {
            //Fix byte order error,maybe there is another way
            int v = bytes[length-j-1] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    public char getChar(int _offset){
        return this.mappedByteBuffer.getChar(this.baseOffset+_offset);
    }

    public MappedByteBufferLocater getPayload(int _startIndex){
        return new MappedByteBufferLocater(this.mappedByteBuffer,_startIndex);
    }

    public long getPhysicOffset(){
        return this.mappedByteBuffer.position();
    }

    public long getUnsignedInt(int _offset){
        return this.getInt(_offset) & 0xFFFFFFFFL;
    }

    public long unsignedInt(final byte a, final byte b, final byte c, final byte d) {
        return (a & 0xff) << 24 | (b & 0xff) << 16 | (c & 0xff) << 8 | d & 0xff;
    }

    public int getUnsignedShort(int _offset) {
        return getShort(_offset) & 0xFFFF;
    }
}
