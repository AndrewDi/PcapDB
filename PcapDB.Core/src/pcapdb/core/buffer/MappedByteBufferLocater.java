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

    public MappedByteBufferLocater(MappedByteBufferLocater _mappedByteBufferLocater,int _baseoffset){
        this(_mappedByteBufferLocater.mappedByteBuffer,_baseoffset);
    }

    public int getBaseOffset() {
        return baseOffset;
    }

    public void resetBaseOffset(){
        this.baseOffset=0;
    }

    public boolean hasRemaining(){
        return this.mappedByteBuffer.capacity()>this.baseOffset;
    }

    public int getRemainLength(){
        return this.mappedByteBuffer.remaining();
    }

    public int getInt(int _offset,ByteOrder byteOrder){
        if(byteOrder==ByteOrder.BIG_ENDIAN)
            return getInt(_offset);
        else {
            return this.getByte(_offset+3) & 0xFF |
                    (this.getByte(_offset+2) & 0xFF )<<8 |
                    (this.getByte(_offset+1) & 0xFF )<<16 |
                    (this.getByte(_offset) & 0xFF )<<24;
        }
    }

    public int getInt(int _offset){
        return this.mappedByteBuffer.getInt(this.baseOffset+_offset);
    }

    public short getShort(int _offset){
        return this.mappedByteBuffer.getShort(this.baseOffset+_offset);
    }

    public int getShort(int _offset,ByteOrder byteOrder){
        if(byteOrder==ByteOrder.BIG_ENDIAN)
            return getShort(_offset);
        else{
            return this.getByte(_offset+1) & 0xFF | (this.getByte(_offset) & 0xFF) <<8;
        }
    }

    public int getSingle(int _offset){
        return this.getByte(_offset) & 0xFF;
    }

    public long getLong(int _offset){
        return this.mappedByteBuffer.getLong(this.baseOffset+_offset);
    }

    public byte getByte(int offset){
        return this.mappedByteBuffer.get(this.baseOffset+offset);
    }

    public byte[] getBytes(int offset,int length){
        byte[] bytesData = new byte[length];
        for (int i = 0; i < length; i++) {
            bytesData[i] = this.mappedByteBuffer.get(this.baseOffset+offset+i);
        }
        return bytesData;
    }

    public String getByteString(int offset,int length, ByteOrder byteOrder){
        char[] hexArray = "0123456789ABCDEF".toCharArray();
        //byte[] bytes = new byte[length];
        //this.mappedByteBuffer.get(bytes,offset,length);
        char[] hexChars = new char[length * 2];
        for ( int j = 0; j < length; j++ ) {
            //Fix byte order error,maybe there is another way
            int v;
            if(byteOrder==ByteOrder.BIG_ENDIAN) {
                v = this.mappedByteBuffer.get(this.baseOffset+offset+(length - j - 1)) & 0xFF;
            }
            else{
                v = this.mappedByteBuffer.get(this.baseOffset+offset+j) & 0xFF;
            }
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    public char getChar(int _offset){
        return this.mappedByteBuffer.getChar(this.baseOffset+_offset);
    }

    public long getPhysicOffset(){
        return this.mappedByteBuffer.position();
    }

    public long getUnsignedInt(int _offset){
        return this.getInt(_offset) & 0xFFFFFFFFL;
    }

    public long getUnsignedInt(int _offset,ByteOrder byteOrder){
        return this.getInt(_offset,byteOrder) & 0xFFFFFFFFL;
    }

    public long unsignedInt(final byte a, final byte b, final byte c, final byte d) {
        return (a & 0xff) << 24 | (b & 0xff) << 16 | (c & 0xff) << 8 | d & 0xff;
    }

    public int getUnsignedShort(int _offset) {
        return getShort(_offset) & 0xFFFF;
    }
}
