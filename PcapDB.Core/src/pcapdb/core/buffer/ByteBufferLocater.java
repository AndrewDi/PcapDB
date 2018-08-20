package pcapdb.core.buffer;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * This class is the basic bytebuffer to decode packet
 *
 * @author PanDi(anonymous-oss@outlook.com)
 */
public class ByteBufferLocater extends AbstractLocater {
    private ByteBuffer byteBuffer;

    /**
     * Hex array was used to print byte string
     * @see "getByteString(int offset, int length, ByteOrder byteOrder)"
     */
    private final char[] hexArray = "0123456789ABCDEF".toCharArray();

    /**
     * e2aTable was used to convert Ebcdic To Ascii String
     * @see "EbcdicToAscii(byte[] data, int length)"
     */
    private final int[] e2aTable = new int[]{
            0, 1, 2, 3, 156, 9, 134, 127, 151, 141, 142, 11, 12, 13, 14, 15,
            16, 17, 18, 19, 157, 133, 8, 135, 24, 25, 146, 143, 28, 29, 30, 31,
            128, 129, 130, 131, 132, 10, 23, 27, 136, 137, 138, 139, 140, 5, 6, 7,
            144, 145, 22, 147, 148, 149, 150, 4, 152, 153, 154, 155, 20, 21, 158, 26,
            32, 160, 161, 162, 163, 164, 165, 166, 167, 168, 91, 46, 60, 40, 43, 33,
            38, 169, 170, 171, 172, 173, 174, 175, 176, 177, 93, 36, 42, 41, 59, 94,
            45, 47, 178, 179, 180, 181, 182, 183, 184, 185, 124, 44, 37, 95, 62, 63,
            186, 187, 188, 189, 190, 191, 192, 193, 194, 96, 58, 35, 64, 39, 61, 34,
            195, 97, 98, 99, 100, 101, 102, 103, 104, 105, 196, 197, 198, 199, 200, 201,
            202, 106, 107, 108, 109, 110, 111, 112, 113, 114, 203, 204, 205, 206, 207, 208,
            209, 126, 115, 116, 117, 118, 119, 120, 121, 122, 210, 211, 212, 213, 214, 215,
            216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231,
            123, 65, 66, 67, 68, 69, 70, 71, 72, 73, 232, 233, 234, 235, 236, 237,
            125, 74, 75, 76, 77, 78, 79, 80, 81, 82, 238, 239, 240, 241, 242, 243,
            92, 159, 83, 84, 85, 86, 87, 88, 89, 90, 244, 245, 246, 247, 248, 249,
            48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 250, 251, 252, 253, 254, 255
    };

    /**
     * The length of this locater can read,not all packet use this length
     */
    private int length;

    /**
     * The absolute offset in pcap file
     */
    private int baseOffset;

    /**
     * Use @see ByteBuffer with new offset to build another ByteBufferLocater
     * @param mappedByteBuffer current ByteBuffer
     * @param baseOffset new offset
     */
    public ByteBufferLocater(ByteBuffer mappedByteBuffer, int baseOffset) {
        this.byteBuffer = mappedByteBuffer;
        this.baseOffset = baseOffset;

        //Current only support little endian
        this.byteBuffer.order(ByteOrder.LITTLE_ENDIAN);
    }

    /**
     * Use @see ByteBufferLocater with new offset to build another ByteBufferLocater
     * @param byteBufferLocater current ByteBufferLocater
     * @param baseoffset new offset
     */
    public ByteBufferLocater(ByteBufferLocater byteBufferLocater, int baseoffset) {
        this(byteBufferLocater.byteBuffer, baseoffset);
    }

    /**
     * Return current ByteBufferLocater Length
     * @return current length
     */
    public int getLength() {
        return length;
    }

    /**
     * Set ByteBufferLocater Length
     * @param length new length
     */
    public void setLength(int length) {
        this.length = length;
    }

    /**
     * Return current base offset
     * @return
     */
    public int getBaseOffset() {
        return baseOffset;
    }

    /**
     * Return Is there still bytes can read in pcap files
     * @return true or false
     */
    public boolean hasRemaining() {
        return this.byteBuffer.capacity() > this.baseOffset;
    }

    /**
     * Decoder Int object(4 bytes/8 bits)
     * @param _offset offset
     * @param byteOrder BIG_ENDIAN or LITTLE_ENDIAN
     * @return int value
     */
    public int getInt(int _offset, ByteOrder byteOrder) {
        if (byteOrder == ByteOrder.BIG_ENDIAN)
            return getInt(_offset);
        else {
            return this.getByte(_offset + 3) & 0xFF |
                    (this.getByte(_offset + 2) & 0xFF) << 8 |
                    (this.getByte(_offset + 1) & 0xFF) << 16 |
                    (this.getByte(_offset) & 0xFF) << 24;
        }
    }

    /**
     * Decoder Int object in BIG_ENDIAN(4 bytes/8 bits)
     * @param offset offset
     * @return int value
     */
    public int getInt(int offset) {
        return this.byteBuffer.getInt(this.baseOffset + offset);
    }

    /**
     * Decoder short object in BIG_ENDIAN(2 bytes/4 bits)
     * @param offset offset
     * @return short value
     */
    public short getShort(int offset) {
        return this.byteBuffer.getShort(this.baseOffset + offset);
    }

    /**
     * Decoder short object(2 bytes/4 bits)
     * @param offset offset
     * @param byteOrder BIG_ENDIAN or LITTLE_ENDIAN
     * @return short value
     */
    public int getShort(int offset, ByteOrder byteOrder) {
        if (byteOrder == ByteOrder.BIG_ENDIAN)
            return getShort(offset);
        else {
            return this.getByte(offset + 1) & 0xFF | (this.getByte(offset) & 0xFF) << 8;
        }
    }

    /**
     * Decoder single byte object
     * @param offset offset
     * @return int value
     */
    public int getSingle(int offset) {
        return this.getByte(offset) & 0xFF;
    }

    /**
     * Decoder long object in BIG_ENDIAN(2 bytes/4 bits)
     * @param offset offset
     * @return long value
     */
    public long getLong(int offset) {
        return this.byteBuffer.getLong(this.baseOffset + offset);
    }

    /**
     * Return one byte
     * @param offset offset
     * @return byte value
     */
    public byte getByte(int offset) {
        return this.byteBuffer.get(this.baseOffset + offset);
    }

    /**
     * Return one byte
     * @param offset offset
     * @return byte value in String format
     */
    public String getByteStrig(int offset) {
        return getByteString(offset, 1, ByteOrder.LITTLE_ENDIAN);
    }

    /**
     * Return @length bytes
     * @param offset offset
     * @param length length
     * @return @length bytes
     */
    public byte[] getBytes(int offset, int length) {
        byte[] bytesData = new byte[length];
        for (int i = 0; i < length; i++) {
            bytesData[i] = this.byteBuffer.get(this.baseOffset + offset + i);
        }
        return bytesData;
    }

    /**
     * Retrun bytes in String Format
     * @param offset offset
     * @param length length
     * @param byteOrder  BIG_ENDIAN or LITTLE_ENDIAN
     * @return String format bytes
     */
    public String getByteString(int offset, int length, ByteOrder byteOrder) {
        char[] hexChars = new char[length * 2];
        for (int j = 0; j < length; j++) {
            //Fix byte order error,maybe there is another way
            int v;
            if (byteOrder == ByteOrder.BIG_ENDIAN) {
                v = this.byteBuffer.get(this.baseOffset + offset + (length - j - 1)) & 0xFF;
            } else {
                v = this.byteBuffer.get(this.baseOffset + offset + j) & 0xFF;
            }
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    /**
     * Decoder bytes into ASCII UTF8 String
     * @param offset offset
     * @param length length
     * @return ASCII UTF8 String
     */
    public String getUTF8String(int offset, int length) {
        byte[] data = this.getBytes(offset, length);
        for (int i=0;i<data.length;i++){
            if((data[i] & 0xFF) == 0x00||(data[i] & 0xFF) == 0xFF){
                data[i]=0x20;
                continue;
            }
        }
        return new String(data);
    }

    /**
     * Decoder bytes into ASCII UTF8 String(Convert from EBCDIC)
     * @param offset offset
     * @param length length
     * @return ASCII UTF8 String
     */
    public String getEbcdicString(int offset, int length) {
        return EbcdicToAscii(this.getBytes(offset, length), length);
    }

    /**
     * Convert EBCDIC to ASCII String
     * @param data data to convert
     * @param length length
     * @return ASCII UTF8 String
     */
    public String EbcdicToAscii(byte[] data, int length) {
        byte[] byteData = new byte[length];
        for (int i = 0; i < data.length; i++) {
            if ((data[i] & 0xFF) == 0x00||(data[i] & 0xFF) == 0xFF) {
                byteData[i] = 0x20;
                continue;
            }
            byteData[i] = (byte) e2aTable[data[i] & 0xFF];
        }
        return new String(byteData);
    }

    public char getChar(int offset) {
        return this.byteBuffer.getChar(this.baseOffset + offset);
    }

    public long getPhysicOffset() {
        return this.byteBuffer.position();
    }

    /**
     * Decoder Unsigned int value
     * @param offset offset
     * @return long value
     */
    public long getUnsignedInt(int offset) {
        return this.getInt(offset) & 0xFFFFFFFFL;
    }

    /**
     * Decoder Unsigned int value
     * @param offset offset
     * @param byteOrder BIG_ENDIAN or LITTLE_ENDIAN
     * @return long value
     */
    public long getUnsignedInt(int offset, ByteOrder byteOrder) {
        return this.getInt(offset, byteOrder) & 0xFFFFFFFFL;
    }

    public long unsignedInt(final byte a, final byte b, final byte c, final byte d) {
        return (a & 0xff) << 24 | (b & 0xff) << 16 | (c & 0xff) << 8 | d & 0xff;
    }

    public int getUnsignedShort(int offset) {
        return getShort(offset) & 0xFFFF;
    }
}
