package pcapdb.core.frame;

public class DrdaFrame {
    public static int DDMLengthLength = 2;

    public static int DDMMagicLength = 1;

    public static int DDMFormatLength = 1;

    public static int DDMCorrelIdLength = 2;

    public static int DDMLength2Length = 2;

    public static int DDMCodePointLength = 2;

    public static int DDMLengthPosition = 0 ;

    public static int DDMMagicPosition;

    public static int DDMFormatPosition;

    public static int DDMCorrelIdPosition;

    public static int DDMLength2Position;

    public static int DDMCodePointPosition;

    public static int totalLength;

    //Extra Parameter Length
    public static int DDMParameterLengthLength = 2;

    public static int DDMParameterCodePointLength = 2;

    static {
        DDMMagicPosition = DDMLengthPosition+DDMLengthLength;
        DDMFormatPosition = DDMMagicPosition+DDMMagicLength;
        DDMCorrelIdPosition = DDMFormatPosition+DDMFormatLength;
        DDMLength2Position = DDMCorrelIdPosition+DDMCorrelIdLength;
        DDMCodePointPosition=DDMLength2Position+DDMLength2Length;
        totalLength = DDMCodePointPosition+DDMCodePointLength;
    }
}
