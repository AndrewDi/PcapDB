package pcapdb.core.packet;

import pcapdb.core.frame.DrdaCodePointType;

public class DrdaDDMParameter {
    private int length;

    private DrdaCodePointType drdaCodePointType;

    private String data;

    public int getLength() {
        return length;
    }

    public void setLength(int length) {
        this.length = length;
    }

    public DrdaCodePointType getDrdaCodePointType() {
        return drdaCodePointType;
    }

    public void setDrdaCodePointType(DrdaCodePointType drdaCodePointType) {
        this.drdaCodePointType = drdaCodePointType;
    }

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }

    @Override
    public String toString() {
        return "DrdaDDMParameter{" +
                "length=" + length +
                ", drdaCodePointType=" + drdaCodePointType +
                ", data='" + data + '\'' +
                '}';
    }
}
