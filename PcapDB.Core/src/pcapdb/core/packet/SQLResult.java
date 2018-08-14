package pcapdb.core.packet;

public class SQLResult {



    private int sqlCode;

    private String sqlState;

    private String sqlErrProc;

    public SQLResult(int sqlCode, String sqlState, String sqlErrProc) {
        this.sqlCode = sqlCode;
        this.sqlState = sqlState;
        this.sqlErrProc = sqlErrProc;
    }

    public int getSqlCode() {
        return sqlCode;
    }

    public void setSqlCode(int sqlCode) {
        this.sqlCode = sqlCode;
    }

    public String getSqlState() {
        return sqlState;
    }

    public void setSqlState(String sqlState) {
        this.sqlState = sqlState;
    }

    public String getSqlErrProc() {
        return sqlErrProc;
    }

    public void setSqlErrProc(String sqlErrProc) {
        this.sqlErrProc = sqlErrProc;
    }

    @Override
    public String toString() {
        return "SQLResult{" +
                "sqlCode=" + sqlCode +
                ", sqlState='" + sqlState + '\'' +
                ", sqlErrProc='" + sqlErrProc + '\'' +
                '}';
    }
}
