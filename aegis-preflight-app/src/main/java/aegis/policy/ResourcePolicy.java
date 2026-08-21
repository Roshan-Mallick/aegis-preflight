package aegis.policy;

import java.util.Map;

public class ResourcePolicy {

    private String memory;
    private String cpus;
    private String tmpfsSize;
    private int pidsLimit;
    private Map<String, Integer> ulimits;

    public String getMemory() {
        return memory;
    }

    public void setMemory(String memory) {
        this.memory = memory;
    }

    public String getCpus() {
        return cpus;
    }

    public void setCpus(String cpus) {
        this.cpus = cpus;
    }

    public String getTmpfsSize() {
        return tmpfsSize;
    }

    public void setTmpfsSize(String tmpfsSize) {
        this.tmpfsSize = tmpfsSize;
    }

    public int getPidsLimit() {
        return pidsLimit;
    }

    public void setPidsLimit(int pidsLimit) {
        this.pidsLimit = pidsLimit;
    }

    public Map<String, Integer> getUlimits() {
        return ulimits;
    }

    public void setUlimits(Map<String, Integer> ulimits) {
        this.ulimits = ulimits;
    }
}
