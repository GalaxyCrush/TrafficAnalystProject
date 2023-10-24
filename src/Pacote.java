import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Classe que representa a abstracao de um pacote
 */
public class Pacote {

    private String numb;
    private String time;
    private String srcIP;
    private String destIP;
    private String srcPort;
    private String destPort;
    private String protocol;
    private String icmpType;
    private String length;
    private String flag;
    private HashMap<String, String> pacoteComb = new HashMap<>();// Hashmap que contem as traducoes das flags

    /**
     * Construtor de um pacote
     * 
     * @param data toda a informacao necessaria para formar um pacote
     */
    public Pacote(String data) {
        String[] info = data.split(",");
        this.numb = info[0];
        this.time = info[1];
        this.srcIP = info[2];
        this.destIP = info[3];
        this.srcPort = info[4];
        this.destPort = info[5];
        this.protocol = info[6];
        this.icmpType = info[7];
        this.length = info[8];
        this.flag = info[9];
        pacoteComb.put("0x012", "SYN/ACK");
        pacoteComb.put("0x014", "RST/ACK");
        pacoteComb.put("0x018", "PSH/ACK");
        pacoteComb.put("0x029", "FIN/PSH/URG");
        pacoteComb.put("0x019", "FIN/PSH/ACK");
        pacoteComb.put("0x011", "FIN/ACK");
        pacoteComb.put("0x020", "URG");
        pacoteComb.put("0x010", "ACK");
        pacoteComb.put("0x008", "PSH");
        pacoteComb.put("0x004", "RST");
        pacoteComb.put("0x002", "SYN");
        pacoteComb.put("0x001", "FIN");
        pacoteComb.put("0x0c2", "SYN/ECN/CWR");
        pacoteComb.put("0x000", "NULL");
        pacoteComb.put("", "NoFlag");
    }

    /**
     * Uma funcao auxiliar para deletar os "" de uma string
     * 
     * @param s1 A string desejada
     * @return A string sem as aspas
     */
    private String fldeleter(String s1) {
        StringBuilder s = new StringBuilder(s1);
        s.deleteCharAt(0);
        s.deleteCharAt(s.length() - 1);
        return s.toString();
    }

    /**
     * Funcao que retorna o numero do pacote
     * 
     * @return O numero do pacote
     */
    public int getNumb() {
        return Integer.parseInt(fldeleter(numb));
    }

    /**
     * Funcao que retorna o tempo em que o pacote se encontra
     * 
     * @return O tempo do pacote
     */
    public double getTime() {
        return Double.parseDouble(fldeleter(time));
    }

    /**
     * Funcao que retorna o IP de origem do pacote
     * 
     * @return O IP de origem
     */
    public String getSrcIP() {
        return fldeleter(srcIP);
    }

    /**
     * Funcao que retorna o IP de destino do pacote
     * 
     * @return O IP de destino
     */
    public String getDestIP() {
        return fldeleter(destIP);
    }

    /**
     * Funcao que retorna o Port de origem
     * 
     * @return O Port de origem
     */
    public String getSrcPort() {
        return fldeleter(srcPort);
    }

    /**
     * Funcao que retorna o Port de destino
     * 
     * @return O Port de destino
     */
    public String getDestPort() {
        return fldeleter(destPort);
    }

    /**
     * Funcao que retorna o protocolom do pacote
     * 
     * @return O protocolo
     */
    public String getProtocol() {
        return fldeleter(protocol);
    }

    /**
     * Funcao que retorna o tipo de icmp do pacote
     * 
     * @return O tipo de icmp
     */
    public String getIcmpType() {
        return fldeleter(icmpType);
    }

    /**
     * Funcao que retorna a dimensao do pacote
     * 
     * @return A dimensao do pacote
     */
    public int getLength() {
        return Integer.parseInt(fldeleter(length));
    }

    /**
     * Funcao que retorna as flags ativas num pacote
     * 
     * @return As flags ativas
     */
    public String getFlag() {
        if (pacoteComb.containsKey(fldeleter(this.flag))) {
            return this.pacoteComb.get(fldeleter(this.flag));
        }
        return fldeleter(this.flag);
    }

    /**
     * Funcao usada para determinar a versao dos IP
     * 
     * @param ip o ip a verificar
     * @return A versao do ip
     */
    public String ipType(String ip) {
        if (ip.contains(":") && !ip.contains(".") && !ip.contains("_") && !ip.contains("-")) {
            return "6";
        }
        if (checkIpV4(ip)) {
            return "4";
        }
        return "hostname";
    }

    /**
     * Funcao auxiliar para verificar se uma string corresponde a um IPv4
     * 
     * @param s A string a verficar
     * @return True ou False se a String corresponde ou nao respetivamente
     */
    private boolean checkIpV4(String s) {
        String numsTo255 = "(\\d{1,2}|(0|1)\\d{2}|2[0-4]\\d|25[0-5])";
        String ipv4 = numsTo255 + "\\." + numsTo255 + "\\." + numsTo255 + "\\." + numsTo255;
        Pattern ip = Pattern.compile(ipv4);
        Matcher verify = ip.matcher(s);
        return verify.matches();
    }
}
