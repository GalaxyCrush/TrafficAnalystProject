import java.io.File;
import java.io.FileNotFoundException;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Scanner;

/**
 * Programa que vai analisar um trace de uma rede
 * 
 * Para o progruma funcionar e ncessario os traces e a class Pacote.java estarem
 * no mesmo directorio.
 * Na execucao e necessario escrever como argumento o nome do trace que se
 * deseja analisar
 * Ex: java TrafficAnalysis.java traceX onde x representa o trace desejado
 */
public class TrafficAnalysis {

    public static ArrayList<Pacote> pacotes = new ArrayList<>();// Lista com todos os pacotes de um trace
    public static ArrayList<Pacote> pacotesTcp = new ArrayList<>();// Lista com todos os pacotes de protocolo tcp
    public static DecimalFormat df = new DecimalFormat("0.00");

    public static void main(String[] args) throws FileNotFoundException {
        analyzer(args[0]);
        for (Pacote aux : pacotes) {
            if (!aux.getFlag().isEmpty()) {
                pacotesTcp.add(aux);
            }
        }
        getAnswer();
    }

    /**
     * funcao que vai analizar o trace e guardar os pacotes numa lista
     * 
     * @param fileName O nome do ficheiro
     * @throws FileNotFoundException
     */
    public static void analyzer(String fileName) throws FileNotFoundException {
        Scanner sc = new Scanner(new File(fileName));
        sc.nextLine();// primeira linha não corresponde a um pacote
        while (sc.hasNextLine()) {
            pacotes.add(new Pacote(sc.nextLine()));
        }
    }

    // Begining of tcp functions----------------------------------------

    /**
     * Funcao que vai retornar uma lista com os portos existentes(nao repetidos)
     * 
     * @return Uma lista com os portos existentes
     */
    public static ArrayList<String> uniqueTCPport() {
        ArrayList<String> lista = new ArrayList<>();
        for (Pacote aux : pacotesTcp) {
            if (!lista.contains(aux.getSrcPort()) && !aux.getSrcPort().isEmpty()) {
                lista.add(aux.getSrcPort());
            }
        }
        lista.sort((x, y) -> Integer.parseInt(x) - Integer.parseInt(y));
        return lista;
    }

    /**
     * Funcao que vai filtrar os portos existentes para uma lista com os portos
     * estudados
     * 
     * @return Uma lista com os portos conhecidos e estudados
     */
    public static ArrayList<String> filtredTcp() {
        ArrayList<String> filtred = new ArrayList<>();
        for (String aux : uniqueTCPport()) {
            if (Integer.parseInt(aux) < 1024) {
                filtred.add(aux);
            }
        }
        return filtred;
    }

    /**
     * Funcao que vai verificar quantas ligacoes foram establecidas ao longo do
     * trace
     * 
     * @return O numero de ligacoes establecidas
     */
    public static int tcpCount() {
        HashSet<String> set = new HashSet<>();
        ArrayList<String> buffer = new ArrayList<>();
        for (Pacote aux : pacotesTcp) {
            // keys que representa os ips que se cominicam em dados portos
            String keySrc = aux.getSrcIP() + "/" + aux.getDestIP() + "/" + aux.getSrcPort() + "/" + aux.getDestPort();
            String keyDest = aux.getDestIP() + "/" + aux.getSrcIP() + "/" + aux.getDestPort() + "/" + aux.getSrcPort();
            if (aux.getFlag().equals("SYN")) {
                set.add(keySrc);
            } else if (aux.getFlag().equals("SYN/ACK")) {
                if (set.contains(keyDest)) {
                    set.add(keySrc);
                }
            } else if (aux.getFlag().equals("ACK")) {
                if (set.contains(keyDest) && set.contains(keySrc) && !buffer.contains(keyDest)
                        && !buffer.contains(keySrc)) {
                    // So vai adicionar a lista se os passos anteriores foram concluidos
                    buffer.add(keySrc);
                }
            }
        }
        return buffer.size();
    }

    // End of tcp functions-------------------------------------------------

    // Begining of packages functions---------------------------------------

    /**
     * Funcao que retorna o numero de pacotes existentes
     * 
     * @return O numero de pacotes existentes num trace
     */
    public static int getNumbPack() {
        return pacotes.size();
    }

    /**
     * Funcao que retorna o tempo total do trace
     * 
     * @return O tempo total de um trace
     */
    public static Double getTime() {
        return pacotes.get((getNumbPack() - 1)).getTime();
    }

    /**
     * Funcao que retorna o numero de pacotes com determinada versao de ip
     * 
     * @param version A versao que queremos verificar a quantidade de pacotes
     * @return o numero de pacotes com receptor e emissor de uma dada version
     */
    public static int getPacoteIp(String version) {// version assume valores 4, 6 ou hostname
        int count = 0;
        for (Pacote aux : pacotes) {
            if (aux.ipType(aux.getDestIP()).equals(version) && aux.ipType(aux.getSrcIP()).equals(version)) {
                count++;
            }
        }
        return count;
    }

    /**
     * Funcao que retorna o a length minima dos pacotes do trace
     * 
     * @return A lenght minima
     */
    public static int getMinLength() {
        int min = -1;
        for (Pacote aux : pacotes) {
            int length = aux.getLength();
            if (length < min || min == -1) {
                min = length;
            }
        }
        return min;
    }

    /**
     * Funcao que retorna a length maxima dos pacotes do trace
     * 
     * @return A lenght maxima
     */
    public static int getMaxLength() {
        int max = 0;
        for (Pacote aux : pacotes) {
            int length = aux.getLength();
            if (length > max) {
                max = length;
            }
        }
        return max;
    }

    /**
     * Funcao que returna um vetor com 2 valores sendo um deles (res[1]) o ultimo
     * index percorrido e
     * outra (res[0]) o numero de pacotes depois do index que tem tamanho menor que
     * o maximo dado
     *
     * @param max   tamanho maximo
     * @param index index a percorrer
     * @param lista lista de todos os pacotes ordenados por tamanho
     * @return
     */
    public static int[] percentageCalculator(int max, int index, ArrayList<Pacote> lista) {
        int[] res = { 0, index }; // esq = count ; direita = index
        while (lista.get(index).getLength() < max) {
            index++;
            res[0] += 1;
            res[1] += 1;
        }

        return res;
    }

    /**
     * Procedimento que calcula e imprime a percentagem de pacotes contida em cada
     * divisao tendo em conta a sua length
     */
    public static void printPercentage() {
        final int ndivisao = 10;
        int min = getMinLength();
        int max = getMaxLength();
        int tamanho = max - min;
        int parte = tamanho / ndivisao;
        ArrayList<Pacote> lista = pacotesOrd();
        int index = 0;
        for (int i = 0; i < ndivisao; i++) {
            int atual = min + parte * i; // minimo atual
            int[] num = percentageCalculator(atual + parte, index, lista); // num[0] = count ; num[1] = index
            System.out.println(
                    "entre " + atual + " e " + (atual + parte) + " = "
                            + df.format(((double) num[0] / getNumbPack() * 100))
                            + "% " + (num[0]) + " pacotes nesta gama");
            index = num[1];
        }
    }

    /**
     * Funcao que vai ordenar os pacotes por tamanho
     * 
     * @return Uma lista de pacotes ordenados por tamanho
     */
    private static ArrayList<Pacote> pacotesOrd() {
        ArrayList<Pacote> lista = pacotes;
        lista.sort((x, y) -> Integer.compare(x.getLength(), y.getLength()));
        return lista;
    }

    /**
     * funcao que retorna a media dos pacotes do trace
     * 
     * @return A media da length
     */
    public static Float getAvgLength() {
        float sum = 0;
        for (Pacote aux : pacotes) {
            sum += aux.getLength();
        }
        return sum / getNumbPack();
    }

    // End of packages functions----------------------------------------

    // Begining of icmp functions---------------------------------------

    /**
     * Funcao que retorna todos os tipos diferentes de icmp presentes no trace
     * 
     * @return Uma lista com os tipos de icmp
     */
    public static ArrayList<String> icmpTypes() {
        ArrayList<String> lista = new ArrayList<>();
        for (Pacote aux : pacotes) {
            String icmp = aux.getIcmpType();
            if (!lista.contains(icmp) && !icmp.isBlank()) {
                lista.add(icmp);
            }
        }
        lista.sort((x, y) -> (Integer.parseInt(x) - Integer.parseInt(y)));
        return lista;
    }

    /**
     * Funcao que retorna o numero de pacotes icmp
     * 
     * @return O numero de pacotes icmp
     */
    public static int icmpNumb() {
        ArrayList<Pacote> lista = new ArrayList<>();
        for (Pacote aux : pacotes) {
            if (!aux.getIcmpType().isBlank() && !lista.contains(aux)) {
                lista.add(aux);
            }
        }
        return lista.size();
    }

    // End of icmp functions----------------------------------------------

    // Begining of flags functions----------------------------------------
    /**
     * Funcao que vai verificar quais os pacotes que tentaram efetuar uma conexao
     * 
     * @return Uma lista com todos os pacotes que tentaram efetuar uma conexao
     */
    public static ArrayList<Pacote> synList() {
        ArrayList<Pacote> lista = new ArrayList<>();
        for (Pacote aux : pacotes) {
            if (aux.getFlag().equals("SYN")) {
                lista.add(aux);
            }
        }
        return lista;
    }

    /**
     * Funcao que verifica qual ip tenetou establecer mais vezes conexao
     * 
     * @return Uma lista contendo o ip que mais conexao tentou fazer
     */
    public static ArrayList<String> maiorSyn() {
        ArrayList<String> ip = new ArrayList<>();
        ArrayList<Integer> contador = new ArrayList<>();
        for (Pacote aux : synList()) {
            String src = aux.getSrcIP();
            if (!ip.contains(src)) {
                ip.add(src);
                contador.add(1);
            } else {
                contador.set(ip.indexOf(src), contador.get(ip.indexOf(src)) + 1);
            }
        }
        ArrayList<String> lista = new ArrayList<>();
        int maior = 0;
        for (int i = 0; i < contador.size(); i++) {
            if (contador.get(i) > maior) {
                if (!lista.isEmpty()) {
                    lista.clear();
                }
                lista.add(ip.get(i));
                maior = contador.get(i);
            } else if (contador.get(i) == maior) {
                // quando chegar aqui, a lista só ira ter ip que tentou establecer mais conexões
                lista.add(ip.get(i));
            }
        }
        // Numero de tentativas do ip
        lista.add(String.valueOf(maior));
        return lista;
    }
    // End of flags functions-------------------------------------------------

    // Begining of traffic functions------------------------------------------

    /**
     * Funcao que ira retornar um HashMap com todos os ips de origem acompanhados
     * de seus pacotes
     *
     * @return Um HashMap com ip como keys e pacotes como valores
     */
    public static HashMap<String, ArrayList<Pacote>> getAllSrcIp() {
        HashMap<String, ArrayList<Pacote>> map = new HashMap<>();
        for (Pacote aux : pacotes) {
            String ip = aux.getSrcIP();
            if (!map.containsKey(ip)) {
                ArrayList<Pacote> buffer = new ArrayList<>();
                buffer.add(aux);
                map.put(ip, buffer);
            } else if (map.containsKey(ip)) {
                ArrayList<Pacote> buffer = map.get(ip);
                buffer.add(aux);
                map.put(ip, buffer);
            }
        }
        return map;
    }

    /**
     * Funcao que irá retornar um HashMap com todos os ips de destino acompanhados
     * de seus pacotes
     * 
     * @return Um HashMap com ip como keys e pacotes como valores
     */
    public static HashMap<String, ArrayList<Pacote>> getAllDestIp() {
        HashMap<String, ArrayList<Pacote>> map = new HashMap<>();
        for (Pacote aux : pacotes) {
            String ip = aux.getDestIP();
            if (!map.containsKey(ip)) {
                ArrayList<Pacote> buffer = new ArrayList<>();
                buffer.add(aux);
                map.put(ip, buffer);
            } else if (map.containsKey(ip)) {
                ArrayList<Pacote> buffer = map.get(ip);
                buffer.add(aux);
                map.put(ip, buffer);
            }
        }
        return map;
    }

    /**
     * Funcao que vai fornecer certas estatisticas sobre o trace a analisar
     * respetivas ao ip emissor
     *
     * @return Um array com as informacoes desejadas
     */
    public static String[] getHigherTraficSrc() {
        HashMap<String, ArrayList<Pacote>> map = getAllSrcIp();
        int maxLength = 0;
        int maxCount = 0;
        String[] ipInfo = new String[4];
        for (String key : map.keySet()) {
            ArrayList<Pacote> pacotesSrc = map.get(key);
            int atual = 0;
            int count = 0;
            for (Pacote packege : pacotesSrc) {
                if (packege.getSrcIP().equals(key)) {
                    atual += packege.getLength();
                    count++;

                }
                if (maxLength < atual) {
                    maxLength = atual;
                    maxCount = count;
                    ipInfo[0] = key;// Ip com maior taxa de envio
                }
            }
        }
        ipInfo[1] = String.valueOf(maxLength);// numero de bytes enviados
        ipInfo[2] = String.valueOf(maxCount);// numero de pacotes enviados
        ipInfo[3] = String.valueOf(calculateDebit(ipInfo[0], maxLength));// debito
        return ipInfo;
    }

    /**
     * Funcao que vai fornecer certas estatisticas sobre o trace a analisar
     * respetivas ao ip recetor
     * 
     * @return Um array com as informacoes desejadas
     */
    public static String[] getHigherTraficDest() {
        HashMap<String, ArrayList<Pacote>> map = getAllDestIp();
        int maxLength = 0;
        int maxCount = 0;
        String[] ipinfo = new String[4];// 4 informacoes a guardar
        for (String key : map.keySet()) {
            ArrayList<Pacote> pacotesDst = map.get(key);
            int atual = 0;
            int count = 0;
            for (Pacote packege : pacotesDst) {
                if (packege.getDestIP().equals(key)) {
                    atual += packege.getLength();
                    count++;
                }
            }
            if (maxLength < atual) {
                maxLength = atual;
                maxCount = count;
                ipinfo[0] = key;// ip com maior taxa de recepcao
            }
        }
        ipinfo[1] = String.valueOf(maxLength);// numero de bytes recebidos
        ipinfo[2] = String.valueOf(maxCount);// numero de pacotes recebidos
        ipinfo[3] = String.valueOf(calculateDebit(ipinfo[0], maxLength));// debito
        return ipinfo;
    }

    /**
     * Funcao para calcular o troughtput de uma ligacao
     * 
     * @param ip        O ip a analisar
     * @param maxLength A quantidade total de bytes enviada
     * @return O troughtput
     */
    public static Float calculateDebit(String ip, int maxLength) {
        ArrayList<Pacote> lista1 = new ArrayList<>();
        for (Pacote packege : pacotes) {
            if (packege.getSrcIP().equals(ip)) {
                lista1.add(packege);
            }
        }
        Float timeSpent = (float) (((lista1.get(lista1.size() - 1).getTime() - lista1.get(0).getTime())) + 0f);
        return ((maxLength * 8) / timeSpent); // fazemos *8 para tornar em bits
    }

    // End of traffic functions---------------------------------------------------

    /**
     * Uma simples UI para obter a resposta pretendida
     */
    public static void getAnswer() {
        while (true) {
            Scanner sc = new Scanner(System.in);
            System.out.println("%-------------Projeto2-------------%");
            System.out.println("1-Pergunta 1");
            System.out.println("2-Pergunta 2");
            System.out.println("3-Pergunta 3");
            System.out.println("4-Pergunta 4");
            System.out.println("5-Pergunta 5");
            System.out.println("6-Pergunta 6");
            System.out.println("7-Pergunta 7");
            System.out.println("8-Pergunta 8");
            System.out.println("9-Pergunta 9");
            System.out.println("0-Sair do programa");
            System.out.println();
            System.out.println("Escolha a sua opcao: ");
            int pergunta = sc.nextInt();
            switch (pergunta) {
                case 0:
                    System.exit(0);
                    sc.close();
                    break;
                case 1:
                    System.out.println();
                    System.out.println("Numero de pacotes ipv4 ");
                    System.out.println(getPacoteIp("4"));
                    System.out.println("Numero de pacotes ipv6");
                    System.out.println(getPacoteIp("6"));
                    System.out.println("Numero de pacotes hostname ");
                    System.out.println(getPacoteIp("hostname"));
                    System.out.println();
                    break;
                case 2:
                    DecimalFormat fd = new DecimalFormat("#.00");
                    System.out.println();
                    System.out.println("Tempo total: ");
                    System.out.println(fd.format(getTime()) + " s");
                    System.out.println("Numero de pacotes: ");
                    System.out.println(getNumbPack());
                    System.out.println();
                    break;
                case 3:
                    System.out.println();
                    System.out.println("Portos conhecidos: ");
                    System.out.println(filtredTcp());
                    System.out.println("Numero de portos unicos");
                    System.out.println(uniqueTCPport().size());
                    System.out.println();
                    break;
                case 4:
                    System.out.println();
                    System.out.println("Numero de icmp: ");
                    System.out.println(icmpNumb());
                    System.out.println("Icmtp types");
                    System.out.println(icmpTypes());
                    System.out.println();
                    System.out.println();
                    break;
                case 5:
                    System.out.println();
                    System.out.println("Tamanho medio: ");
                    System.out.println(df.format(getAvgLength()));
                    System.out.println("Tamanho minimo: ");
                    System.out.println(getMinLength());
                    System.out.println("Tamanho maximo: ");
                    System.out.println(getMaxLength());
                    System.out.println();
                    System.out.println("Histograma");
                    printPercentage();
                    System.out.println();
                    break;
                case 6:
                    System.out.println();
                    System.out.println("Numero de SYN");
                    System.out.println(synList().size());
                    System.out.println("Ip com maior numero de chamadas SYN");
                    System.out.println(maiorSyn().get(0) + " ," + maiorSyn().get(1) + " tentativas.");
                    System.out.println();
                    break;
                case 7:
                    System.out.println();
                    System.out.println("Numero de ligacoes tcp");
                    System.out.println(tcpCount());
                    System.out.println();
                    break;
                case 8:
                    String[] aux = getHigherTraficDest();
                    System.out.println();
                    System.out.println("Info sobre o trafico dest");
                    System.out.println();
                    System.out.println("IP com maior taxa de recepcao");
                    System.out.println(aux[0]);
                    System.out.println("Numero de bytes ");
                    System.out.println(aux[1]);
                    System.out.println("Numero de pacotes ");
                    System.out.println(aux[2]);
                    System.out.println("Throughtput");
                    System.out.println(df.format(Double.parseDouble(aux[3])));
                    System.out.println();
                    break;
                case 9:
                    String[] aux1 = getHigherTraficSrc();
                    System.out.println();
                    System.out.println("Info sobre o trafico src");
                    System.out.println();
                    System.out.println("IP com maior taxa de envio");
                    System.out.println(aux1[0]);
                    System.out.println("Numero de bytes ");
                    System.out.println(aux1[1]);
                    System.out.println("Numero de pacotes ");
                    System.out.println(aux1[2]);
                    System.out.println("Throughtput");
                    System.out.println(df.format(Double.parseDouble(aux1[3])));
                    System.out.println();
                    break;
            }
        }
    }
}