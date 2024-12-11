public class clientTest {
    public static void main(String[] args) throws Exception {
        client_shp_phase1 test = new client_shp_phase1("test123", "sporting", "ola", "1000");
        test.startConnection(null, 12345);
    }
}
