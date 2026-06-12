import java.io.*;
import java.util.*;

public class SecurityLogAnalyzer {

    public static void main(String[] args) {
        String inputFile = "server_log.txt";
        String outputFile = "suspicious_activity.txt";

        List<String> failedLogins = new ArrayList<>();

        // =============================================
        // LANGKAH 1: Baca File Log dengan BufferedReader
        // =============================================
        System.out.println("=== Sistem Log Keamanan & Analisis Peretas ===");
        System.out.println("Membaca file log: " + inputFile);

        try (BufferedReader reader = new BufferedReader(new FileReader(inputFile))) {
            String line;

            // =============================================
            // LANGKAH 2: Filter baris yang mengandung "FAILED"
            // =============================================
            while ((line = reader.readLine()) != null) {
                if (line.contains("FAILED")) {
                    failedLogins.add(line);
                }
            }

            System.out.println("Selesai membaca file log.");
            System.out.println("Ditemukan " + failedLogins.size() + " percobaan login gagal.\n");

        } catch (FileNotFoundException e) {
            System.out.println("[ERROR] File tidak ditemukan: " + inputFile);
            System.out.println("Pastikan file server_log.txt ada di direktori yang sama.");
            return;
        } catch (IOException e) {
            System.out.println("[ERROR] Gagal membaca file: " + e.getMessage());
            return;
        }

        // =============================================
        // LANGKAH 3: Tulis Laporan ke suspicious_activity.txt
        // =============================================
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputFile))) {

            writer.write("============================================");
            writer.newLine();
            writer.write("   LAPORAN AKTIVITAS MENCURIGAKAN - SERVER");
            writer.newLine();
            writer.write("============================================");
            writer.newLine();
            writer.write("Tanggal Generate: " + new java.util.Date());
            writer.newLine();
            writer.write("--------------------------------------------");
            writer.newLine();
            writer.newLine();

            writer.write("Daftar Percobaan Login yang GAGAL:");
            writer.newLine();
            writer.write("--------------------------------------------");
            writer.newLine();

            // Tulis semua baris login gagal
            for (String failedLine : failedLogins) {
                writer.write(failedLine);
                writer.newLine();
            }

            writer.newLine();
            writer.write("--------------------------------------------");
            writer.newLine();

            // =============================================
            // LANGKAH 4 (FITUR TAMBAHAN): Hitung total login gagal
            // dan rangkuman per IP Address
            // =============================================
            int totalGagal = failedLogins.size();

            // Hitung frekuensi per IP Address
            Map<String, Integer> ipCount = new LinkedHashMap<>();
            Map<String, Integer> userCount = new LinkedHashMap<>();

            for (String entry : failedLogins) {
                // Format: 2026-06-04 08:01:45 | FAILED | user: unknown | IP: 103.45.21.9
                String[] parts = entry.split("\\|");

                if (parts.length >= 4) {
                    // Ambil IP
                    String ipPart = parts[3].trim(); // "IP: 103.45.21.9"
                    String ip = ipPart.replace("IP:", "").trim();
                    ipCount.put(ip, ipCount.getOrDefault(ip, 0) + 1);

                    // Ambil Username
                    String userPart = parts[2].trim(); // "user: unknown"
                    String user = userPart.replace("user:", "").trim();
                    userCount.put(user, userCount.getOrDefault(user, 0) + 1);
                }
            }

            // Tulis rangkuman
            writer.write("RANGKUMAN LAPORAN:");
            writer.newLine();
            writer.write("Total Percobaan Login Gagal : " + totalGagal);
            writer.newLine();
            writer.newLine();

            writer.write("Frekuensi Gagal per IP Address:");
            writer.newLine();
            for (Map.Entry<String, Integer> entry : ipCount.entrySet()) {
                writer.write("  - IP " + entry.getKey() + " : " + entry.getValue() + " kali");
                writer.newLine();
            }

            writer.newLine();
            writer.write("Frekuensi Gagal per Username:");
            writer.newLine();
            for (Map.Entry<String, Integer> entry : userCount.entrySet()) {
                writer.write("  - User \"" + entry.getKey() + "\" : " + entry.getValue() + " kali");
                writer.newLine();
            }

            writer.newLine();
            writer.write("============================================");
            writer.newLine();
            writer.write("          AKHIR LAPORAN KEAMANAN");
            writer.newLine();
            writer.write("============================================");

            System.out.println("Laporan berhasil disimpan ke: " + outputFile);
            System.out.println("\n=== RANGKUMAN ===");
            System.out.println("Total login gagal   : " + totalGagal);
            System.out.println("Frekuensi per IP    :");
            for (Map.Entry<String, Integer> entry : ipCount.entrySet()) {
                System.out.println("  IP " + entry.getKey() + " -> " + entry.getValue() + " kali");
            }
            System.out.println("Frekuensi per User  :");
            for (Map.Entry<String, Integer> entry : userCount.entrySet()) {
                System.out.println("  User \"" + entry.getKey() + "\" -> " + entry.getValue() + " kali");
            }

        } catch (IOException e) {
            System.out.println("[ERROR] Gagal menulis laporan: " + e.getMessage());
        }
    }
}
