# AV Scanner - Hash-Based Antivirus

Pemindai antivirus berbasis hash SHA-256 untuk Windows. Proyek ini bersifat **educational** dan mendemonstrasikan cara kerja deteksi malware menggunakan signature matching.

## Fitur
- **Hash-Based Detection**: Mencocokkan SHA-256 file dengan database hash malware yang diketahui
- **Recursive Directory Scanning**: Memindai seluruh folder dan subfolder
- **Quarantine**: Mengisolasi file terdeteksi dengan metadata untuk pemulihan
- **Progress Bar**: Visualisasi progress pemindaian real-time
- **Structured Logging**: Log terstruktur ke file dan console

## Build

### Prerequisite
- Visual Studio 2022 (dengan workload "Desktop development with C++")
- CMake 3.20+

### Kompilasi
```powershell
cmake -B build -S .
cmake --build build --config Release
```

### Jalankan Tests
```powershell
cmake --build build --config Release --target av_tests
.\build\Release\av_tests.exe
```

## Penggunaan

### Scan Dasar
```powershell
.\build\Release\av_scanner.exe --scan C:\Downloads --db data\hashdb.txt
```

### Scan dengan Auto-Quarantine
```powershell
.\build\Release\av_scanner.exe --scan C:\Downloads --db data\hashdb.txt --auto-quarantine
```

### Opsi Lengkap
```
--scan <path>          Path yang akan dipindai
--db <file>            File database hash
--quarantine <path>    Direktori karantina (default: data/quarantine)
--auto-quarantine      Otomatis karantina file terdeteksi
--max-size <MB>        Ukuran file maksimum (default: 100 MB)
--log <file>           Path file log (default: av_scan.log)
```

## Database Hash
Isi `data/hashdb.txt` dengan hash SHA-256 malware yang diketahui:
- [MalwareBazaar](https://bazaar.abuse.ch/export/) — download SHA-256 hash list
- [VirusShare](https://virusshare.com/) — perlu registrasi

## Testing dengan EICAR
Download [EICAR test file](https://www.eicar.org/download-anti-malware-testfile/) untuk menguji deteksi. Hash EICAR sudah ada di `data/hashdb.txt`.

## ⚠️ Disclaimer
Proyek ini bersifat educational. Untuk proteksi nyata, gunakan solusi antivirus komersial. Scanner ini hanya mendeteksi ancaman yang hash-nya sudah terdaftar dalam database.
