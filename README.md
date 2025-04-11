# Subdomain Enumerator

Subdomain Enumerator adalah sebuah alat untuk menemukan subdomain dari suatu domain, memeriksa status HTTP/HTTPS, informasi server, validitas SSL, serta melakukan geolokasi IP dan pencarian CNAME.

## Fitur

- Mencari subdomain dari crt.sh
- Mengecek status HTTP/HTTPS
- Mengambil informasi server dari header HTTP
- Mengecek validitas sertifikat SSL
- Melakukan resolusi DNS untuk mendapatkan IP
- Melakukan pencarian geolokasi IP menggunakan IPInfo
- Melakukan reverse IP lookup
- Mendapatkan informasi CNAME
- Menyimpan hasil dalam format TXT atau JSON
- Mengambil screenshot halaman website (opsional)

## Persyaratan

- Python 3.x
- Paket Python:
  - `requests`
  - `colorama`
  - `OpenSSL`
  - `urllib3`
  - `dns.resolver`
  - `whois`
  - `ipinfo`
- CutyCapt (opsional, untuk screenshot website)

## Instalasi

1. Clone repositori ini atau unduh scriptnya.
2. Install dependensi dengan menjalankan perintah berikut:
   ```sh
   pip install -r requirements.txt
   ```
3. Dapatkan API Token dari [IPInfo](https://ipinfo.io/) dan ganti `YOUR_IPINFO_TOKEN` dalam script.

## Penggunaan

Jalankan script dengan format berikut:

```sh
python sub.py domain.com [json]
```

**Contoh:**

```sh
python sub.py example.com json
```

Opsi `json` bersifat opsional dan akan menyimpan output dalam format JSON.

## Output

Hasil pemindaian akan disimpan dalam file dengan format berikut:

- **TXT:** `example-com_YYYYMMDD-HHMMSS.txt`
- **JSON:** `example-com_YYYYMMDD-HHMMSS.json`

## Catatan

- Pastikan koneksi internet stabil untuk mendapatkan hasil optimal.
- Gunakan API Token IPInfo agar tidak terkena batasan request.

## Lisensi

Proyek ini dirilis di bawah lisensi MIT.

