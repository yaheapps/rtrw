// Created by @ruangperpustakaan

/**
 * Fungsi publik untuk menjalankan pembuatan database di Spreadsheet baru.
 * Pilih fungsi ini di editor Apps Script dan klik "Run" (Jalankan).
 */
function jalankanSetupDatabase() {
  setupDatabase_();
}

/**
 * Konfigurasi Awal doGet() Google Apps Script Web App
 */
function doGet(e) {
  return HtmlService.createTemplateFromFile('index')
    .evaluate()
    .setTitle('Sistem Informasi Administrasi & Keuangan RT/RW')
    .addMetaTag('viewport', 'width=device-width, initial-scale=1.0')
    .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL);
}

/**
 * [MS-1] Password Hashing dengan algoritma SHA-256
 */
function hashPassword_(password) {
  var rawHash = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, password);
  var txtHash = '';
  for (var i = 0; i < rawHash.length; i++) {
    var hashVal = rawHash[i];
    if (hashVal < 0) hashVal += 256;
    if (hashVal.toString(16).length === 1) txtHash += '0';
    txtHash += hashVal.toString(16);
  }
  return txtHash;
}

/**
 * [MS-2] Session management & CacheService token generator (Aktif selama 8 jam)
 */
function getSecretKey_() {
  var props = PropertiesService.getScriptProperties();
  var secret = props.getProperty('APP_SECRET_KEY');
  if (!secret) {
    secret = Utilities.getUuid() + '-' + Date.now();
    props.setProperty('APP_SECRET_KEY', secret);
  }
  return secret;
}

function generateSessionToken_(username) {
  var secret = getSecretKey_();
  var timestamp = Date.now();
  var uuid = Utilities.getUuid();
  var rawPayload = username + ':' + timestamp + ':' + uuid;
  var signatureBytes = Utilities.computeHmacSha256Signature(rawPayload, secret);
  var signatureHex = signatureBytes.map(function(b) {
    return ('0' + (b & 0xFF).toString(16)).slice(-2);
  }).join('');
  
  var token = Utilities.base64EncodeWebSafe(rawPayload) + '.' + signatureHex;
  var cache = CacheService.getScriptCache();
  
  // Expiration diizinkan Google Apps Script maks 21600 detik (6 Jam)
  var sessionObj = {
    username: username,
    created: new Date(timestamp).toISOString()
  };
  cache.put('session_' + token, JSON.stringify(sessionObj), 21600);
  cache.put('user_session_' + username, token, 21600);
  return token;
}

/**
 * [MS-3] Validasi Sesi Token di Setiap Akses Engine (Sliding Session + HMAC Fallback)
 */
function validateSession_(token) {
  if (!token) return { valid: false, message: 'Autentikasi token tidak dilampirkan.' };
  
  var cache = CacheService.getScriptCache();

  // Cek apakah token sudah di-revoke via Logout
  if (cache.get('revoked_' + token)) {
    return { valid: false, message: 'Sesi login telah ditutup (Logout).' };
  }

  // 1. Cek Cepat dari CacheService
  var sessionData = cache.get('session_' + token);
  if (sessionData) {
    try {
      var parsed = JSON.parse(sessionData);
      // Sliding Session: Perpanjang durasi Cache (21600 detik = 6 jam) pada setiap aktivitas aktif
      cache.put('session_' + token, sessionData, 21600);
      cache.put('user_session_' + parsed.username, token, 21600);
      return { valid: true, username: parsed.username };
    } catch (e) {}
  }
  
  // 2. Fallback: Verifikasi HMAC Signature jika Cache terhapus oleh server Google
  try {
    var parts = String(token).split('.');
    if (parts.length === 2) {
      var rawPayload = Utilities.newBlob(Utilities.base64DecodeWebSafe(parts[0])).getDataAsString();
      var signatureHex = parts[1];
      var payloadParts = rawPayload.split(':');
      if (payloadParts.length === 3) {
        var username = payloadParts[0];
        var timestamp = parseInt(payloadParts[1], 10);
        var secret = getSecretKey_();
        var checkBytes = Utilities.computeHmacSha256Signature(rawPayload, secret);
        var checkHex = checkBytes.map(function(b) {
          return ('0' + (b & 0xFF).toString(16)).slice(-2);
        }).join('');

        if (checkHex === signatureHex) {
          var ageMs = Date.now() - timestamp;
          var MAX_SESSION_AGE = 7 * 24 * 60 * 60 * 1000; // Maksimal Umur Token 7 Hari
          if (ageMs < MAX_SESSION_AGE) {
            // Restore otomatis sesi ke dalam CacheService
            var newSessionObj = { username: username, created: new Date(timestamp).toISOString() };
            cache.put('session_' + token, JSON.stringify(newSessionObj), 21600);
            cache.put('user_session_' + username, token, 21600);
            return { valid: true, username: username };
          }
        }
      }
    }
  } catch (e) {
    Logger.log('Token fallback validation error: ' + e.message);
  }
  
  return { valid: false, message: 'Sesi login telah kadaluarsa. Silakan masuk kembali.' };
}

/**
 * [MS-7] Logout untuk menghapus Sesi di Cache server
 */
function destroySession(token) {
  var cache = CacheService.getScriptCache();
  var sessionData = cache.get('session_' + token);
  if (sessionData) {
    try {
      var parsed = JSON.parse(sessionData);
      cache.remove('user_session_' + parsed.username);
    } catch (e) {}
  }
  cache.remove('session_' + token);
  cache.put('revoked_' + token, '1', 21600);
  return { success: true };
}

/**
 * [MS-5] Rate Limiting - Maksimal 5x percobaan salah, kunci 15 menit
 */
function checkLoginRateLimit_(username) {
  var cache = CacheService.getScriptCache();
  var key = 'login_fail_' + username;
  var failCount = parseInt(cache.get(key) || '0');
  if (failCount >= 5) {
    return { allowed: false, message: 'Akun terblokir sementara akibat terlalu banyak percobaan salah. Coba lagi dalam 15 menit.' };
  }
  return { allowed: true, failCount: failCount };
}

function recordLoginFailure_(username) {
  var cache = CacheService.getScriptCache();
  var key = 'login_fail_' + username;
  var failCount = parseInt(cache.get(key) || '0') + 1;
  cache.put(key, String(failCount), 900); // Kunci 15 menit = 900 detik
}

function clearLoginFailures_(username) {
  var cache = CacheService.getScriptCache();
  cache.remove('login_fail_' + username);
}

/**
 * Helper untuk memastikan kolom header no_hp dan email ada di sheet Users
 */
function ensureUserColumns_(sheet) {
  if (!sheet) return;
  var lastCol = Math.max(1, sheet.getLastColumn());
  var headers = sheet.getRange(1, 1, 1, lastCol).getValues()[0];
  var required = ['no_hp', 'email'];
  required.forEach(function(col) {
    if (headers.indexOf(col) === -1) {
      sheet.getRange(1, headers.length + 1).setValue(col);
      headers.push(col);
    }
  });
}

/**
 * Login Petugas dengan Validasi Database
 */
function loginUser(username, password) {
  var rateCheck = checkLoginRateLimit_(username);
  if (!rateCheck.allowed) return { success: false, message: rateCheck.message };

  username = String(username).trim().substring(0, 50).toLowerCase();
  password = String(password).trim();
  if (!username || !password) return { success: false, message: 'Form login tidak boleh kosong.' };

  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('Users');
  if (!sheet) return { success: false, message: 'Spreadsheet Users belum diinisialisasi. Silakan jalankan setupDatabase_().' };

  ensureUserColumns_(sheet);
  var data = sheet.getDataRange().getValues();
  var map = getColumnMap_(sheet);
  var hashedInput = hashPassword_(password);

  for (var i = 1; i < data.length; i++) {
    var dbUser = String(data[i][map['username']]).trim().toLowerCase();
    var dbPass = String(data[i][map['password']]).trim();
    
    if (dbUser === username && dbPass === hashedInput) {
      clearLoginFailures_(username);
      var token = generateSessionToken_(username);
      
      // Catat Log ke sheet AuditLog
      logAction_(username, 'LOGIN', 'Berhasil masuk ke aplikasi web.');
      
      return {
        success: true,
        token: token,
        user: {
          username: data[i][map['username']],
          fullname: data[i][map['fullname']],
          role: data[i][map['role']],
          acc_terms: map['acc_terms'] !== undefined ? safeDateFormat_(data[i][map['acc_terms']]) : '',
          no_hp: map['no_hp'] !== undefined ? sanitizePhone_(data[i][map['no_hp']]) : '',
          email: map['email'] !== undefined ? (data[i][map['email']] || '') : ''
        }
      };
    }
  }

  recordLoginFailure_(username);
  return { success: false, message: 'Username atau Password salah!' };
}

/**
 * Menyimpan persetujuan syarat & ketentuan oleh pengurus (admin/staff)
 */
function acceptTerms(token) {
  var session = validateSession_(token);
  if (!session.valid) return { success: false, message: session.message, sessionExpired: true };

  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('Users');
  if (!sheet) return { success: false, message: 'Database Users tidak ditemukan.' };

  var lock = LockService.getScriptLock();
  try {
    lock.waitLock(10000);
    var data = sheet.getDataRange().getValues();
    var map = getColumnMap_(sheet);

    if (map['acc_terms'] === undefined) {
      return { success: false, message: 'Kolom persetujuan syarat belum terinisialisasi. Silakan jalankan setupDatabase_() terlebih dahulu.' };
    }

    for (var i = 1; i < data.length; i++) {
      if (String(data[i][map['username']]).trim().toLowerCase() === session.username.toLowerCase()) {
        var rowNum = i + 1;
        var timestamp = new Date();
        sheet.getRange(rowNum, map['acc_terms'] + 1).setValue(timestamp);
        logAction_(session.username, 'ACCEPT_TERMS', 'Menyetujui syarat & ketentuan pelindungan data warga.');
        return { success: true, acc_terms: timestamp.toISOString() };
      }
    }
    return { success: false, message: 'User tidak ditemukan.' };
  } catch (e) {
    return { success: false, message: e.toString() };
  } finally {
    lock.releaseLock();
  }
}

/**
 * Mengubah Biodata Profil, Username dan/atau Password pengguna yang sedang login
 */
function changePassword(token, oldPassword, newPassword, newUsername, fullname, no_hp, email) {
  var session = validateSession_(token);
  if (!session.valid) return { success: false, message: session.message, sessionExpired: true };

  oldPassword = String(oldPassword || '').trim();
  newPassword = String(newPassword || '').trim();
  newUsername = sanitizeInput_(newUsername || '', 50).trim();
  fullname = sanitizeInput_(fullname || '', 100).trim();
  no_hp = sanitizePhone_(no_hp);
  email = sanitizeInput_(email || '', 100).trim();

  if (!oldPassword) {
    return { success: false, message: 'Password lama wajib diisi untuk verifikasi keamanan.' };
  }

  if (newUsername && newUsername.length < 3) {
    return { success: false, message: 'Username baru minimal 3 karakter.' };
  }

  if (newPassword && newPassword.length < 6) {
    return { success: false, message: 'Password baru minimal 6 karakter.' };
  }

  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('Users');
  if (!sheet) return { success: false, message: 'Database Users tidak ditemukan.' };

  var lock = LockService.getScriptLock();
  try {
    lock.waitLock(10000);
    ensureUserColumns_(sheet);
    var data = sheet.getDataRange().getValues();
    var map = getColumnMap_(sheet);
    var oldHash = hashPassword_(oldPassword);

    var userRowIndex = -1;
    var currentUsername = session.username.toLowerCase();

    for (var i = 1; i < data.length; i++) {
      if (String(data[i][map['username']]).trim().toLowerCase() === currentUsername) {
        userRowIndex = i;
        var currentPass = String(data[i][map['password']]).trim();
        if (currentPass !== oldHash) {
          return { success: false, message: 'Password lama yang Anda masukkan tidak sesuai.' };
        }
        break;
      }
    }

    if (userRowIndex === -1) {
      return { success: false, message: 'Akun user tidak ditemukan.' };
    }

    var targetRow = userRowIndex + 1;
    var targetUsername = newUsername ? newUsername : data[userRowIndex][map['username']];

    if (newUsername && newUsername.toLowerCase() !== currentUsername) {
      for (var j = 1; j < data.length; j++) {
        if (j !== userRowIndex && String(data[j][map['username']]).trim().toLowerCase() === newUsername.toLowerCase()) {
          return { success: false, message: 'Username "' + newUsername + '" sudah digunakan oleh akun pengurus lain.' };
        }
      }

      sheet.getRange(targetRow, map['username'] + 1).setValue(targetUsername);

      var cache = CacheService.getScriptCache();
      var sessionObj = {
        username: targetUsername,
        created: new Date().toISOString()
      };
      cache.put('session_' + token, JSON.stringify(sessionObj), 21600);
      cache.remove('user_session_' + currentUsername);
      cache.put('user_session_' + targetUsername.toLowerCase(), token, 21600);
    }

    if (fullname && map['fullname'] !== undefined) {
      sheet.getRange(targetRow, map['fullname'] + 1).setValue(fullname);
    }
    if (map['no_hp'] !== undefined) {
      sheet.getRange(targetRow, map['no_hp'] + 1).setNumberFormat('@').setValue("'" + no_hp);
    }
    if (map['email'] !== undefined) {
      sheet.getRange(targetRow, map['email'] + 1).setValue(email);
    }

    if (newPassword) {
      var newHash = hashPassword_(newPassword);
      sheet.getRange(targetRow, map['password'] + 1).setValue(newHash);
    }

    logAction_(targetUsername, 'CHANGE_PROFILE', 'Berhasil memperbarui biodata & akun (Nama/No.HP/Email/Username/Password).');
    
    var updatedRowData = sheet.getRange(targetRow, 1, 1, sheet.getLastColumn()).getValues()[0];
    var updatedMap = getColumnMap_(sheet);

    return {
      success: true,
      message: 'Profil biodata dan akun berhasil diperbarui.',
      user: {
        username: updatedRowData[updatedMap['username']] || targetUsername,
        fullname: updatedRowData[updatedMap['fullname']] || fullname,
        role: updatedRowData[updatedMap['role']] || '',
        acc_terms: updatedMap['acc_terms'] !== undefined ? safeDateFormat_(updatedRowData[updatedMap['acc_terms']]) : '',
        no_hp: updatedMap['no_hp'] !== undefined ? sanitizePhone_(updatedRowData[updatedMap['no_hp']]) : '',
        email: updatedMap['email'] !== undefined ? (updatedRowData[updatedMap['email']] || '') : ''
      }
    };
  } catch (e) {
    return { success: false, message: e.toString() };
  } finally {
    lock.releaseLock();
  }
}


/**
 * [ES-5] Menulis Log Aktivitas Petugas
 */
function logAction_(username, action, detail) {
  try {
    var sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName('AuditLog');
    if (!sheet) return;
    sheet.appendRow([
      new Date(),
      username || 'SISTEM',
      action,
      String(detail || '').substring(0, 500)
    ]);
  } catch (e) {
    Logger.log('Gagal menyimpan audit log: ' + e.toString());
  }
}

/**
 * Normalisasi dan Serialisasi Tanggal Google Sheets agar aman dikirim ke Frontend
 */
function safeDateFormat_(value) {
  if (!value) return '';
  if (value instanceof Date) {
    return Utilities.formatDate(value, Session.getScriptTimeZone(), 'yyyy-MM-dd');
  }
  return String(value);
}

function getColumnMap_(sheetOrData) {
  var headers;
  if (Array.isArray(sheetOrData)) {
    headers = sheetOrData.length ? sheetOrData[0] : [];
  } else if (sheetOrData && typeof sheetOrData.getLastColumn === 'function') {
    headers = sheetOrData.getRange(1, 1, 1, sheetOrData.getLastColumn()).getValues()[0];
  } else {
    return {};
  }
  var map = {};
  headers.forEach(function(h, i) {
    map[String(h).toLowerCase().trim()] = i;
  });
  return map;
}

/**
 * [MS-9] Sanitasi Input Data Form
 */
function sanitizeInput_(value, maxLength) {
  if (!value) return '';
  maxLength = maxLength || 500;
  return String(value).replace(/<[^>]*>/g, '').trim().substring(0, maxLength);
}

/**
 * Sanitasi & Normalisasi Nomor Telepon / WhatsApp Indonesia
 */
function sanitizePhone_(hp) {
  if (hp === undefined || hp === null) return '';
  var str = String(hp).trim().replace(/[^0-9]/g, '');
  if (!str) return '';
  if (str.startsWith('8')) str = '0' + str;
  else if (str.startsWith('628')) str = '08' + str.substring(3);
  return str;
}

/**
 * Sanitasi & Normalisasi String Angka Panjang (NIK, No KK) untuk Mencegah Scientific Notation (3,67107E+15)
 */
function sanitizeDigitString_(val) {
  if (val === undefined || val === null) return '';
  var str = String(val).trim();
  if (!str) return '';
  if (/^[0-9]+([.,][0-9]+)?[eE]\+[0-9]+$/.test(str)) {
    var num = Number(str.replace(',', '.'));
    if (!isNaN(num)) str = num.toFixed(0);
  }
  return str;
}

/**
 * [ES-4] Validasi Server-Side Hak Akses Role Khusus
 */
function requireRole_(token, requiredRole) {
  var session = validateSession_(token);
  if (!session.valid) return { authorized: false, message: session.message, sessionExpired: true };
  
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('Users');
  if (!sheet) return { authorized: false, message: 'Database Users tidak ditemukan.' };
  var map = getColumnMap_(sheet);
  var data = sheet.getDataRange().getValues();

  var userRole = '';
  for (var i = 1; i < data.length; i++) {
    if (String(data[i][map['username']]).toLowerCase().trim() === session.username.toLowerCase().trim()) {
      userRole = String(data[i][map['role']]).trim();
      break;
    }
  }

  if (!userRole) return { authorized: false, message: 'Data role pengguna tidak ditemukan.' };

  if (userRole === 'Admin') {
    return { authorized: true, username: session.username, role: userRole };
  }
  if (requiredRole === 'Bendahara' && (userRole === 'Bendahara' || userRole === 'Admin')) {
    return { authorized: true, username: session.username, role: userRole };
  }
  if (requiredRole === 'Staff' && (userRole === 'Staff' || userRole === 'Bendahara' || userRole === 'Admin')) {
    return { authorized: true, username: session.username, role: userRole };
  }
  if (userRole === requiredRole) {
    return { authorized: true, username: session.username, role: userRole };
  }

  return { authorized: false, message: 'Otoritas ditolak. Peran Anda (' + userRole + ') tidak memiliki hak akses untuk tindakan ini.' };
}

// ==================== DATABASE CRUD ENGINE ====================

/**
 * Mengambil Ringkasan Data Utama untuk Dashboard Visual
 */
function getDashboardData(token) {
  var session = validateSession_(token);
  if (!session.valid) return { success: false, message: session.message, sessionExpired: true };

  var ss = SpreadsheetApp.getActiveSpreadsheet();
  
  // Ambil Data Warga
  var wargaSheet = ss.getSheetByName('Warga');
  var rawWarga = wargaSheet ? wargaSheet.getDataRange().getValues() : [];
  var mapW = getColumnMap_(rawWarga);
  var wargaList = [];
  for (var i = 1; i < rawWarga.length; i++) {
    wargaList.push({
      id_warga: rawWarga[i][mapW['id_warga']] || '',
      no_kk: mapW['no_kk'] !== undefined ? sanitizeDigitString_(rawWarga[i][mapW['no_kk']]) : '',
      nik: mapW['nik'] !== undefined ? sanitizeDigitString_(rawWarga[i][mapW['nik']]) : '',
      nama: rawWarga[i][mapW['nama']] || '',
      no_rumah: rawWarga[i][mapW['no_rumah']] || '',
      jenis_kelamin: rawWarga[i][mapW['jenis_kelamin']] || '',
      agama: mapW['agama'] !== undefined ? (rawWarga[i][mapW['agama']] || 'Islam') : 'Islam',
      tempat_lahir: rawWarga[i][mapW['tempat_lahir']] || '',
      tanggal_lahir: safeDateFormat_(rawWarga[i][mapW['tanggal_lahir']]),
      status_tinggal: rawWarga[i][mapW['status_tinggal']] || '',
      status_pernikahan: rawWarga[i][mapW['status_pernikahan']] || '',
      posisi_keluarga: rawWarga[i][mapW['posisi_keluarga']] || '',
      no_hp: mapW['no_hp'] !== undefined ? sanitizePhone_(rawWarga[i][mapW['no_hp']]) : '',
      status_warga: rawWarga[i][mapW['status_warga']] || '',
      created_at: safeDateFormat_(rawWarga[i][mapW['created_at']])
    });
  }

  // Ambil Data Iuran
  var iuranSheet = ss.getSheetByName('Iuran');
  var rawIuran = iuranSheet ? iuranSheet.getDataRange().getValues() : [];
  var mapI = getColumnMap_(rawIuran);
  var iuranList = [];
  for (var i = 1; i < rawIuran.length; i++) {
    iuranList.push({
      id_iuran: rawIuran[i][mapI['id_iuran']] || '',
      id_warga: rawIuran[i][mapI['id_warga']] || '',
      bulan: rawIuran[i][mapI['bulan']] || '',
      tahun: rawIuran[i][mapI['tahun']] || '',
      jumlah: parseInt(rawIuran[i][mapI['jumlah']] || 0, 10),
      tanggal_bayar: safeDateFormat_(rawIuran[i][mapI['tanggal_bayar']]),
      petugas_penerima: rawIuran[i][mapI['petugas_penerima']] || '',
      kategori: mapI['kategori'] !== undefined ? (rawIuran[i][mapI['kategori']] || 'Iuran Bulanan') : 'Iuran Bulanan',
      bukti: mapI['bukti'] !== undefined ? (rawIuran[i][mapI['bukti']] || '') : ''
    });
  }

  // Ambil Data Kas Keluar
  var kasSheet = ss.getSheetByName('Kas_Keluar');
  var rawKas = kasSheet ? kasSheet.getDataRange().getValues() : [];
  var mapK = getColumnMap_(rawKas);
  var kasKeluarList = [];
  for (var i = 1; i < rawKas.length; i++) {
    kasKeluarList.push({
      id_keluar: rawKas[i][mapK['id_keluar']] || '',
      keperluan: rawKas[i][mapK['keperluan']] || '',
      jumlah: parseInt(rawKas[i][mapK['jumlah']] || 0, 10),
      tanggal_keluar: safeDateFormat_(rawKas[i][mapK['tanggal_keluar']]),
      petugas: rawKas[i][mapK['petugas']] || '',
      kategori: mapK['kategori'] !== undefined ? (rawKas[i][mapK['kategori']] || 'Lain-lain') : 'Lain-lain',
      bukti: mapK['bukti'] !== undefined ? (rawKas[i][mapK['bukti']] || '') : ''
    });
  }

  // Ambil Data Aduan (Legacy, now empty)
  var aduanList = [];

  // Ambil Data Aset
  var asetSheet = ss.getSheetByName('Aset');
  var rawAset = asetSheet ? asetSheet.getDataRange().getValues() : [];
  var mapAs = getColumnMap_(rawAset);
  var asetList = [];
  for (var i = 1; i < rawAset.length; i++) {
    asetList.push({
      id_aset: rawAset[i][mapAs['id_aset']] || '',
      nama_barang: rawAset[i][mapAs['nama_barang']] || '',
      kategori: rawAset[i][mapAs['kategori']] || '',
      jumlah_total: parseInt(rawAset[i][mapAs['jumlah_total']] || 0, 10),
      jumlah_tersedia: parseInt(rawAset[i][mapAs['jumlah_tersedia']] || 0, 10),
      kondisi_fisik: rawAset[i][mapAs['kondisi_fisik']] || 'Baik',
      keterangan_lokasi: rawAset[i][mapAs['keterangan_lokasi']] || '',
      foto: rawAset[i][mapAs['foto']] || '',
      petugas: rawAset[i][mapAs['petugas']] || '',
      created_at: safeDateFormat_(rawAset[i][mapAs['created_at']])
    });
  }

  // Ambil Data Settings
  var settings = {
    nominal_iuran: 20000,
    kategori_pemasukan: ["Iuran Bulanan", "Sumbangan", "Lain-lain"],
    kategori_pengeluaran: ["Kebersihan", "Keamanan", "Sosial", "Operasional", "Lain-lain"],
    kategori_aset: ["Peralatan", "Perlengkapan Acara", "Alat Kebersihan", "Lain-lain"],
    kategori_surat: ["Pembuatan KTP", "Pembuatan KK", "Surat Keterangan Domisili", "Surat Keterangan Usaha", "Surat Keterangan Tidak Mampu", "Lainnya"],
    kategori_umkm: [
      "Kuliner / Makanan & Minuman",
      "Sembako / Toko Manisan",
      "Jasa / Service",
      "Fashion & Pakaian",
      "Kerajinan / Kriya",
      "Pertanian / Peternakan",
      "Lain-lain"
    ]
  };
  var settingsSheet = ss.getSheetByName('Settings');
  var rawSettings = settingsSheet ? settingsSheet.getDataRange().getValues() : [];
  var mapS = getColumnMap_(settingsSheet);
  if (rawSettings.length > 0) {
    for (var k = 1; k < rawSettings.length; k++) {
      var key = String(rawSettings[k][mapS['key']]).trim();
      var val = String(rawSettings[k][mapS['value']]).trim();
      if (key === 'nominal_iuran') {
        settings.nominal_iuran = parseInt(val || '20000', 10);
      } else if (key.indexOf('kategori_') === 0) {
        try {
          settings[key] = JSON.parse(val);
        } catch (e) {
          settings[key] = val.split(',').map(function(s) { return s.trim(); });
        }
      } else {
        settings[key] = val;
      }
    }
  }

  // Ambil Data Permohonan_Surat
  var suratSheet = ss.getSheetByName('Permohonan_Surat');
  var rawSurat = suratSheet ? suratSheet.getDataRange().getValues() : [];
  var mapSurat = getColumnMap_(rawSurat);
  var permohonanSuratList = [];
  for (var i = 1; i < rawSurat.length; i++) {
    permohonanSuratList.push({
      id_tiket: rawSurat[i][mapSurat['id_tiket']] || '',
      tanggal: safeDateFormat_(rawSurat[i][mapSurat['tanggal']]),
      jenis_layanan: rawSurat[i][mapSurat['jenis_layanan']] || '',
      nama_pemohon: rawSurat[i][mapSurat['nama_pemohon']] || '',
      no_wa: rawSurat[i][mapSurat['no_wa']] || '',
      nik_no_rumah: rawSurat[i][mapSurat['nik_no_rumah']] || '',
      detail_permintaan: rawSurat[i][mapSurat['detail_permintaan']] || '',
      no_surat: rawSurat[i][mapSurat['no_surat']] || '',
      status: rawSurat[i][mapSurat['status']] || 'Pending'
    });
  }

  // Ambil Data Peminjaman_Aset
  var peminjamanSheet = ss.getSheetByName('Peminjaman_Aset');
  var rawPeminjaman = peminjamanSheet ? peminjamanSheet.getDataRange().getValues() : [];
  var mapPeminjaman = getColumnMap_(rawPeminjaman);
  var peminjamanAsetList = [];
  for (var i = 1; i < rawPeminjaman.length; i++) {
    peminjamanAsetList.push({
      id_tiket: rawPeminjaman[i][mapPeminjaman['id_tiket']] || '',
      tanggal: safeDateFormat_(rawPeminjaman[i][mapPeminjaman['tanggal']]),
      nama_peminjam: rawPeminjaman[i][mapPeminjaman['nama_peminjam']] || '',
      no_wa: rawPeminjaman[i][mapPeminjaman['no_wa']] || '',
      no_rumah: rawPeminjaman[i][mapPeminjaman['no_rumah']] || '',
      barang: rawPeminjaman[i][mapPeminjaman['barang']] || '',
      jumlah_unit: parseInt(rawPeminjaman[i][mapPeminjaman['jumlah_unit']] || 0, 10),
      tanggal_pinjam: safeDateFormat_(rawPeminjaman[i][mapPeminjaman['tanggal_pinjam']]),
      tanggal_kembali: safeDateFormat_(rawPeminjaman[i][mapPeminjaman['tanggal_kembali']]),
      detail_peminjaman: rawPeminjaman[i][mapPeminjaman['detail_peminjaman']] || '',
      status: rawPeminjaman[i][mapPeminjaman['status']] || 'Pending'
    });
  }

  // Hitung jumlah_tersedia secara dinamis
  for (var a = 0; a < asetList.length; a++) {
    var borrowed = 0;
    for (var p = 0; p < peminjamanAsetList.length; p++) {
      if (peminjamanAsetList[p].status === 'Disetujui' && (peminjamanAsetList[p].barang === asetList[a].nama_barang || String(peminjamanAsetList[p].detail_peminjaman).indexOf(asetList[a].nama_barang) !== -1)) {
        var u = parseInt(peminjamanAsetList[p].jumlah_unit || 0, 10);
        // Fallback parsing unit dari detail jika legacy
        if (!peminjamanAsetList[p].barang && u === 0) {
          var legacyPart = String(peminjamanAsetList[p].detail_peminjaman);
          if (legacyPart.indexOf('|') !== -1) {
            var detailPart = legacyPart.split('|')[1].trim();
            var numMatch = detailPart.match(/(\d+)/);
            if (numMatch) u = parseInt(numMatch[1], 10);
          }
        }
        borrowed += u;
      }
    }
    asetList[a].jumlah_tersedia = Math.max(0, asetList[a].jumlah_total - borrowed);
  }

  // Ambil Data Pengaduan_Saran
  var pengaduanLayananSheet = ss.getSheetByName('Pengaduan_Saran');
  var rawPengaduanLayanan = pengaduanLayananSheet ? pengaduanLayananSheet.getDataRange().getValues() : [];
  var mapPengaduanLayanan = getColumnMap_(rawPengaduanLayanan);
  var pengaduanSaranList = [];
  for (var i = 1; i < rawPengaduanLayanan.length; i++) {
    pengaduanSaranList.push({
      id_tiket: rawPengaduanLayanan[i][mapPengaduanLayanan['id_tiket']] || '',
      tanggal: safeDateFormat_(rawPengaduanLayanan[i][mapPengaduanLayanan['tanggal']]),
      jenis_layanan: rawPengaduanLayanan[i][mapPengaduanLayanan['jenis_layanan']] || '',
      nama_pengadu: rawPengaduanLayanan[i][mapPengaduanLayanan['nama_pengadu']] || '',
      no_wa: rawPengaduanLayanan[i][mapPengaduanLayanan['no_wa']] || '',
      lokasi_kejadian: rawPengaduanLayanan[i][mapPengaduanLayanan['lokasi_kejadian']] || '',
      detail_pengaduan: rawPengaduanLayanan[i][mapPengaduanLayanan['detail_pengaduan']] || '',
      bukti_foto: rawPengaduanLayanan[i][mapPengaduanLayanan['bukti_foto']] || '',
      status: rawPengaduanLayanan[i][mapPengaduanLayanan['status']] || 'Pending'
    });
  }

  // Ambil Data Agenda
  var agendaSheet = ss.getSheetByName('Agenda');
  var rawAgenda = agendaSheet ? agendaSheet.getDataRange().getValues() : [];
  var mapAgenda = getColumnMap_(rawAgenda);
  var agendaList = [];
  for (var i = 1; i < rawAgenda.length; i++) {
    agendaList.push({
      id_agenda: rawAgenda[i][mapAgenda['id_agenda']] || '',
      judul_kegiatan: rawAgenda[i][mapAgenda['judul_kegiatan']] || '',
      kategori: rawAgenda[i][mapAgenda['kategori']] || '',
      tanggal_jam: rawAgenda[i][mapAgenda['tanggal_jam']] || '',
      lokasi: rawAgenda[i][mapAgenda['lokasi']] || '',
      status: rawAgenda[i][mapAgenda['status']] || 'TERJADWAL',
      petugas: rawAgenda[i][mapAgenda['petugas']] || '',
      created_at: safeDateFormat_(rawAgenda[i][mapAgenda['created_at']]),
      url_laporan: (mapAgenda['url_laporan'] !== undefined && mapAgenda['url_laporan'] < rawAgenda[i].length) ? (rawAgenda[i][mapAgenda['url_laporan']] || '') : '',
      url_notulen: (mapAgenda['url_notulen'] !== undefined && mapAgenda['url_notulen'] < rawAgenda[i].length) ? (rawAgenda[i][mapAgenda['url_notulen']] || '') : ''
    });
  }

  // Ambil Data Pengumuman
  var pengumumanSheet = ss.getSheetByName('Pengumuman');
  var rawPengumuman = pengumumanSheet ? pengumumanSheet.getDataRange().getValues() : [];
  var mapPengumuman = getColumnMap_(rawPengumuman);
  var pengumumanList = [];
  for (var i = 1; i < rawPengumuman.length; i++) {
    pengumumanList.push({
      id_pengumuman: rawPengumuman[i][mapPengumuman['id_pengumuman']] || '',
      tanggal: safeDateFormat_(rawPengumuman[i][mapPengumuman['tanggal']]),
      tipe: rawPengumuman[i][mapPengumuman['tipe']] || '',
      judul: rawPengumuman[i][mapPengumuman['judul']] || '',
      isi_pengumuman: rawPengumuman[i][mapPengumuman['isi_pengumuman']] || '',
      petugas: rawPengumuman[i][mapPengumuman['petugas']] || '',
      created_at: safeDateFormat_(rawPengumuman[i][mapPengumuman['created_at']])
    });
  }

  // Ambil Data UMKM
  var umkmSheet = ss.getSheetByName('UMKM');
  var rawUmkm = umkmSheet ? umkmSheet.getDataRange().getValues() : [];
  var mapUmkm = getColumnMap_(rawUmkm);
  var umkmList = [];
  for (var i = 1; i < rawUmkm.length; i++) {
    umkmList.push({
      id_umkm: rawUmkm[i][mapUmkm['id_umkm']] || '',
      id_warga: mapUmkm['id_warga'] !== undefined ? (rawUmkm[i][mapUmkm['id_warga']] || '') : '',
      nama_pemilik: rawUmkm[i][mapUmkm['nama_pemilik']] || '',
      nama_usaha: rawUmkm[i][mapUmkm['nama_usaha']] || '',
      kategori_usaha: rawUmkm[i][mapUmkm['kategori_usaha']] || '',
      deskripsi: rawUmkm[i][mapUmkm['deskripsi']] || '',
      no_hp: mapUmkm['no_hp'] !== undefined ? sanitizePhone_(rawUmkm[i][mapUmkm['no_hp']]) : '',
      alamat_lokasi: rawUmkm[i][mapUmkm['alamat_lokasi']] || '',
      foto_produk: mapUmkm['foto_produk'] !== undefined ? (rawUmkm[i][mapUmkm['foto_produk']] || '') : '',
      status: rawUmkm[i][mapUmkm['status']] || 'Aktif',
      created_at: safeDateFormat_(rawUmkm[i][mapUmkm['created_at']])
    });
  }

  return {
    success: true,
    warga: wargaList,
    iuran: iuranList,
    kasKeluar: kasKeluarList,
    aduan: aduanList,
    aset: asetList,
    settings: settings,
    permohonanSurat: permohonanSuratList,
    peminjamanAset: peminjamanAsetList,
    pengaduanSaran: pengaduanSaranList,
    agenda: agendaList,
    pengumuman: pengumumanList,
    umkm: umkmList
  };
}

/**
 * CRUD Warga
 */
function getWargaData(token) {
  var session = validateSession_(token);
  if (!session.valid) return { success: false, message: session.message, sessionExpired: true };

  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('Warga');
  if (!sheet) return { success: true, data: [] };

  var data = sheet.getDataRange().getValues();
  if (data.length <= 1) return { success: true, data: [] };

  var map = getColumnMap_(data);
  var result = [];
  for (var i = 1; i < data.length; i++) {
    result.push({
      id_warga: data[i][map['id_warga']] || '',
      no_kk: map['no_kk'] !== undefined ? sanitizeDigitString_(data[i][map['no_kk']]) : '',
      nik: map['nik'] !== undefined ? sanitizeDigitString_(data[i][map['nik']]) : '',
      nama: data[i][map['nama']] || '',
      no_rumah: data[i][map['no_rumah']] || '',
      jenis_kelamin: data[i][map['jenis_kelamin']] || '',
      agama: map['agama'] !== undefined ? (data[i][map['agama']] || 'Islam') : 'Islam',
      tempat_lahir: data[i][map['tempat_lahir']] || '',
      tanggal_lahir: safeDateFormat_(data[i][map['tanggal_lahir']]),
      status_tinggal: data[i][map['status_tinggal']] || '',
      status_pernikahan: data[i][map['status_pernikahan']] || '',
      posisi_keluarga: data[i][map['posisi_keluarga']] || '',
      no_hp: map['no_hp'] !== undefined ? sanitizePhone_(data[i][map['no_hp']]) : '',
      status_warga: data[i][map['status_warga']] || '',
      created_at: safeDateFormat_(data[i][map['created_at']])
    });
  }
  return { success: true, data: result };
}

function saveWarga(token, form) {
  var session = validateSession_(token);
  if (!session.valid) return { success: false, message: session.message, sessionExpired: true };

  // Sanitasi Input
  form.no_kk = sanitizeDigitString_(form.no_kk);
  form.nik = sanitizeDigitString_(form.nik);
  form.nama = sanitizeInput_(form.nama, 100);
  form.no_rumah = sanitizeInput_(form.no_rumah, 20);
  form.jenis_kelamin = sanitizeInput_(form.jenis_kelamin, 20);
  form.agama = sanitizeInput_(form.agama, 30);
  form.tempat_lahir = sanitizeInput_(form.tempat_lahir, 100);
  form.tanggal_lahir = sanitizeInput_(form.tanggal_lahir, 20);
  form.status_tinggal = sanitizeInput_(form.status_tinggal, 20);
  form.status_pernikahan = sanitizeInput_(form.status_pernikahan, 20);
  form.posisi_keluarga = sanitizeInput_(form.posisi_keluarga, 30);
  form.no_hp = sanitizePhone_(form.no_hp);
  form.status_warga = sanitizeInput_(form.status_warga, 20);

  if (!form.nama || !form.no_rumah) return { success: false, message: 'Nama dan Nomor Rumah wajib diisi.' };

  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('Warga');
  if (!sheet) return { success: false, message: 'Sheet warga tidak ditemukan.' };

  var lock = LockService.getScriptLock();
  try {
    lock.waitLock(10000);
    var map = getColumnMap_(sheet);

    if (map['no_kk'] === undefined) {
      var lastC = sheet.getLastColumn();
      sheet.getRange(1, lastC + 1).setValue('no_kk');
      map = getColumnMap_(sheet);
    }
    if (map['no_hp'] === undefined) {
      var lastC2 = sheet.getLastColumn();
      sheet.getRange(1, lastC2 + 1).setValue('no_hp');
      map = getColumnMap_(sheet);
    }

    if (form.isEdit === true || form.isEdit === 'true') {
      // Edit data yang sudah ada
      var data = sheet.getDataRange().getValues();
      for (var i = 1; i < data.length; i++) {
        if (String(data[i][map['id_warga']]) === form.id_warga) {
          var rowNum = i + 1;
          
          if (map['no_kk'] !== undefined) sheet.getRange(rowNum, map['no_kk'] + 1).setNumberFormat('@').setValue("'" + form.no_kk);
          if (map['nik'] !== undefined) sheet.getRange(rowNum, map['nik'] + 1).setNumberFormat('@').setValue("'" + form.nik);
          sheet.getRange(rowNum, map['nama'] + 1).setValue(form.nama);
          sheet.getRange(rowNum, map['no_rumah'] + 1).setValue(form.no_rumah);
          if (map['jenis_kelamin'] !== undefined) sheet.getRange(rowNum, map['jenis_kelamin'] + 1).setValue(form.jenis_kelamin);
          if (map['agama'] !== undefined) sheet.getRange(rowNum, map['agama'] + 1).setValue(form.agama || 'Islam');
          if (map['tempat_lahir'] !== undefined) sheet.getRange(rowNum, map['tempat_lahir'] + 1).setValue(form.tempat_lahir);
          if (map['tanggal_lahir'] !== undefined) sheet.getRange(rowNum, map['tanggal_lahir'] + 1).setValue(form.tanggal_lahir ? new Date(form.tanggal_lahir) : '');
          if (map['status_tinggal'] !== undefined) sheet.getRange(rowNum, map['status_tinggal'] + 1).setValue(form.status_tinggal);
          if (map['status_pernikahan'] !== undefined) sheet.getRange(rowNum, map['status_pernikahan'] + 1).setValue(form.status_pernikahan);
          if (map['posisi_keluarga'] !== undefined) sheet.getRange(rowNum, map['posisi_keluarga'] + 1).setValue(form.posisi_keluarga);
          if (map['no_hp'] !== undefined) sheet.getRange(rowNum, map['no_hp'] + 1).setNumberFormat('@').setValue("'" + form.no_hp);
          var statusCol = map['status_warga'];
          if (statusCol === undefined) {
            var lastCol = sheet.getLastColumn();
            sheet.getRange(1, lastCol + 1).setValue('status_warga');
            statusCol = lastCol;
          }
          sheet.getRange(rowNum, statusCol + 1).setValue(form.status_warga);
          
          logAction_(session.username, 'UPDATE', 'Mengubah profil warga: ' + form.nama + ' (' + form.id_warga + ')');
          return { success: true };
        }
      }
      return { success: false, message: 'Data warga dengan ID ' + form.id_warga + ' tidak ditemukan.' };
    } else {
      // Create data warga baru
      var lastRow = sheet.getLastRow();
      var idNum = lastRow > 1 ? parseInt(String(sheet.getRange(lastRow, map['id_warga'] + 1).getValue()).replace('W-', '')) + 1 : 1;
      var newId = 'W-' + ('000' + idNum).slice(-3);

      var headers = sheet.getRange(1, 1, 1, sheet.getLastColumn()).getValues()[0];
      var newRow = new Array(headers.length);
      newRow[map['id_warga']] = newId;
      if (map['no_kk'] !== undefined) newRow[map['no_kk']] = "'" + form.no_kk;
      newRow[map['nik']] = "'" + form.nik;
      newRow[map['nama']] = form.nama;
      newRow[map['no_rumah']] = form.no_rumah;
      if (map['jenis_kelamin'] !== undefined) newRow[map['jenis_kelamin']] = form.jenis_kelamin;
      if (map['agama'] !== undefined) newRow[map['agama']] = form.agama || 'Islam';
      if (map['tempat_lahir'] !== undefined) newRow[map['tempat_lahir']] = form.tempat_lahir;
      if (map['tanggal_lahir'] !== undefined) newRow[map['tanggal_lahir']] = form.tanggal_lahir ? new Date(form.tanggal_lahir) : '';
      if (map['status_tinggal'] !== undefined) newRow[map['status_tinggal']] = form.status_tinggal;
      if (map['status_pernikahan'] !== undefined) newRow[map['status_pernikahan']] = form.status_pernikahan;
      if (map['posisi_keluarga'] !== undefined) newRow[map['posisi_keluarga']] = form.posisi_keluarga;
      if (map['no_hp'] !== undefined) newRow[map['no_hp']] = "'" + form.no_hp;
      if (map['status_warga'] !== undefined) newRow[map['status_warga']] = form.status_warga;
      if (map['created_at'] !== undefined) newRow[map['created_at']] = new Date();

      sheet.appendRow(newRow);

      logAction_(session.username, 'CREATE', 'Mendaftarkan warga baru: ' + form.nama + ' (' + newId + ')');
      return { success: true };
    }
  } catch (e) {
    return { success: false, message: e.toString() };
  } finally {
    lock.releaseLock();
  }
}

/**
 * Mengubah status keaktifan warga (Aktif, Pindah, Meninggal)
 */
function updateWargaStatus(token, id_warga, newStatus) {
  try {
    var session = validateSession_(token);
    if (!session.valid) return { success: false, message: session.message, sessionExpired: true };
    
    var roleCheck = requireRole_(token, 'Staff');
    if (!roleCheck.allowed) return { success: false, message: roleCheck.message };

    id_warga = sanitizeInput_(id_warga, 50);
    newStatus = sanitizeInput_(newStatus, 20);

    var allowedStatuses = ['Aktif', 'Pindah', 'Pindahan', 'Meninggal'];
    if (allowedStatuses.indexOf(newStatus) === -1) {
      return { success: false, message: 'Status keaktifan warga tidak valid.' };
    }

    var ss = SpreadsheetApp.getActiveSpreadsheet();
    var sheet = ss.getSheetByName('Warga');
    if (!sheet) return { success: false, message: 'Sheet Warga tidak ditemukan.' };

    var data = sheet.getDataRange().getValues();
    var map = getColumnMap_(sheet);
    
    if (map['id_warga'] === undefined) {
      return { success: false, message: 'Kolom id_warga tidak ditemukan pada sheet Warga.' };
    }

    // Jika kolom status_warga belum ada di spreadsheet, buat kolomnya secara otomatis
    var statusColIdx = map['status_warga'];
    if (statusColIdx === undefined) {
      var lastCol = sheet.getLastColumn();
      sheet.getRange(1, lastCol + 1).setValue('status_warga');
      statusColIdx = lastCol;
    }

    var targetRow = -1;
    var targetSearchId = String(id_warga).trim().toLowerCase();
    for (var i = 1; i < data.length; i++) {
      var rowId = String(data[i][map['id_warga']]).trim().toLowerCase();
      if (rowId === targetSearchId) {
        targetRow = i + 1;
        break;
      }
    }

    // Fallback: pencarian berdasarkan NIK atau Nama jika id_warga tidak persis sama
    if (targetRow === -1) {
      for (var i = 1; i < data.length; i++) {
        var rowNik = map['nik'] !== undefined ? sanitizeDigitString_(data[i][map['nik']]).toLowerCase() : '';
        var rowNama = map['nama'] !== undefined ? String(data[i][map['nama']]).trim().toLowerCase() : '';
        if ((rowNik && rowNik === targetSearchId) || (rowNama && rowNama === targetSearchId)) {
          targetRow = i + 1;
          break;
        }
      }
    }

    if (targetRow === -1) {
      return { success: false, message: 'Data warga dengan ID ' + id_warga + ' tidak ditemukan di spreadsheet.' };
    }

    sheet.getRange(targetRow, statusColIdx + 1).setValue(newStatus);
    logAction_(session.username, 'UPDATE', 'Mengubah status warga ID ' + id_warga + ' menjadi ' + newStatus);
    return { success: true, message: 'Status warga berhasil diperbarui.' };
  } catch (e) {
    return { success: false, message: e.toString() };
  }
}

function deleteWarga(token, id_warga) {
  var session = validateSession_(token);
  if (!session.valid) return { success: false, message: session.message, sessionExpired: true };

  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('Warga');
  if (!sheet) return { success: false, message: 'Database Warga tidak ditemukan.' };

  var lock = LockService.getScriptLock();
  try {
    lock.waitLock(10000);
    var data = sheet.getDataRange().getValues();
    var map = getColumnMap_(sheet);

    for (var i = 1; i < data.length; i++) {
      if (String(data[i][map['id_warga']]) === id_warga) {
        var rowNum = i + 1;
        var namaWarga = data[i][map['nama']];
        sheet.deleteRow(rowNum);
        
        logAction_(session.username, 'DELETE', 'Menghapus warga: ' + namaWarga + ' (' + id_warga + ')');
        return { success: true };
      }
    }
    return { success: false, message: 'ID Warga tidak ditemukan.' };
  } catch (e) {
    return { success: false, message: e.toString() };
  } finally {
    lock.releaseLock();
  }
}

/**
 * CRUD Iuran
 */
function getIuranData(token) {
  var session = validateSession_(token);
  if (!session.valid) return { success: false, message: session.message, sessionExpired: true };

  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('Iuran');
  if (!sheet) return { success: true, data: [] };

  var data = sheet.getDataRange().getValues();
  if (data.length <= 1) return { success: true, data: [] };

  var map = getColumnMap_(data);
  var result = [];
  for (var i = 1; i < data.length; i++) {
    result.push({
      id_iuran: data[i][map['id_iuran']] || '',
      id_warga: data[i][map['id_warga']] || '',
      bulan: data[i][map['bulan']] || '',
      tahun: data[i][map['tahun']] || '',
      jumlah: parseInt(data[i][map['jumlah']] || 0, 10),
      tanggal_bayar: safeDateFormat_(data[i][map['tanggal_bayar']]),
      petugas_penerima: data[i][map['petugas_penerima']] || '',
      kategori: map['kategori'] !== undefined ? (data[i][map['kategori']] || 'Iuran Bulanan') : 'Iuran Bulanan',
      bukti: map['bukti'] !== undefined ? (data[i][map['bukti']] || '') : ''
    });
  }
  return { success: true, data: result };
}

function saveIuran(token, form) {
  var auth = requireRole_(token, 'Bendahara');
  if (!auth.authorized) return { success: false, message: auth.message, sessionExpired: auth.sessionExpired };
  var session = { username: auth.username };

  form.id_warga = sanitizeInput_(form.id_warga, 20);
  form.bulan = sanitizeInput_(form.bulan, 20);
  form.tahun = sanitizeInput_(form.tahun, 10);
  form.tanggal_bayar = sanitizeInput_(form.tanggal_bayar, 30);
  form.kategori = sanitizeInput_(form.kategori, 50);
  form.bukti = sanitizeInput_(form.bukti, 1000);

  if (!form.id_warga || !form.jumlah) return { success: false, message: 'Kelengkapan iuran wajib dipenuhi.' };

  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('Iuran');
  if (!sheet) return { success: false, message: 'Database Iuran tidak ditemukan.' };

  var lock = LockService.getScriptLock();
  try {
    lock.waitLock(10000);
    var map = getColumnMap_(sheet);
    var lastRow = sheet.getLastRow();
    
    var idNum = lastRow > 1 ? parseInt(String(sheet.getRange(lastRow, map['id_iuran'] + 1).getValue()).replace('TX-I-', '')) + 1 : 1;
    var newId = 'TX-I-' + ('000' + idNum).slice(-3);

    sheet.appendRow([
      newId,
      form.id_warga,
      form.bulan,
      form.tahun,
      form.jumlah,
      form.tanggal_bayar ? new Date(form.tanggal_bayar) : new Date(),
      session.username,
      form.kategori || 'Iuran Bulanan',
      form.bukti || ''
    ]);

    logAction_(session.username, 'CREATE', 'Menerima pembayaran iuran ' + form.bulan + ' ' + form.tahun + ' untuk ID Warga: ' + form.id_warga + ' (Kategori: ' + (form.kategori || 'Iuran Bulanan') + ')');
    return { success: true };
  } catch (e) {
    return { success: false, message: e.toString() };
  } finally {
    lock.releaseLock();
  }
}

function deleteIuran(token, id_iuran) {
  var auth = requireRole_(token, 'Bendahara');
  if (!auth.authorized) return { success: false, message: auth.message, sessionExpired: auth.sessionExpired };
  var session = { username: auth.username };

  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('Iuran');
  if (!sheet) return { success: false, message: 'Database Iuran tidak ditemukan.' };

  var lock = LockService.getScriptLock();
  try {
    lock.waitLock(10000);
    var data = sheet.getDataRange().getValues();
    var map = getColumnMap_(sheet);

    for (var i = 1; i < data.length; i++) {
      if (String(data[i][map['id_iuran']]) === id_iuran) {
        var rowNum = i + 1;

        // Calculate if deleting this iuran results in a negative cash balance
        var amount = parseInt(data[i][map['jumlah']] || 0, 10);
        
        // Calculate current total pemasukan
        var totalPemasukan = 0;
        for (var j = 1; j < data.length; j++) {
          totalPemasukan += parseInt(data[j][map['jumlah']] || 0, 10);
        }

        // Calculate current total pengeluaran
        var kasSheet = ss.getSheetByName('Kas_Keluar');
        var totalPengeluaran = 0;
        if (kasSheet && kasSheet.getLastRow() > 1) {
          var kasMap = getColumnMap_(kasSheet);
          var kasData = kasSheet.getDataRange().getValues();
          for (var k = 1; k < kasData.length; k++) {
            totalPengeluaran += parseInt(kasData[k][kasMap['jumlah']] || 0, 10);
          }
        }

        var sisaSaldo = totalPemasukan - totalPengeluaran;
        if (sisaSaldo - amount < 0) {
          return {
            success: false,
            message: 'Tidak dapat menghapus iuran ini karena sisa saldo kas saat ini (' + formatRupiahGAS_(sisaSaldo) + ') tidak mencukupi jika dikurangi nominal iuran ini (' + formatRupiahGAS_(amount) + '), yang akan menyebabkan saldo kas menjadi minus.'
          };
        }

        sheet.deleteRow(rowNum);
        
        logAction_(session.username, 'DELETE', 'Membatalkan / menghapus iuran invoice: ' + id_iuran);
        return { success: true };
      }
    }
    return { success: false, message: 'Invoice iuran tidak ditemukan.' };
  } catch (e) {
    return { success: false, message: e.toString() };
  } finally {
    lock.releaseLock();
  }
}

/**
 * CRUD Kas Keluar
 */
function getKasKeluarData(token) {
  var session = validateSession_(token);
  if (!session.valid) return { success: false, message: session.message, sessionExpired: true };

  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('Kas_Keluar');
  if (!sheet) return { success: true, data: [] };

  var data = sheet.getDataRange().getValues();
  if (data.length <= 1) return { success: true, data: [] };

  var map = getColumnMap_(data);
  var result = [];
  for (var i = 1; i < data.length; i++) {
    result.push({
      id_keluar: data[i][map['id_keluar']] || '',
      keperluan: data[i][map['keperluan']] || '',
      jumlah: parseInt(data[i][map['jumlah']] || 0, 10),
      tanggal_keluar: safeDateFormat_(data[i][map['tanggal_keluar']]),
      petugas: data[i][map['petugas']] || '',
      kategori: map['kategori'] !== undefined ? (data[i][map['kategori']] || 'Lain-lain') : 'Lain-lain',
      bukti: map['bukti'] !== undefined ? (data[i][map['bukti']] || '') : ''
    });
  }
  return { success: true, data: result };
}

function saveKasKeluar(token, form) {
  var auth = requireRole_(token, 'Bendahara');
  if (!auth.authorized) return { success: false, message: auth.message, sessionExpired: auth.sessionExpired };
  var session = { username: auth.username };

  form.keperluan = sanitizeInput_(form.keperluan, 300);
  form.tanggal_keluar = sanitizeInput_(form.tanggal_keluar, 30);
  form.kategori = sanitizeInput_(form.kategori, 50);
  form.bukti = sanitizeInput_(form.bukti, 1000);

  if (!form.keperluan || !form.jumlah) return { success: false, message: 'Data keperluan dan jumlah wajib diisi.' };

  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('Kas_Keluar');
  if (!sheet) return { success: false, message: 'Database Kas Keluar tidak ditemukan.' };

  var lock = LockService.getScriptLock();
  try {
    lock.waitLock(10000);
    var map = getColumnMap_(sheet);

    // Calculate current total pemasukan (Iuran)
    var iuranSheet = ss.getSheetByName('Iuran');
    var totalPemasukan = 0;
    if (iuranSheet && iuranSheet.getLastRow() > 1) {
      var iuranMap = getColumnMap_(iuranSheet);
      var iuranData = iuranSheet.getDataRange().getValues();
      for (var i = 1; i < iuranData.length; i++) {
        totalPemasukan += parseInt(iuranData[i][iuranMap['jumlah']] || 0, 10);
      }
    }

    // Calculate current total pengeluaran
    var totalPengeluaran = 0;
    var kasData = sheet.getDataRange().getValues();
    for (var i = 1; i < kasData.length; i++) {
      totalPengeluaran += parseInt(kasData[i][map['jumlah']] || 0, 10);
    }

    var sisaSaldo = totalPemasukan - totalPengeluaran;
    if (form.jumlah > sisaSaldo) {
      return {
        success: false,
        message: 'Saldo kas tidak mencukupi. Saldo kas saat ini: ' + formatRupiahGAS_(sisaSaldo) + ', sedangkan nominal pengeluaran: ' + formatRupiahGAS_(form.jumlah) + '.'
      };
    }

    var lastRow = sheet.getLastRow();
    var idNum = lastRow > 1 ? parseInt(String(sheet.getRange(lastRow, map['id_keluar'] + 1).getValue()).replace('TX-K-', '')) + 1 : 1;
    var newId = 'TX-K-' + ('000' + idNum).slice(-3);

    sheet.appendRow([
      newId,
      form.keperluan,
      form.jumlah,
      form.tanggal_keluar ? new Date(form.tanggal_keluar) : new Date(),
      session.username,
      form.kategori || 'Lain-lain',
      form.bukti || ''
    ]);

    logAction_(session.username, 'CREATE', 'Mencatat pengeluaran Kas RT (' + newId + '): ' + form.keperluan + ' senilai ' + form.jumlah + ' (Kategori: ' + (form.kategori || 'Lain-lain') + ')');
    return { success: true };
  } catch (e) {
    return { success: false, message: e.toString() };
  } finally {
    lock.releaseLock();
  }
}

function deleteKasKeluar(token, id_keluar) {
  var auth = requireRole_(token, 'Bendahara');
  if (!auth.authorized) return { success: false, message: auth.message, sessionExpired: auth.sessionExpired };
  var session = { username: auth.username };

  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('Kas_Keluar');
  if (!sheet) return { success: false, message: 'Database pengeluaran tidak ditemukan.' };

  var lock = LockService.getScriptLock();
  try {
    lock.waitLock(10000);
    var data = sheet.getDataRange().getValues();
    var map = getColumnMap_(sheet);

    for (var i = 1; i < data.length; i++) {
      if (String(data[i][map['id_keluar']]) === id_keluar) {
        var rowNum = i + 1;
        sheet.deleteRow(rowNum);
        
        logAction_(session.username, 'DELETE', 'Menghapus kas pengeluaran: ' + id_keluar);
        return { success: true };
      }
    }
    return { success: false, message: 'Invoice kas tidak ditemukan.' };
  } catch (e) {
    return { success: false, message: e.toString() };
  } finally {
    lock.releaseLock();
  }
}



/**
 * CRUD Aset & Inventaris RT/RW
 */
function getAsetData(token) {
  var session = validateSession_(token);
  if (!session.valid) return { success: false, message: session.message, sessionExpired: true };

  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('Aset');
  if (!sheet) return { success: true, data: [] };

  var data = sheet.getDataRange().getValues();
  if (data.length <= 1) return { success: true, data: [] };

  var map = getColumnMap_(data);
  var result = [];
  for (var i = 1; i < data.length; i++) {
    result.push({
      id_aset: data[i][map['id_aset']] || '',
      nama_barang: data[i][map['nama_barang']] || '',
      kategori: data[i][map['kategori']] || '',
      jumlah_total: parseInt(data[i][map['jumlah_total']] || 0, 10),
      jumlah_tersedia: parseInt(data[i][map['jumlah_tersedia']] || 0, 10),
      kondisi_fisik: data[i][map['kondisi_fisik']] || 'Baik',
      keterangan_lokasi: data[i][map['keterangan_lokasi']] || '',
      foto: data[i][map['foto']] || '',
      petugas: data[i][map['petugas']] || '',
      created_at: safeDateFormat_(data[i][map['created_at']])
    });
  }
  return { success: true, data: result };
}

function saveAset(token, form) {
  var session = validateSession_(token);
  if (!session.valid) return { success: false, message: session.message, sessionExpired: true };

  // Sanitasi Input
  form.nama_barang = sanitizeInput_(form.nama_barang, 100);
  form.kategori = sanitizeInput_(form.kategori, 50);
  form.jumlah_total = parseInt(form.jumlah_total || 0, 10);
  form.jumlah_tersedia = parseInt(form.jumlah_tersedia || 0, 10);
  form.kondisi_fisik = sanitizeInput_(form.kondisi_fisik, 30);
  form.keterangan_lokasi = sanitizeInput_(form.keterangan_lokasi, 500);
  form.foto = sanitizeInput_(form.foto, 1000);

  if (!form.nama_barang) return { success: false, message: 'Nama Barang wajib diisi.' };
  if (form.jumlah_tersedia > form.jumlah_total) {
    return { success: false, message: 'Jumlah tersedia tidak boleh melebihi jumlah total.' };
  }

  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('Aset');
  if (!sheet) return { success: false, message: 'Database Aset tidak ditemukan.' };

  var lock = LockService.getScriptLock();
  try {
    lock.waitLock(10000);
    var map = getColumnMap_(sheet);

    if (form.isEdit === true || form.isEdit === 'true') {
      var data = sheet.getDataRange().getValues();
      for (var i = 1; i < data.length; i++) {
        if (String(data[i][map['id_aset']]) === form.id_aset) {
          var rowNum = i + 1;
          sheet.getRange(rowNum, map['nama_barang'] + 1).setValue(form.nama_barang);
          sheet.getRange(rowNum, map['kategori'] + 1).setValue(form.kategori);
          sheet.getRange(rowNum, map['jumlah_total'] + 1).setValue(form.jumlah_total);
          sheet.getRange(rowNum, map['kondisi_fisik'] + 1).setValue(form.kondisi_fisik);
          sheet.getRange(rowNum, map['keterangan_lokasi'] + 1).setValue(form.keterangan_lokasi);
          if (form.foto) {
            sheet.getRange(rowNum, map['foto'] + 1).setValue(form.foto);
          }
          sheet.getRange(rowNum, map['petugas'] + 1).setValue(session.username);
          
          recalculateAsetStock_(ss);
          logAction_(session.username, 'UPDATE', 'Mengubah data aset (' + form.id_aset + '): ' + form.nama_barang);
          return { success: true };
        }
      }
      return { success: false, message: 'Data aset tidak ditemukan.' };
    } else {
      var lastRow = sheet.getLastRow();
      var idNum = lastRow > 1 ? parseInt(String(sheet.getRange(lastRow, map['id_aset'] + 1).getValue()).replace('AST-', '')) + 1 : 1;
      if (isNaN(idNum)) idNum = lastRow;
      var newId = 'AST-' + ('000' + idNum).slice(-3);

      sheet.appendRow([
        newId,
        form.nama_barang,
        form.kategori,
        form.jumlah_total,
        form.jumlah_total, // default awal sama dengan total
        form.kondisi_fisik || 'Baik',
        form.keterangan_lokasi,
        form.foto || '',
        session.username,
        new Date()
      ]);

      recalculateAsetStock_(ss);
      logAction_(session.username, 'CREATE', 'Mendaftarkan aset baru (' + newId + '): ' + form.nama_barang);
      return { success: true };
    }
  } catch (e) {
    return { success: false, message: e.toString() };
  } finally {
    lock.releaseLock();
  }
}

function deleteAset(token, id_aset) {
  var session = validateSession_(token);
  if (!session.valid) return { success: false, message: session.message, sessionExpired: true };

  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('Aset');
  if (!sheet) return { success: false, message: 'Database Aset tidak ditemukan.' };

  var lock = LockService.getScriptLock();
  try {
    lock.waitLock(10000);
    var data = sheet.getDataRange().getValues();
    var map = getColumnMap_(sheet);

    for (var i = 1; i < data.length; i++) {
      if (String(data[i][map['id_aset']]) === id_aset) {
        var rowNum = i + 1;
        var namaBarang = data[i][map['nama_barang']];
        sheet.deleteRow(rowNum);
        
        logAction_(session.username, 'DELETE', 'Menghapus aset (' + id_aset + '): ' + namaBarang);
        return { success: true };
      }
    }
    return { success: false, message: 'Data aset tidak ditemukan.' };
  } catch (e) {
    return { success: false, message: e.toString() };
  } finally {
    lock.releaseLock();
  }
}

/**
 * CRUD Users & Access Audit Logs (Semua akun pengurus dapat melihat daftar profil pengurus RT)
 */
function getUsersData(token) {
  var session = validateSession_(token);
  if (!session.valid) return { success: false, message: session.message, sessionExpired: true };

  var ss = SpreadsheetApp.getActiveSpreadsheet();
  
  // Ambil Data Users
  var userSheet = ss.getSheetByName('Users');
  if (userSheet) ensureUserColumns_(userSheet);

  var rawUsers = userSheet ? userSheet.getDataRange().getValues() : [];
  var mapU = userSheet ? getColumnMap_(userSheet) : {};
  var userList = [];
  var isUserAdmin = false;

  for (var i = 1; i < rawUsers.length; i++) {
    var uName = String(rawUsers[i][mapU['username']] || '').trim();
    var uRole = String(rawUsers[i][mapU['role']] || '').trim();
    if (uName.toLowerCase() === session.username.toLowerCase() && uRole === 'Admin') {
      isUserAdmin = true;
    }
    userList.push({
      username: uName,
      fullname: rawUsers[i][mapU['fullname']] || '',
      role: uRole,
      no_hp: mapU['no_hp'] !== undefined ? sanitizePhone_(rawUsers[i][mapU['no_hp']]) : '',
      email: mapU['email'] !== undefined ? (rawUsers[i][mapU['email']] || '') : ''
    });
  }

  // Ambil Data AuditLog (Khusus jika role Admin)
  var auditLogs = [];
  if (isUserAdmin) {
    var logSheet = ss.getSheetByName('AuditLog');
    var rawLogs = logSheet ? logSheet.getDataRange().getValues() : [];
    var mapL = logSheet ? getColumnMap_(logSheet) : {};
    
    var startIdx = Math.max(1, rawLogs.length - 100);
    for (var j = rawLogs.length - 1; j >= startIdx; j--) {
      auditLogs.push({
        timestamp: safeDateFormat_(rawLogs[j][mapL['timestamp']]),
        username: rawLogs[j][mapL['username']],
        action: rawLogs[j][mapL['action']],
        detail: rawLogs[j][mapL['detail']]
      });
    }
  }

  return {
    success: true,
    users: userList,
    auditLogs: auditLogs
  };
}

function saveUser(token, form) {
  var auth = requireRole_(token, 'Admin');
  if (!auth.authorized) return { success: false, message: auth.message, sessionExpired: auth.sessionExpired };

  form.fullname = sanitizeInput_(form.fullname, 100);
  form.username = sanitizeInput_(form.username, 50).toLowerCase();
  form.role = sanitizeInput_(form.role, 20);
  form.no_hp = sanitizePhone_(form.no_hp);
  form.email = sanitizeInput_(form.email || '', 100);

  if (!form.username || !form.password || !form.fullname) {
    return { success: false, message: 'Data pendaftaran petugas wajib lengkap.' };
  }

  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('Users');
  if (!sheet) return { success: false, message: 'Sheet Users tidak ditemukan.' };

  var lock = LockService.getScriptLock();
  try {
    lock.waitLock(10000);
    ensureUserColumns_(sheet);
    var map = getColumnMap_(sheet);
    var data = sheet.getDataRange().getValues();

    // Pastikan username tidak duplikat
    for (var i = 1; i < data.length; i++) {
      if (String(data[i][map['username']]).toLowerCase().trim() === form.username) {
        return { success: false, message: 'Username sudah digunakan oleh petugas lain.' };
      }
    }

    var hashedPass = hashPassword_(form.password);
    var headers = sheet.getRange(1, 1, 1, sheet.getLastColumn()).getValues()[0];
    var newRow = new Array(headers.length);
    newRow[map['username']] = form.username;
    newRow[map['password']] = hashedPass;
    newRow[map['fullname']] = form.fullname;
    newRow[map['role']] = form.role;
    if (map['acc_terms'] !== undefined) newRow[map['acc_terms']] = '';
    if (map['no_hp'] !== undefined) newRow[map['no_hp']] = "'" + form.no_hp;
    if (map['email'] !== undefined) newRow[map['email']] = form.email;

    sheet.appendRow(newRow);

    logAction_(auth.username, 'CREATE_USER', 'Mendaftarkan petugas baru: @' + form.username + ' (' + form.fullname + ')');
    return { success: true };
  } catch (e) {
    return { success: false, message: e.toString() };
  } finally {
    lock.releaseLock();
  }
}

function deleteUser(token, targetUsername) {
  var auth = requireRole_(token, 'Admin');
  if (!auth.authorized) return { success: false, message: auth.message, sessionExpired: auth.sessionExpired };

  if (targetUsername === 'admin') return { success: false, message: 'Akun Super Admin utama terlindungi dan tidak bisa dihapus.' };

  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('Users');
  if (!sheet) return { success: false, message: 'Sheet Users tidak ditemukan.' };

  var lock = LockService.getScriptLock();
  try {
    lock.waitLock(10000);
    var data = sheet.getDataRange().getValues();
    var map = getColumnMap_(sheet);

    for (var i = 1; i < data.length; i++) {
      if (String(data[i][map['username']]).toLowerCase().trim() === targetUsername.toLowerCase().trim()) {
        sheet.deleteRow(i + 1);
        
        logAction_(auth.username, 'DELETE_USER', 'Menghapus akses petugas: @' + targetUsername);
        return { success: true };
      }
    }
    return { success: false, message: 'Petugas tidak ditemukan.' };
  } catch (e) {
    return { success: false, message: e.toString() };
  } finally {
    lock.releaseLock();
  }
}

/**
 * SETUP DATABASE AWAL
 * Fungsi wajib dijalankan pertama kali setelah instalasi di GAS
 */
function setupDatabase_() {
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  
  // 1. Sheet Users
  var sheetUsers = ss.getSheetByName('Users');
  if (!sheetUsers) {
    sheetUsers = ss.insertSheet('Users');
    sheetUsers.appendRow(['username', 'password', 'fullname', 'role', 'acc_terms']);
    sheetUsers.setFrozenRows(1);
    
    // Simpan password default: "Admin@2026" dalam bentuk HASH SHA-256
    sheetUsers.appendRow(['admin', hashPassword_('Admin@2026'), 'Super Admin', 'Admin', '']);
    sheetUsers.appendRow(['bendahara', hashPassword_('Admin@2026'), 'Bendahara RT', 'Bendahara', '']);
    sheetUsers.appendRow(['staff', hashPassword_('Admin@2026'), 'Staff User', 'Staff', '']);
  } else {
    var headers = sheetUsers.getRange(1, 1, 1, sheetUsers.getLastColumn()).getValues()[0];
    var requiredHeaders = ['username', 'password', 'fullname', 'role', 'acc_terms'];
    requiredHeaders.forEach(function(h) {
      if (headers.indexOf(h) === -1) {
        sheetUsers.getRange(1, headers.length + 1).setValue(h);
        headers.push(h);
      }
    });
  }

  // 2. Sheet Warga
  var sheetWarga = ss.getSheetByName('Warga');
  var requiredWargaHeaders = ['id_warga', 'no_kk', 'nik', 'nama', 'no_rumah', 'jenis_kelamin', 'agama', 'tempat_lahir', 'tanggal_lahir', 'status_tinggal', 'status_pernikahan', 'posisi_keluarga', 'no_hp', 'status_warga', 'created_at'];
  if (!sheetWarga) {
    sheetWarga = ss.insertSheet('Warga');
    sheetWarga.appendRow(requiredWargaHeaders);
    sheetWarga.setFrozenRows(1);
  } else {
    var headers = sheetWarga.getRange(1, 1, 1, Math.max(1, sheetWarga.getLastColumn())).getValues()[0];
    requiredWargaHeaders.forEach(function(h) {
      if (headers.indexOf(h) === -1) {
        sheetWarga.getRange(1, headers.length + 1).setValue(h);
        headers.push(h);
      }
    });
  }

  // 3. Sheet Iuran
  var sheetIuran = ss.getSheetByName('Iuran');
  var requiredIuranHeaders = ['id_iuran', 'id_warga', 'bulan', 'tahun', 'jumlah', 'tanggal_bayar', 'petugas_penerima', 'kategori', 'bukti'];
  if (!sheetIuran) {
    sheetIuran = ss.insertSheet('Iuran');
    sheetIuran.appendRow(requiredIuranHeaders);
    sheetIuran.setFrozenRows(1);
  } else {
    var headers = sheetIuran.getRange(1, 1, 1, sheetIuran.getLastColumn()).getValues()[0];
    requiredIuranHeaders.forEach(function(h) {
      if (headers.indexOf(h) === -1) {
        sheetIuran.getRange(1, headers.length + 1).setValue(h);
        headers.push(h);
      }
    });
  }

  // 4. Sheet Kas Keluar
  var sheetKas = ss.getSheetByName('Kas_Keluar');
  var requiredKasHeaders = ['id_keluar', 'keperluan', 'jumlah', 'tanggal_keluar', 'petugas', 'kategori', 'bukti'];
  if (!sheetKas) {
    sheetKas = ss.insertSheet('Kas_Keluar');
    sheetKas.appendRow(requiredKasHeaders);
    sheetKas.setFrozenRows(1);
  } else {
    var headers = sheetKas.getRange(1, 1, 1, sheetKas.getLastColumn()).getValues()[0];
    requiredKasHeaders.forEach(function(h) {
      if (headers.indexOf(h) === -1) {
        sheetKas.getRange(1, headers.length + 1).setValue(h);
        headers.push(h);
      }
    });
  }



  // 6. Sheet AuditLog
  var sheetLog = ss.getSheetByName('AuditLog');
  if (!sheetLog) {
    sheetLog = ss.insertSheet('AuditLog');
    sheetLog.appendRow(['timestamp', 'username', 'action', 'detail']);
    sheetLog.setFrozenRows(1);
  } else {
    var headers = sheetLog.getRange(1, 1, 1, sheetLog.getLastColumn()).getValues()[0];
    var requiredHeaders = ['timestamp', 'username', 'action', 'detail'];
    requiredHeaders.forEach(function(h) {
      if (headers.indexOf(h) === -1) {
        sheetLog.getRange(1, headers.length + 1).setValue(h);
        headers.push(h);
      }
    });
  }

  // 7. Sheet Ceklist_Iuran
  var sheetCeklist = ss.getSheetByName('Ceklist_Iuran');
  var requiredCeklistHeaders = ['id_ceklist', 'id_warga', 'nama_warga', 'no_rumah', 'tahun', 'jan', 'feb', 'mar', 'apr', 'mei', 'jun', 'jul', 'agt', 'sep', 'okt', 'nov', 'des'];
  if (!sheetCeklist) {
    sheetCeklist = ss.insertSheet('Ceklist_Iuran');
    sheetCeklist.appendRow(requiredCeklistHeaders);
    sheetCeklist.setFrozenRows(1);
  } else {
    var headers = sheetCeklist.getRange(1, 1, 1, sheetCeklist.getLastColumn()).getValues()[0];
    requiredCeklistHeaders.forEach(function(h) {
      if (headers.indexOf(h) === -1) {
        sheetCeklist.getRange(1, headers.length + 1).setValue(h);
        headers.push(h);
      }
    });
  }

  // 8. Sheet Settings
  var sheetSettings = ss.getSheetByName('Settings');
  if (!sheetSettings) {
    sheetSettings = ss.insertSheet('Settings');
    sheetSettings.appendRow(['key', 'value']);
    sheetSettings.setFrozenRows(1);
    
    // Set default key-value pairs
    sheetSettings.appendRow(['nominal_iuran', '20000']);
    sheetSettings.appendRow(['kategori_pemasukan', '["Iuran Bulanan", "Sumbangan", "Lain-lain"]']);
    sheetSettings.appendRow(['kategori_pengeluaran', '["Kebersihan", "Keamanan", "Sosial", "Operasional", "Lain-lain"]']);
    sheetSettings.appendRow(['kategori_aset', '["Peralatan", "Perlengkapan Acara", "Alat Kebersihan", "Lain-lain"]']);
    sheetSettings.appendRow(['pdf_label_kota_tanggal', 'Jakarta, 06 Juni 2026']);
    sheetSettings.appendRow(['pdf_label_bendahara', 'Bendahara']);
    sheetSettings.appendRow(['pdf_nama_bendahara', 'Bambang Trianto']);
    sheetSettings.appendRow(['pdf_label_ketua', 'Ketua RT']);
    sheetSettings.appendRow(['pdf_nama_ketua', 'Budi Santoso']);
  }
  
  var headers = sheetSettings.getRange(1, 1, 1, sheetSettings.getLastColumn()).getValues()[0];
  var requiredHeaders = ['key', 'value'];
  requiredHeaders.forEach(function(h) {
    if (headers.indexOf(h) === -1) {
      sheetSettings.getRange(1, headers.length + 1).setValue(h);
      headers.push(h);
    }
  });
  
  var data = sheetSettings.getDataRange().getValues();
  var keys = data.map(function(row) { return row[0]; });
  
  if (keys.indexOf('nominal_iuran') === -1) {
    sheetSettings.appendRow(['nominal_iuran', '20000']);
  }
  if (keys.indexOf('kategori_pemasukan') === -1) {
    sheetSettings.appendRow(['kategori_pemasukan', '["Iuran Bulanan", "Sumbangan", "Lain-lain"]']);
  }
  if (keys.indexOf('kategori_pengeluaran') === -1) {
    sheetSettings.appendRow(['kategori_pengeluaran', '["Kebersihan", "Keamanan", "Sosial", "Operasional", "Lain-lain"]']);
  }
  if (keys.indexOf('kategori_aset') === -1) {
    sheetSettings.appendRow(['kategori_aset', '["Peralatan", "Perlengkapan Acara", "Alat Kebersihan", "Lain-lain"]']);
  }
  if (keys.indexOf('kategori_surat') === -1) {
    sheetSettings.appendRow(['kategori_surat', '["Pembuatan KTP", "Pembuatan KK", "Surat Keterangan Domisili", "Surat Keterangan Usaha", "Surat Keterangan Tidak Mampu", "Lainnya"]']);
  }
  
  var defaultPdfSettings = {
    pdf_label_kota_tanggal: 'Jakarta, 06 Juni 2026',
    pdf_label_bendahara: 'Bendahara',
    pdf_nama_bendahara: 'Bambang Trianto',
    pdf_label_ketua: 'Ketua RT',
    pdf_nama_ketua: 'Budi Santoso'
  };
  Object.keys(defaultPdfSettings).forEach(function(key) {
    if (keys.indexOf(key) === -1) {
      sheetSettings.appendRow([key, defaultPdfSettings[key]]);
    }
  });

  var defaultLayoutSettings = {
    rt_name: 'RT01RW05',
    rt_logo: '',
    hero_title: 'Solusi Digital RT/RW: <br><span><small>Lebih Dekat, Lebih Mudah, Lebih Harmonis</small></span>',
    hero_subtitle: 'Layanan RT01 RW05 Kelurahan Limbungan, Kecamatan Rumbai Timur, Pekanbaru dalam satu aplikasi: Komunikasi lebih lancar, informasi lebih cepat, urusan warga makin praktis.',
    footer_copyright: '© 2026 Portal RTRW Digital. Seluruh hak cipta dilindungi.',
    footer_link_1_text: 'Tentang Kami',
    footer_link_1_url: '#',
    footer_link_2_text: 'Kebijakan Privasi',
    footer_link_2_url: '#',
    footer_link_3_text: 'Syarat & Ketentuan',
    footer_link_3_url: '#',
    footer_link_4_text: 'Bantuan',
    footer_link_4_url: '#'
  };
  Object.keys(defaultLayoutSettings).forEach(function(key) {
    if (keys.indexOf(key) === -1) {
      sheetSettings.appendRow([key, defaultLayoutSettings[key]]);
    }
  });

  // 9. Sheet Aset
  var sheetAset = ss.getSheetByName('Aset');
  var requiredAsetHeaders = ['id_aset', 'nama_barang', 'kategori', 'jumlah_total', 'jumlah_tersedia', 'kondisi_fisik', 'keterangan_lokasi', 'foto', 'petugas', 'created_at'];
  if (!sheetAset) {
    sheetAset = ss.insertSheet('Aset');
    sheetAset.appendRow(requiredAsetHeaders);
    sheetAset.setFrozenRows(1);
  } else {
    var headers = sheetAset.getRange(1, 1, 1, sheetAset.getLastColumn()).getValues()[0];
    requiredAsetHeaders.forEach(function(h) {
      if (headers.indexOf(h) === -1) {
        sheetAset.getRange(1, headers.length + 1).setValue(h);
        headers.push(h);
      }
    });
  }

  // 10. Sheet Permohonan_Surat
  var sheetPermohonanSurat = ss.getSheetByName('Permohonan_Surat');
  var requiredSuratHeaders = ['id_tiket', 'tanggal', 'jenis_layanan', 'nama_pemohon', 'no_wa', 'nik_no_rumah', 'detail_permintaan', 'no_surat', 'status'];
  if (!sheetPermohonanSurat) {
    sheetPermohonanSurat = ss.insertSheet('Permohonan_Surat');
    sheetPermohonanSurat.appendRow(requiredSuratHeaders);
    sheetPermohonanSurat.setFrozenRows(1);
  } else {
    var headers = sheetPermohonanSurat.getRange(1, 1, 1, sheetPermohonanSurat.getLastColumn()).getValues()[0];
    requiredSuratHeaders.forEach(function(h) {
      if (headers.indexOf(h) === -1) {
        sheetPermohonanSurat.getRange(1, headers.length + 1).setValue(h);
        headers.push(h);
      }
    });
  }

  // 11. Sheet Peminjaman_Aset
  var sheetPeminjamanAset = ss.getSheetByName('Peminjaman_Aset');
  var requiredPeminjamanHeaders = ['id_tiket', 'tanggal', 'nama_peminjam', 'no_wa', 'no_rumah', 'barang', 'jumlah_unit', 'tanggal_pinjam', 'tanggal_kembali', 'detail_peminjaman', 'status'];
  if (!sheetPeminjamanAset) {
    sheetPeminjamanAset = ss.insertSheet('Peminjaman_Aset');
    sheetPeminjamanAset.appendRow(requiredPeminjamanHeaders);
    sheetPeminjamanAset.setFrozenRows(1);
  } else {
    var headers = sheetPeminjamanAset.getRange(1, 1, 1, sheetPeminjamanAset.getLastColumn()).getValues()[0];
    requiredPeminjamanHeaders.forEach(function(h) {
      if (headers.indexOf(h) === -1) {
        sheetPeminjamanAset.getRange(1, headers.length + 1).setValue(h);
        headers.push(h);
      }
    });
  }

  // 12. Sheet Pengaduan_Saran
  var sheetPengaduanSaran = ss.getSheetByName('Pengaduan_Saran');
  var requiredPengaduanHeaders = ['id_tiket', 'tanggal', 'jenis_layanan', 'nama_pengadu', 'no_wa', 'lokasi_kejadian', 'detail_pengaduan', 'bukti_foto', 'status'];
  if (!sheetPengaduanSaran) {
    sheetPengaduanSaran = ss.insertSheet('Pengaduan_Saran');
    sheetPengaduanSaran.appendRow(requiredPengaduanHeaders);
    sheetPengaduanSaran.setFrozenRows(1);
  } else {
    var headers = sheetPengaduanSaran.getRange(1, 1, 1, sheetPengaduanSaran.getLastColumn()).getValues()[0];
    requiredPengaduanHeaders.forEach(function(h) {
      if (headers.indexOf(h) === -1) {
        sheetPengaduanSaran.getRange(1, headers.length + 1).setValue(h);
        headers.push(h);
      }
    });
  }

  // 13. Sheet Agenda
  var sheetAgenda = ss.getSheetByName('Agenda');
  var requiredAgendaHeaders = ['id_agenda', 'judul_kegiatan', 'kategori', 'tanggal_jam', 'lokasi', 'status', 'petugas', 'created_at', 'url_laporan', 'url_notulen'];
  if (!sheetAgenda) {
    sheetAgenda = ss.insertSheet('Agenda');
    sheetAgenda.appendRow(requiredAgendaHeaders);
    sheetAgenda.setFrozenRows(1);
  } else {
    var headers = sheetAgenda.getRange(1, 1, 1, sheetAgenda.getLastColumn()).getValues()[0];
    requiredAgendaHeaders.forEach(function(h) {
      if (headers.indexOf(h) === -1) {
        sheetAgenda.getRange(1, headers.length + 1).setValue(h);
        headers.push(h);
      }
    });
  }

  // 14. Sheet Pengumuman
  var sheetPengumuman = ss.getSheetByName('Pengumuman');
  var requiredPengumumanHeaders = ['id_pengumuman', 'tanggal', 'tipe', 'judul', 'isi_pengumuman', 'petugas', 'created_at'];
  if (!sheetPengumuman) {
    sheetPengumuman = ss.insertSheet('Pengumuman');
    sheetPengumuman.appendRow(requiredPengumumanHeaders);
    sheetPengumuman.setFrozenRows(1);
  } else {
    var headers = sheetPengumuman.getRange(1, 1, 1, sheetPengumuman.getLastColumn()).getValues()[0];
    requiredPengumumanHeaders.forEach(function(h) {
      if (headers.indexOf(h) === -1) {
        sheetPengumuman.getRange(1, headers.length + 1).setValue(h);
        headers.push(h);
      }
    });
  }

  // 15. Sheet UMKM
  var sheetUmkm = ss.getSheetByName('UMKM');
  var requiredUmkmHeaders = ['id_umkm', 'id_warga', 'nama_pemilik', 'nama_usaha', 'kategori_usaha', 'deskripsi', 'no_hp', 'alamat_lokasi', 'foto_produk', 'status', 'created_at'];
  if (!sheetUmkm) {
    sheetUmkm = ss.insertSheet('UMKM');
    sheetUmkm.appendRow(requiredUmkmHeaders);
    sheetUmkm.setFrozenRows(1);
  } else {
    var headers = sheetUmkm.getRange(1, 1, 1, Math.max(1, sheetUmkm.getLastColumn())).getValues()[0];
    requiredUmkmHeaders.forEach(function(h) {
      if (headers.indexOf(h) === -1) {
        sheetUmkm.getRange(1, headers.length + 1).setValue(h);
        headers.push(h);
      }
    });
  }

  // Hapus lembar kerja default 'Sheet1' / 'Sheet 1' jika ada agar lebih rapi
  var defaultSheet = ss.getSheetByName('Sheet1') || ss.getSheetByName('Sheet 1');
  if (defaultSheet && ss.getSheets().length > 1) {
    ss.deleteSheet(defaultSheet);
  }

  return 'Database Berhasil Dibuat/Diverifikasi!';
}

/**
 * Mengambil Data Checklist Iuran Warga per Tahun Buku
 */
function getCeklistIuranData(token, tahun) {
  var session = validateSession_(token);
  if (!session.valid) return { success: false, message: session.message, sessionExpired: true };

  tahun = String(tahun || new Date().getFullYear());

  var ss = SpreadsheetApp.getActiveSpreadsheet();
  
  // 1. Ambil Warga Aktif
  var wargaSheet = ss.getSheetByName('Warga');
  if (!wargaSheet) return { success: false, message: 'Database Warga tidak ditemukan.' };
  var rawWarga = wargaSheet.getDataRange().getValues();
  var mapW = getColumnMap_(wargaSheet);
  
  var hasKepalaKeluarga = false;
  for (var i = 1; i < rawWarga.length; i++) {
    var status = String(rawWarga[i][mapW['status_warga']] || 'Aktif');
    var posisi = String(rawWarga[i][mapW['posisi_keluarga']] || '').trim();
    if (status === 'Aktif' && (posisi === 'Kepala Keluarga' || posisi === 'KEPALA KELUARGA')) {
      hasKepalaKeluarga = true;
      break;
    }
  }

  var activeWargaList = [];
  for (var i = 1; i < rawWarga.length; i++) {
    var status = String(rawWarga[i][mapW['status_warga']] || 'Aktif');
    var posisi = String(rawWarga[i][mapW['posisi_keluarga']] || '').trim();
    if (status === 'Aktif') {
      if (hasKepalaKeluarga) {
        if (posisi === 'Kepala Keluarga' || posisi === 'KEPALA KELUARGA' || posisi === '' || posisi === '-') {
          activeWargaList.push({
            id_warga: String(rawWarga[i][mapW['id_warga']]),
            nama: String(rawWarga[i][mapW['nama']]),
            no_rumah: String(rawWarga[i][mapW['no_rumah']])
          });
        }
      } else {
        activeWargaList.push({
          id_warga: String(rawWarga[i][mapW['id_warga']]),
          nama: String(rawWarga[i][mapW['nama']]),
          no_rumah: String(rawWarga[i][mapW['no_rumah']])
        });
      }
    }
  }

  // 2. Ambil data checklist yang ada di database untuk tahun ini
  var ceklistSheet = ss.getSheetByName('Ceklist_Iuran');
  var rawCeklist = ceklistSheet ? ceklistSheet.getDataRange().getValues() : [];
  var mapC = ceklistSheet ? getColumnMap_(ceklistSheet) : {};
  
  var ceklistMap = {};
  if (ceklistSheet && rawCeklist.length > 1) {
    for (var i = 1; i < rawCeklist.length; i++) {
      var rowTahun = String(rawCeklist[i][mapC['tahun']]);
      if (rowTahun === tahun) {
        var idW = String(rawCeklist[i][mapC['id_warga']]);
        ceklistMap[idW] = {
          id_ceklist: String(rawCeklist[i][mapC['id_ceklist']]),
          jan: rawCeklist[i][mapC['jan']] === true || String(rawCeklist[i][mapC['jan']]).toUpperCase() === 'TRUE',
          feb: rawCeklist[i][mapC['feb']] === true || String(rawCeklist[i][mapC['feb']]).toUpperCase() === 'TRUE',
          mar: rawCeklist[i][mapC['mar']] === true || String(rawCeklist[i][mapC['mar']]).toUpperCase() === 'TRUE',
          apr: rawCeklist[i][mapC['apr']] === true || String(rawCeklist[i][mapC['apr']]).toUpperCase() === 'TRUE',
          mei: rawCeklist[i][mapC['mei']] === true || String(rawCeklist[i][mapC['mei']]).toUpperCase() === 'TRUE',
          jun: rawCeklist[i][mapC['jun']] === true || String(rawCeklist[i][mapC['jun']]).toUpperCase() === 'TRUE',
          jul: rawCeklist[i][mapC['jul']] === true || String(rawCeklist[i][mapC['jul']]).toUpperCase() === 'TRUE',
          agt: rawCeklist[i][mapC['agt']] === true || String(rawCeklist[i][mapC['agt']]).toUpperCase() === 'TRUE',
          sep: rawCeklist[i][mapC['sep']] === true || String(rawCeklist[i][mapC['sep']]).toUpperCase() === 'TRUE',
          okt: rawCeklist[i][mapC['okt']] === true || String(rawCeklist[i][mapC['okt']]).toUpperCase() === 'TRUE',
          nov: rawCeklist[i][mapC['nov']] === true || String(rawCeklist[i][mapC['nov']]).toUpperCase() === 'TRUE',
          des: rawCeklist[i][mapC['des']] === true || String(rawCeklist[i][mapC['des']]).toUpperCase() === 'TRUE'
        };
      }
    }
  }

  // 3. Gabungkan: Pastikan semua warga aktif punya baris data
  var result = [];
  activeWargaList.forEach(function(w) {
    var dbEntry = ceklistMap[w.id_warga];
    if (dbEntry) {
      result.push({
        id_warga: w.id_warga,
        nama: w.nama,
        no_rumah: w.no_rumah,
        tahun: tahun,
        id_ceklist: dbEntry.id_ceklist,
        jan: dbEntry.jan,
        feb: dbEntry.feb,
        mar: dbEntry.mar,
        apr: dbEntry.apr,
        mei: dbEntry.mei,
        jun: dbEntry.jun,
        jul: dbEntry.jul,
        agt: dbEntry.agt,
        sep: dbEntry.sep,
        okt: dbEntry.okt,
        nov: dbEntry.nov,
        des: dbEntry.des
      });
    } else {
      result.push({
        id_warga: w.id_warga,
        nama: w.nama,
        no_rumah: w.no_rumah,
        tahun: tahun,
        id_ceklist: '',
        jan: false,
        feb: false,
        mar: false,
        apr: false,
        mei: false,
        jun: false,
        jul: false,
        agt: false,
        sep: false,
        okt: false,
        nov: false,
        des: false
      });
    }
  });

  return {
    success: true,
    data: result
  };
}

/**
 * Toggle Status Checklist Iuran Warga & Sinkronisasi ke Transaksi Iuran
 */
function toggleIuranCeklist(token, id_warga, bulan, tahun, isChecked, customNominal) {
  var auth = requireRole_(token, 'Bendahara');
  if (!auth.authorized) return { success: false, message: auth.message, sessionExpired: auth.sessionExpired };
  var session = { username: auth.username };

  // Sanitasi & Validasi Input
  id_warga = sanitizeInput_(id_warga, 20);
  bulan = sanitizeInput_(bulan, 20); // e.g., "Januari" atau "Jan"

  var monthNameMap = {
    'jan': 'Januari', 'feb': 'Februari', 'mar': 'Maret', 'apr': 'April',
    'mei': 'Mei', 'jun': 'Juni', 'jul': 'Juli', 'agt': 'Agustus',
    'sep': 'September', 'okt': 'Oktober', 'nov': 'November', 'des': 'Desember'
  };
  
  var shortBulan = String(bulan).toLowerCase().substring(0, 3);
  if (shortBulan === 'mei') shortBulan = 'mei';
  if (shortBulan === 'agu') shortBulan = 'agt';
  if (shortBulan === 'okt') shortBulan = 'okt';
  if (shortBulan === 'des') shortBulan = 'des';
  
  var fullBulanName = monthNameMap[shortBulan];
  if (!fullBulanName) {
    return { success: false, message: 'Nama bulan tidak dikenali: ' + bulan };
  }

  tahun = String(tahun);
  isChecked = (isChecked === true || isChecked === 'true');

  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var lock = LockService.getScriptLock();
  try {
    lock.waitLock(15000); // Wait up to 15 seconds

    var nominal = 20000;
    if (customNominal !== undefined && customNominal !== null && parseInt(customNominal, 10) > 0) {
      nominal = parseInt(customNominal, 10);
    } else {
      var settingsSheet = ss.getSheetByName('Settings');
      if (settingsSheet) {
        var settingsMap = getColumnMap_(settingsSheet);
        var settingsData = settingsSheet.getDataRange().getValues();
        var defaultNominal = 20000;
        var tarifMapStr = '';
        for (var k = 1; k < settingsData.length; k++) {
          var kKey = String(settingsData[k][settingsMap['key']]).trim();
          if (kKey === 'nominal_iuran') {
            defaultNominal = parseInt(settingsData[k][settingsMap['value']] || '20000', 10);
          } else if (kKey === 'tarif_iuran_bulanan') {
            tarifMapStr = String(settingsData[k][settingsMap['value']] || '');
          }
        }
        nominal = defaultNominal;
        if (tarifMapStr) {
          try {
            var parsedTarifMap = JSON.parse(tarifMapStr);
            var yrStr = String(tahun);
            if (parsedTarifMap && parsedTarifMap[yrStr] && parsedTarifMap[yrStr][shortBulan] !== undefined) {
              var monthNominalYr = parseInt(parsedTarifMap[yrStr][shortBulan], 10);
              if (!isNaN(monthNominalYr) && monthNominalYr > 0) nominal = monthNominalYr;
            } else if (parsedTarifMap && parsedTarifMap[shortBulan] !== undefined) {
              var monthNominal = parseInt(parsedTarifMap[shortBulan], 10);
              if (!isNaN(monthNominal) && monthNominal > 0) nominal = monthNominal;
            }
          } catch (e) {}
        }
      }
    }

    // 1. Dapatkan nama warga dan no_rumah dari sheet Warga
    var wargaSheet = ss.getSheetByName('Warga');
    var mapW = getColumnMap_(wargaSheet);
    var rawWarga = wargaSheet.getDataRange().getValues();
    var namaWarga = '';
    var noRumah = '';
    for (var i = 1; i < rawWarga.length; i++) {
      if (String(rawWarga[i][mapW['id_warga']]) === id_warga) {
        namaWarga = String(rawWarga[i][mapW['nama']]);
        noRumah = String(rawWarga[i][mapW['no_rumah']]);
        break;
      }
    }

    if (!namaWarga) {
      return { success: false, message: 'Warga dengan ID ' + id_warga + ' tidak ditemukan.' };
    }

    // 2. Perbarui Sheet Ceklist_Iuran
    var ceklistSheet = ss.getSheetByName('Ceklist_Iuran');
    if (!ceklistSheet) {
      return { success: false, message: 'Database Ceklist Iuran belum siap.' };
    }
    
    var mapC = getColumnMap_(ceklistSheet);
    var rawCeklist = ceklistSheet.getDataRange().getValues();
    var rowNum = -1;
    
    for (var i = 1; i < rawCeklist.length; i++) {
      if (String(rawCeklist[i][mapC['id_warga']]) === id_warga && String(rawCeklist[i][mapC['tahun']]) === tahun) {
        rowNum = i + 1;
        break;
      }
    }

    var requiredCeklistHeaders = ['id_ceklist', 'id_warga', 'nama_warga', 'no_rumah', 'tahun', 'jan', 'feb', 'mar', 'apr', 'mei', 'jun', 'jul', 'agt', 'sep', 'okt', 'nov', 'des'];

    if (rowNum === -1) {
      // Buat baris baru untuk warga ini di tahun ini
      var lastRow = ceklistSheet.getLastRow();
      var idNum = lastRow > 1 ? parseInt(String(ceklistSheet.getRange(lastRow, mapC['id_ceklist'] + 1).getValue()).replace('CK-', '')) + 1 : 1;
      if (isNaN(idNum)) idNum = lastRow;
      var newId = 'CK-' + ('000' + idNum).slice(-3);

      var newRow = new Array(requiredCeklistHeaders.length);
      for (var colIdx = 0; colIdx < requiredCeklistHeaders.length; colIdx++) {
        var hName = requiredCeklistHeaders[colIdx];
        if (hName === 'id_ceklist') newRow[colIdx] = newId;
        else if (hName === 'id_warga') newRow[colIdx] = id_warga;
        else if (hName === 'nama_warga') newRow[colIdx] = namaWarga;
        else if (hName === 'no_rumah') newRow[colIdx] = noRumah;
        else if (hName === 'tahun') newRow[colIdx] = tahun;
        else newRow[colIdx] = false;
      }
      
      ceklistSheet.appendRow(newRow);
      rowNum = ceklistSheet.getLastRow();
    } else {
      // Sinkronkan nama dan no_rumah barangkali ada perubahan
      ceklistSheet.getRange(rowNum, mapC['nama_warga'] + 1).setValue(namaWarga);
      ceklistSheet.getRange(rowNum, mapC['no_rumah'] + 1).setValue(noRumah);
    }

    // Set nilai di kolom bulan terkait
    var colBulanIdx = mapC[shortBulan];
    if (colBulanIdx !== undefined) {
      ceklistSheet.getRange(rowNum, colBulanIdx + 1).setValue(isChecked);
    }

    // 3. Sinkronisasikan ke Sheet Iuran (Transaksi)
    var iuranSheet = ss.getSheetByName('Iuran');
    var mapI = getColumnMap_(iuranSheet);
    var rawIuran = iuranSheet.getDataRange().getValues();

    if (isChecked) {
      // Tambah Transaksi Iuran (jika belum terdaftar transaksi yang sama)
      var transExists = false;
      for (var i = 1; i < rawIuran.length; i++) {
        if (String(rawIuran[i][mapI['id_warga']]) === id_warga &&
            String(rawIuran[i][mapI['bulan']]) === fullBulanName &&
            String(rawIuran[i][mapI['tahun']]) === tahun) {
          transExists = true;
          break;
        }
      }

      if (!transExists) {
        var lastTxRow = iuranSheet.getLastRow();
        var idNum = lastTxRow > 1 ? parseInt(String(iuranSheet.getRange(lastTxRow, mapI['id_iuran'] + 1).getValue()).replace('TX-I-', '')) + 1 : 1;
        if (isNaN(idNum)) idNum = lastTxRow;
        var newTxId = 'TX-I-' + ('000' + idNum).slice(-3);

        iuranSheet.appendRow([
          newTxId,
          id_warga,
          fullBulanName,
          tahun,
          nominal,
          new Date(),
          session.username,
          'Iuran Bulanan'
        ]);
        
        logAction_(session.username, 'CREATE', 'Menerima iuran ' + fullBulanName + ' ' + tahun + ' via Ceklist untuk Warga: ' + namaWarga + ' (' + id_warga + ')');
      }
    } else {
      // Check if removing this iuran causes the balance to go negative
      var totalPemasukan = 0;
      for (var j = 1; j < rawIuran.length; j++) {
        totalPemasukan += parseInt(rawIuran[j][mapI['jumlah']] || 0, 10);
      }

      var kasSheet = ss.getSheetByName('Kas_Keluar');
      var totalPengeluaran = 0;
      if (kasSheet && kasSheet.getLastRow() > 1) {
        var kasMap = getColumnMap_(kasSheet);
        var kasData = kasSheet.getDataRange().getValues();
        for (var k = 1; k < kasData.length; k++) {
          totalPengeluaran += parseInt(kasData[k][kasMap['jumlah']] || 0, 10);
        }
      }

      var sisaSaldo = totalPemasukan - totalPengeluaran;
      if (sisaSaldo - nominal < 0) {
        return {
          success: false,
          message: 'Iuran tidak dapat dibatalkan karena sisa saldo kas saat ini (' + formatRupiahGAS_(sisaSaldo) + ') tidak mencukupi jika dikurangi nominal iuran ini (' + formatRupiahGAS_(nominal) + '), yang akan menyebabkan saldo kas menjadi minus.'
        };
      }

      // Hapus Transaksi Iuran yang cocok
      var txDeleted = false;
      for (var i = rawIuran.length - 1; i >= 1; i--) {
        if (String(rawIuran[i][mapI['id_warga']]) === id_warga &&
            String(rawIuran[i][mapI['bulan']]) === fullBulanName &&
            String(rawIuran[i][mapI['tahun']]) === tahun) {
          var rowToDelete = i + 1;
          iuranSheet.deleteRow(rowToDelete);
          txDeleted = true;
          break;
        }
      }

      if (txDeleted) {
        logAction_(session.username, 'DELETE', 'Membatalkan iuran ' + fullBulanName + ' ' + tahun + ' via Ceklist untuk Warga: ' + namaWarga + ' (' + id_warga + ')');
      }
    }

    return { success: true };
  } catch (e) {
    return { success: false, message: e.toString() };
  } finally {
    lock.releaseLock();
  }
}

/**
 * Mendapatkan Pengaturan Dinamis dari Database
 */
function getSettingsData(token) {
  var session = validateSession_(token);
  if (!session.valid) return { success: false, message: session.message, sessionExpired: true };

  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('Settings');
  if (!sheet) return { success: false, message: 'Database Settings belum inisialisasi.' };

  var data = sheet.getDataRange().getValues();
  var map = getColumnMap_(sheet);
  
  var settings = {
    nominal_iuran: 20000,
    kategori_pemasukan: ["Iuran Bulanan", "Sumbangan", "Lain-lain"],
    kategori_pengeluaran: ["Kebersihan", "Keamanan", "Sosial", "Operasional", "Lain-lain"],
    kategori_umkm: [
      "Kuliner / Makanan & Minuman",
      "Sembako / Toko Manisan",
      "Jasa / Service",
      "Fashion & Pakaian",
      "Kerajinan / Kriya",
      "Pertanian / Peternakan",
      "Lain-lain"
    ]
  };

  for (var i = 1; i < data.length; i++) {
    var key = String(data[i][map['key']]).trim();
    var val = String(data[i][map['value']]).trim();
    
    if (key === 'nominal_iuran') {
      settings.nominal_iuran = parseInt(val || '20000', 10);
    } else if (key === 'tarif_iuran_bulanan') {
      try {
        settings.tarif_iuran_bulanan = JSON.parse(val);
      } catch (e) {
        settings.tarif_iuran_bulanan = val;
      }
    } else if (key.indexOf('kategori_') === 0) {
      try {
        settings[key] = JSON.parse(val);
      } catch (e) {
        settings[key] = val.split(',').map(function(s) { return s.trim(); });
      }
    } else {
      settings[key] = val;
    }
  }

  return { success: true, settings: settings };
}
/**
 * Menyimpan Pengaturan Baru ke Database
 */
function saveSettingsData(token, settingsObj) {
  var auth = requireRole_(token, 'Staff'); // Staff or Admin
  if (!auth.authorized) return { success: false, message: auth.message, sessionExpired: auth.sessionExpired };

  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('Settings');
  if (!sheet) return { success: false, message: 'Database Settings tidak ditemukan.' };

  var lock = LockService.getScriptLock();
  try {
    lock.waitLock(10000);
    var map = getColumnMap_(sheet);
    var data = sheet.getDataRange().getValues();

    var updateKey = function(keyName, valueStr) {
      for (var i = 1; i < data.length; i++) {
        if (String(data[i][map['key']]).trim() === keyName) {
          sheet.getRange(i + 1, map['value'] + 1).setValue(valueStr);
          return;
        }
      }
      sheet.appendRow([keyName, valueStr]);
    };

    Object.keys(settingsObj).forEach(function(key) {
      var val = settingsObj[key];
      if (typeof val === 'object') {
        updateKey(key, JSON.stringify(val));
      } else {
        updateKey(key, String(val));
      }
    });

    logAction_(auth.username, 'UPDATE_SETTINGS', 'Mengubah konfigurasi sistem (nominal iuran, kategori, dan label laporan PDF)');
    return { success: true };
  } catch (e) {
    return { success: false, message: e.toString() };
  } finally {
    lock.releaseLock();
  }
}

/**
 * Helper untuk membuat atau mengambil folder berdasarkan nama di dalam folder induk.
 */
function getOrCreateFolder_(parent, name) {
  var folders = parent.getFoldersByName(name);
  if (folders.hasNext()) {
    return folders.next();
  }
  return parent.createFolder(name);
}

/**
 * Fungsi untuk mengunggah file base64 ke Google Drive di dalam folder terstruktur.
 */
function uploadFileToDrive(token, base64Data, fileName, mimeType, type) {
  if (!base64Data || typeof base64Data !== 'string') {
    return { success: false, message: 'Gagal mengunggah: Data berkas kosong atau tidak terbaca.' };
  }
  // Strict Security Validations (Multi-layered Protection)
  if (type !== 'Pengaduan') {
    var session = validateSession_(token);
    if (!session.valid) {
      return { success: false, message: 'Autentikasi gagal untuk upload data internal. Harap login terlebih dahulu.' };
    }
  }
  
  var allowedTypes = ['Pemasukan', 'Pengeluaran', 'Aset', 'Pengaduan', 'Logo', 'Agenda', 'UMKM', 'UMKM_Foto'];
  if (allowedTypes.indexOf(type) === -1) {
    return { success: false, message: 'Tipe folder upload tidak valid.' };
  }
  
  var mimeLower = String(mimeType || '').toLowerCase();
  if (!mimeLower.startsWith('image/') && mimeLower !== 'application/pdf') {
    return { success: false, message: 'Tipe file tidak diizinkan. Hanya gambar dan PDF yang diperbolehkan.' };
  }
  
  var ext = String(fileName || '').split('.').pop().toLowerCase();
  var allowedExts = ['jpg', 'jpeg', 'png', 'gif', 'pdf', 'webp'];
  if (allowedExts.indexOf(ext) === -1) {
    return { success: false, message: 'Ekstensi file tidak diizinkan.' };
  }
  
  if (base64Data && base64Data.length > 15 * 1024 * 1024) {
    return { success: false, message: 'Ukuran file melebihi batas 10MB.' };
  }
  
  try {
    var ss = SpreadsheetApp.getActiveSpreadsheet();
    var folderName = ss.getName();
    
    // Ambil atau buat folder utama aplikasi di root Google Drive
    var rootFolder = DriveApp.getRootFolder();
    var appFolder = getOrCreateFolder_(rootFolder, folderName);
    
    // Ambil atau buat subfolder (Pemasukan / Pengeluaran / Aset / Pengaduan / Logo / Agenda / UMKM)
    var targetFolderName = (type === 'UMKM_Foto' || type === 'UMKM') ? 'UMKM' : type;
    var subFolder = getOrCreateFolder_(appFolder, targetFolderName);
    
    // Decode data base64
    var base64Part = base64Data;
    if (base64Data && base64Data.indexOf && base64Data.indexOf(',') !== -1) {
      base64Part = base64Data.split(',')[1];
    }
    var decoded = Utilities.base64Decode(base64Part);
    var blob = Utilities.newBlob(decoded, mimeType, fileName);
    
    // Tulis file ke Drive
    var file = subFolder.createFile(blob);
    
    // Atur hak akses file (Siapa saja yang memiliki link bisa melihat)
    try {
      file.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW);
    } catch (shareErr) {
      Logger.log('Gagal mengatur hak akses sharing file: ' + shareErr.toString());
    }
    
    return {
      success: true,
      url: file.getUrl()
    };
  } catch (e) {
    return {
      success: false,
      message: e.toString()
    };
  }
}
function formatRupiahGAS_(angka) {
  var isNegative = parseInt(angka, 10) < 0;
  var str = Math.abs(parseInt(angka, 10)).toString();
  var rev = str.split('').reverse().join('');
  var ribuan = '';
  for (var i = 0; i < rev.length; i++) {
    ribuan += rev[i];
    if ((i + 1) % 3 === 0 && i !== rev.length - 1) {
      ribuan += '.';
    }
  }
  var result = ribuan.split('').reverse().join('');
  return (isNegative ? 'Rp -' : 'Rp ') + result;
}

/**
 * Public Submissions
 */
function submitPublicSurat(form) {
  form.nik_no_rumah = sanitizeInput_(form.nik_no_rumah, 100);
  form.nama_pemohon = sanitizeInput_(form.nama_pemohon, 100);
  form.no_wa = sanitizeInput_(form.no_wa, 20);
  form.jenis_layanan = sanitizeInput_(form.jenis_layanan, 50);
  form.detail_permintaan = sanitizeInput_(form.detail_permintaan, 500);

  if (!form.nik_no_rumah || !form.nama_pemohon || !form.no_wa || !form.jenis_layanan || !form.detail_permintaan) {
    return { success: false, message: 'Semua field wajib diisi.' };
  }

  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('Permohonan_Surat');
  if (!sheet) return { success: false, message: 'Database Permohonan Surat tidak ditemukan.' };

  var lock = LockService.getScriptLock();
  try {
    lock.waitLock(10000);
    var map = getColumnMap_(sheet);
    var lastRow = sheet.getLastRow();
    var idNum = lastRow > 1 ? parseInt(String(sheet.getRange(lastRow, map['id_tiket'] + 1).getValue()).replace('SRT-', '')) + 1 : 1;
    if (isNaN(idNum)) idNum = lastRow;
    var newId = 'SRT-' + ('000' + idNum).slice(-3);

    sheet.appendRow([
      newId,
      new Date(),
      form.jenis_layanan,
      form.nama_pemohon,
      form.no_wa,
      form.nik_no_rumah,
      form.detail_permintaan,
      '',
      'Pending'
    ]);

    logAction_('Warga (Public)', 'CREATE', 'Mengajukan permohonan surat pengantar (' + newId + ')');
    return { success: true, id_tiket: newId };
  } catch (e) {
    return { success: false, message: e.toString() };
  } finally {
    lock.releaseLock();
  }
}

function submitPublicPeminjaman(form) {
  form.nama_peminjam = sanitizeInput_(form.nama_peminjam, 100);
  form.no_wa = sanitizeInput_(form.no_wa, 20);
  form.no_rumah = sanitizeInput_(form.no_rumah, 30);
  form.barang = sanitizeInput_(form.barang, 100);
  form.tanggal_pinjam = sanitizeInput_(form.tanggal_pinjam, 30);
  form.tanggal_kembali = sanitizeInput_(form.tanggal_kembali, 30);
  form.jumlah_unit = parseInt(form.jumlah_unit || 0, 10);
  form.detail_peminjaman = sanitizeInput_(form.detail_peminjaman, 500);

  if (!form.nama_peminjam || !form.no_wa || !form.no_rumah || !form.barang || !form.tanggal_pinjam || !form.tanggal_kembali || !form.jumlah_unit || !form.detail_peminjaman) {
    return { success: false, message: 'Semua field wajib diisi.' };
  }

  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('Peminjaman_Aset');
  if (!sheet) return { success: false, message: 'Database Peminjaman Aset tidak ditemukan.' };

  var lock = LockService.getScriptLock();
  try {
    lock.waitLock(10000);
    var map = getColumnMap_(sheet);
    var lastRow = sheet.getLastRow();
    var idNum = lastRow > 1 ? parseInt(String(sheet.getRange(lastRow, map['id_tiket'] + 1).getValue()).replace('AST-', '')) + 1 : 1;
    if (isNaN(idNum)) idNum = lastRow;
    var newId = 'AST-' + ('000' + idNum).slice(-3);

    var maxCol = 0;
    for (var k in map) {
      if (map[k] > maxCol) maxCol = map[k];
    }
    var rowValues = [];
    for (var c = 0; c <= maxCol; c++) {
      rowValues.push('');
    }
    rowValues[map['id_tiket']] = newId;
    rowValues[map['tanggal']] = new Date();
    rowValues[map['nama_peminjam']] = form.nama_peminjam;
    rowValues[map['no_wa']] = form.no_wa;
    rowValues[map['no_rumah']] = form.no_rumah;
    rowValues[map['barang']] = form.barang;
    rowValues[map['jumlah_unit']] = form.jumlah_unit;
    rowValues[map['tanggal_pinjam']] = form.tanggal_pinjam;
    rowValues[map['tanggal_kembali']] = form.tanggal_kembali;
    rowValues[map['detail_peminjaman']] = form.detail_peminjaman;
    rowValues[map['status']] = 'Pending';

    sheet.appendRow(rowValues);

    logAction_('Warga (Public)', 'CREATE', 'Mengajukan peminjaman aset (' + newId + ')');
    return { success: true, id_tiket: newId };
  } catch (e) {
    return { success: false, message: e.toString() };
  } finally {
    lock.releaseLock();
  }
}

function submitPublicPengaduan(form) {
  form.nama_pengadu = sanitizeInput_(form.nama_pengadu, 100);
  form.no_wa = sanitizeInput_(form.no_wa, 20);
  form.jenis_layanan = sanitizeInput_(form.jenis_layanan, 50);
  form.lokasi_kejadian = sanitizeInput_(form.lokasi_kejadian, 100);
  form.detail_pengaduan = sanitizeInput_(form.detail_pengaduan, 500);
  form.bukti_foto = sanitizeInput_(form.bukti_foto, 1000);

  if (!form.nama_pengadu || !form.no_wa || !form.jenis_layanan || !form.lokasi_kejadian || !form.detail_pengaduan) {
    return { success: false, message: 'Semua field wajib diisi.' };
  }

  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('Pengaduan_Saran');
  if (!sheet) return { success: false, message: 'Database Pengaduan & Saran tidak ditemukan.' };

  var lock = LockService.getScriptLock();
  try {
    lock.waitLock(10000);
    var map = getColumnMap_(sheet);
    var lastRow = sheet.getLastRow();
    var idNum = lastRow > 1 ? parseInt(String(sheet.getRange(lastRow, map['id_tiket'] + 1).getValue()).replace('ADN-', '')) + 1 : 1;
    if (isNaN(idNum)) idNum = lastRow;
    var newId = 'ADN-' + ('000' + idNum).slice(-3);

    sheet.appendRow([
      newId,
      new Date(),
      form.jenis_layanan,
      form.nama_pengadu,
      form.no_wa,
      form.lokasi_kejadian,
      form.detail_pengaduan,
      form.bukti_foto || '',
      'Pending'
    ]);

    logAction_('Warga (Public)', 'CREATE', 'Mengirimkan pengaduan / saran (' + newId + ')');
    return { success: true, id_tiket: newId };
  } catch (e) {
    return { success: false, message: e.toString() };
  } finally {
    lock.releaseLock();
  }
}

/**
 * Admin Actions: Layanan Warga
 */
function updateSuratStatus(token, id_tiket, status, no_surat) {
  var session = validateSession_(token);
  if (!session.valid) return { success: false, message: session.message, sessionExpired: true };

  status = sanitizeInput_(status, 20);
  no_surat = sanitizeInput_(no_surat, 100);

  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('Permohonan_Surat');
  if (!sheet) return { success: false, message: 'Database Permohonan Surat tidak ditemukan.' };

  var lock = LockService.getScriptLock();
  try {
    lock.waitLock(10000);
    var map = getColumnMap_(sheet);
    var data = sheet.getDataRange().getValues();
    for (var i = 1; i < data.length; i++) {
      if (String(data[i][map['id_tiket']]) === id_tiket) {
        var rowNum = i + 1;
        sheet.getRange(rowNum, map['status'] + 1).setValue(status);
        sheet.getRange(rowNum, map['no_surat'] + 1).setValue(no_surat);
        logAction_(session.username, 'UPDATE', 'Mengubah status permohonan surat ' + id_tiket + ' menjadi ' + status + ' (No. Surat: ' + no_surat + ')');
        return { success: true };
      }
    }
    return { success: false, message: 'Permohonan surat tidak ditemukan.' };
  } catch (e) {
    return { success: false, message: e.toString() };
  } finally {
    lock.releaseLock();
  }
}

function deleteSurat(token, id_tiket) {
  var session = validateSession_(token);
  if (!session.valid) return { success: false, message: session.message, sessionExpired: true };

  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('Permohonan_Surat');
  if (!sheet) return { success: false, message: 'Database Permohonan Surat tidak ditemukan.' };

  var lock = LockService.getScriptLock();
  try {
    lock.waitLock(10000);
    var map = getColumnMap_(sheet);
    var data = sheet.getDataRange().getValues();
    for (var i = 1; i < data.length; i++) {
      if (String(data[i][map['id_tiket']]) === id_tiket) {
        sheet.deleteRow(i + 1);
        logAction_(session.username, 'DELETE', 'Menghapus permohonan surat: ' + id_tiket);
        return { success: true };
      }
    }
    return { success: false, message: 'Permohonan surat tidak ditemukan.' };
  } catch (e) {
    return { success: false, message: e.toString() };
  } finally {
    lock.releaseLock();
  }
}

function updatePeminjamanStatus(token, id_tiket, status) {
  var session = validateSession_(token);
  if (!session.valid) return { success: false, message: session.message, sessionExpired: true };

  status = sanitizeInput_(status, 20);

  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('Peminjaman_Aset');
  if (!sheet) return { success: false, message: 'Database Peminjaman Aset tidak ditemukan.' };

  var lock = LockService.getScriptLock();
  try {
    lock.waitLock(10000);
    var map = getColumnMap_(sheet);
    var data = sheet.getDataRange().getValues();
    for (var i = 1; i < data.length; i++) {
      if (String(data[i][map['id_tiket']]) === id_tiket) {
        sheet.getRange(i + 1, map['status'] + 1).setValue(status);
        recalculateAsetStock_(ss);
        logAction_(session.username, 'UPDATE', 'Mengubah status peminjaman aset ' + id_tiket + ' menjadi ' + status);
        return { success: true };
      }
    }
    return { success: false, message: 'Permohonan peminjaman tidak ditemukan.' };
  } catch (e) {
    return { success: false, message: e.toString() };
  } finally {
    lock.releaseLock();
  }
}

function deletePeminjaman(token, id_tiket) {
  var session = validateSession_(token);
  if (!session.valid) return { success: false, message: session.message, sessionExpired: true };

  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('Peminjaman_Aset');
  if (!sheet) return { success: false, message: 'Database Peminjaman Aset tidak ditemukan.' };

  var lock = LockService.getScriptLock();
  try {
    lock.waitLock(10000);
    var map = getColumnMap_(sheet);
    var data = sheet.getDataRange().getValues();
    for (var i = 1; i < data.length; i++) {
      if (String(data[i][map['id_tiket']]) === id_tiket) {
        sheet.deleteRow(i + 1);
        recalculateAsetStock_(ss);
        logAction_(session.username, 'DELETE', 'Menghapus permohonan peminjaman: ' + id_tiket);
        return { success: true };
      }
    }
    return { success: false, message: 'Permohonan peminjaman tidak ditemukan.' };
  } catch (e) {
    return { success: false, message: e.toString() };
  } finally {
    lock.releaseLock();
  }
}

function updatePengaduanLayananStatus(token, id_tiket, status) {
  var session = validateSession_(token);
  if (!session.valid) return { success: false, message: session.message, sessionExpired: true };

  status = sanitizeInput_(status, 20);

  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('Pengaduan_Saran');
  if (!sheet) return { success: false, message: 'Database Pengaduan & Saran tidak ditemukan.' };

  var lock = LockService.getScriptLock();
  try {
    lock.waitLock(10000);
    var map = getColumnMap_(sheet);
    var data = sheet.getDataRange().getValues();
    for (var i = 1; i < data.length; i++) {
      if (String(data[i][map['id_tiket']]) === id_tiket) {
        sheet.getRange(i + 1, map['status'] + 1).setValue(status);
        logAction_(session.username, 'UPDATE', 'Mengubah status pengaduan layanan ' + id_tiket + ' menjadi ' + status);
        return { success: true };
      }
    }
    return { success: false, message: 'Pengaduan / saran tidak ditemukan.' };
  } catch (e) {
    return { success: false, message: e.toString() };
  } finally {
    lock.releaseLock();
  }
}

function deletePengaduanLayanan(token, id_tiket) {
  var session = validateSession_(token);
  if (!session.valid) return { success: false, message: session.message, sessionExpired: true };

  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('Pengaduan_Saran');
  if (!sheet) return { success: false, message: 'Database Pengaduan & Saran tidak ditemukan.' };

  var lock = LockService.getScriptLock();
  try {
    lock.waitLock(10000);
    var map = getColumnMap_(sheet);
    var data = sheet.getDataRange().getValues();
    for (var i = 1; i < data.length; i++) {
      if (String(data[i][map['id_tiket']]) === id_tiket) {
        sheet.deleteRow(i + 1);
        logAction_(session.username, 'DELETE', 'Menghapus pengaduan/saran: ' + id_tiket);
        return { success: true };
      }
    }
    return { success: false, message: 'Pengaduan / saran tidak ditemukan.' };
  } catch (e) {
    return { success: false, message: e.toString() };
  } finally {
    lock.releaseLock();
  }
}

/**
 * Public function to retrieve financial summary and asset list
 */
function getPublicFinancialAndAssetData() {
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  
  // 1. Calculate Pemasukan
  var iuranSheet = ss.getSheetByName('Iuran');
  var totalPemasukan = 0;
  var rawIuran = iuranSheet ? iuranSheet.getDataRange().getValues() : [];
  var mapI = iuranSheet ? getColumnMap_(iuranSheet) : {};
  if (iuranSheet && rawIuran.length > 1) {
    for (var i = 1; i < rawIuran.length; i++) {
      totalPemasukan += parseInt(rawIuran[i][mapI['jumlah']] || 0, 10);
    }
  }
  
  // 2. Calculate Pengeluaran & Extract Recent Pengeluaran
  var kasSheet = ss.getSheetByName('Kas_Keluar');
  var totalPengeluaran = 0;
  var rawKas = kasSheet ? kasSheet.getDataRange().getValues() : [];
  var mapK = kasSheet ? getColumnMap_(kasSheet) : {};
  var allKas = [];
  if (kasSheet && rawKas.length > 1) {
    for (var i = 1; i < rawKas.length; i++) {
      var jml = parseInt(rawKas[i][mapK['jumlah']] || 0, 10);
      totalPengeluaran += jml;
      
      var keperluan = String(rawKas[i][mapK['keperluan']] || '').trim();
      var tgl = String(rawKas[i][mapK['tanggal_keluar']] || rawKas[i][mapK['tanggal']] || '').trim();
      var kat = String(rawKas[i][mapK['kategori']] || '').trim();
      var bkt = String(rawKas[i][mapK['bukti']] || '').trim();
      
      if (keperluan || jml > 0) {
        allKas.push({
          keperluan: keperluan,
          jumlah: jml,
          tanggal: tgl,
          kategori: kat,
          bukti: bkt
        });
      }
    }
  }
  allKas.reverse();
  var recentPengeluaran = allKas.slice(0, 3);
  
  var totalSaldo = totalPemasukan - totalPengeluaran;
  
  // 3. Status Iuran Bulan Berjalan
  var wargaSheet = ss.getSheetByName('Warga');
  var rawWarga = wargaSheet ? wargaSheet.getDataRange().getValues() : [];
  var mapW = wargaSheet ? getColumnMap_(wargaSheet) : {};
  
  var activeKKIds = {};
  var totalKK = 0;
  var totalWarga = 0;
  var totalLakiLaki = 0;
  var totalPerempuan = 0;
  
  if (wargaSheet && rawWarga.length > 1) {
    for (var i = 1; i < rawWarga.length; i++) {
      var status = String(rawWarga[i][mapW['status_warga']]).trim();
      if (status === 'Aktif') {
        totalWarga++;
        
        var gender = String(rawWarga[i][mapW['jenis_kelamin']]).trim().toLowerCase();
        if (gender === 'laki-laki') {
          totalLakiLaki++;
        } else if (gender === 'perempuan') {
          totalPerempuan++;
        }
        
        var posisi = String(rawWarga[i][mapW['posisi_keluarga']]).trim();
        if (posisi === 'Kepala Keluarga') {
          var idW = String(rawWarga[i][mapW['id_warga']]).trim();
          activeKKIds[idW] = true;
          totalKK++;
        }
      }
    }
  }
  
  var monthsIndo = ['Januari', 'Februari', 'Maret', 'April', 'Mei', 'Juni', 'Juli', 'Agustus', 'September', 'Oktober', 'November', 'Desember'];
  var now = new Date();
  var curMonthName = monthsIndo[now.getMonth()];
  var curYear = now.getFullYear();
  
  var sudahBayar = 0;
  if (iuranSheet && rawIuran.length > 1) {
    var paidThisMonth = {};
    for (var i = 1; i < rawIuran.length; i++) {
      var idW = String(rawIuran[i][mapI['id_warga']]).trim();
      var bulanVal = String(rawIuran[i][mapI['bulan']]).trim();
      var tahunVal = String(rawIuran[i][mapI['tahun']]).trim();
      
      if (bulanVal === curMonthName && String(tahunVal) === String(curYear)) {
        paidThisMonth[idW] = true;
      }
    }
    for (var idW in activeKKIds) {
      if (paidThisMonth[idW]) {
        sudahBayar++;
      }
    }
  }
  
  var belumBayar = Math.max(0, totalKK - sudahBayar);
  var persen = totalKK > 0 ? Math.round((sudahBayar / totalKK) * 100) : 0;
  
  var iuranStatus = {
    bulan: curMonthName + ' ' + curYear,
    totalKK: totalKK,
    sudahBayar: sudahBayar,
    belumBayar: belumBayar,
    persen: persen
  };
  
  // 4. Inventaris Aset RT/RW
  var asetSheet = ss.getSheetByName('Aset');
  var rawAset = asetSheet ? asetSheet.getDataRange().getValues() : [];
  var mapAs = asetSheet ? getColumnMap_(asetSheet) : {};
  
  var peminjamanSheet = ss.getSheetByName('Peminjaman_Aset');
  var rawPeminjaman = peminjamanSheet ? peminjamanSheet.getDataRange().getValues() : [];
  var mapP = peminjamanSheet ? getColumnMap_(peminjamanSheet) : {};
  var activeLoans = {};
  if (peminjamanSheet && rawPeminjaman.length > 1) {
    for (var j = 1; j < rawPeminjaman.length; j++) {
      var status = String(rawPeminjaman[j][mapP['status']]).trim();
      if (status === 'Disetujui') {
        var barangName = String(rawPeminjaman[j][mapP['barang']] || '').trim();
        var units = parseInt(rawPeminjaman[j][mapP['jumlah_unit']] || 0, 10);
        
        // Fallback legacy data parsing
        if (!barangName) {
          var legacyNotes = String(rawPeminjaman[j][mapP['detail_peminjaman']] || '');
          if (legacyNotes.startsWith('Aset: ')) {
            var parts = legacyNotes.split('|');
            if (parts.length >= 2) {
              barangName = parts[0].replace('Aset: ', '').trim();
              var numMatch = parts[1].match(/(\d+)/);
              if (numMatch) units = parseInt(numMatch[1], 10);
            }
          }
        }
        
        if (barangName) {
          activeLoans[barangName] = (activeLoans[barangName] || 0) + units;
        }
      }
    }
  }
  
  var asetList = [];
  if (asetSheet && rawAset.length > 1) {
    for (var i = 1; i < rawAset.length; i++) {
      var namaBarang = String(rawAset[i][mapAs['nama_barang']]).trim();
      var total = parseInt(rawAset[i][mapAs['jumlah_total']] || 0, 10);
      var borrowed = activeLoans[namaBarang] || 0;
      var tersedia = Math.max(0, total - borrowed);
      var statusStr = tersedia > 0 ? 'TERSEDIA' : 'DIPINJAM';
      
      asetList.push({
        nama_barang: namaBarang,
        total: total,
        tersedia: tersedia,
        status: statusStr
      });
    }
  }
  
  return {
    success: true,
    financials: {
      totalSaldo: totalSaldo,
      totalPemasukan: totalPemasukan,
      totalPengeluaran: totalPengeluaran,
      recentPengeluaran: recentPengeluaran,
      iuranStatus: iuranStatus
    },
    wargaStats: {
      totalWarga: totalWarga,
      totalLakiLaki: totalLakiLaki,
      totalPerempuan: totalPerempuan,
      totalKK: totalKK
    },
    assets: asetList
  };
}

/**
 * Public function to retrieve available assets for citizen borrowing
 */
function getPublicAset() {
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('Aset');
  if (!sheet) return [];
  var data = sheet.getDataRange().getValues();
  var map = getColumnMap_(sheet);
  
  // Ambil data peminjaman untuk hitung sisa secara dinamis
  var peminjamanSheet = ss.getSheetByName('Peminjaman_Aset');
  var rawPeminjaman = peminjamanSheet ? peminjamanSheet.getDataRange().getValues() : [];
  var mapP = peminjamanSheet ? getColumnMap_(peminjamanSheet) : {};
  var activeLoans = {};
  if (peminjamanSheet) {
    for (var j = 1; j < rawPeminjaman.length; j++) {
      var status = rawPeminjaman[j][mapP['status']] || 'Pending';
      if (status === 'Disetujui') {
        var barangName = rawPeminjaman[j][mapP['barang']] || '';
        var units = parseInt(rawPeminjaman[j][mapP['jumlah_unit']] || 0, 10);
        
        // Fallback parsing unit dan barang untuk data legacy
        if (!barangName) {
          var legacyNotes = String(rawPeminjaman[j][mapP['detail_peminjaman']] || '');
          if (legacyNotes.startsWith('Aset: ')) {
            var parts = legacyNotes.split('|');
            if (parts.length >= 2) {
              barangName = parts[0].replace('Aset: ', '').trim();
              var numMatch = parts[1].match(/(\d+)/);
              if (numMatch) units = parseInt(numMatch[1], 10);
            }
          }
        }
        
        if (barangName) {
          activeLoans[barangName] = (activeLoans[barangName] || 0) + units;
        }
      }
    }
  }

  var result = [];
  for (var i = 1; i < data.length; i++) {
    var total = parseInt(data[i][map['jumlah_total']] || 0, 10);
    var namaBarang = String(data[i][map['nama_barang']]);
    var borrowed = activeLoans[namaBarang] || 0;
    var tersedia = Math.max(0, total - borrowed);
    if (tersedia > 0) {
      result.push({
        id_aset: String(data[i][map['id_aset']]),
        nama_barang: namaBarang,
        jumlah_tersedia: tersedia
      });
    }
  }
  return result;
}

/**
 * Public function to retrieve public Agenda and Pengumuman lists
 */
function getPublicAgendaPengumuman() {
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  
  // Ambil Data Agenda
  var agendaSheet = ss.getSheetByName('Agenda');
  var rawAgenda = agendaSheet ? agendaSheet.getDataRange().getValues() : [];
  var mapAgenda = agendaSheet ? getColumnMap_(agendaSheet) : {};
  var agendaList = [];
  for (var i = 1; i < rawAgenda.length; i++) {
    agendaList.push({
      id_agenda: rawAgenda[i][mapAgenda['id_agenda']] || '',
      judul_kegiatan: rawAgenda[i][mapAgenda['judul_kegiatan']] || '',
      kategori: rawAgenda[i][mapAgenda['kategori']] || '',
      tanggal_jam: rawAgenda[i][mapAgenda['tanggal_jam']] || '',
      lokasi: rawAgenda[i][mapAgenda['lokasi']] || '',
      status: rawAgenda[i][mapAgenda['status']] || 'TERJADWAL',
      created_at: safeDateFormat_(rawAgenda[i][mapAgenda['created_at']])
    });
  }

  // Ambil Data Pengumuman
  var pengumumanSheet = ss.getSheetByName('Pengumuman');
  var rawPengumuman = pengumumanSheet ? pengumumanSheet.getDataRange().getValues() : [];
  var mapPengumuman = pengumumanSheet ? getColumnMap_(pengumumanSheet) : {};
  var pengumumanList = [];
  for (var i = 1; i < rawPengumuman.length; i++) {
    pengumumanList.push({
      id_pengumuman: rawPengumuman[i][mapPengumuman['id_pengumuman']] || '',
      tanggal: safeDateFormat_(rawPengumuman[i][mapPengumuman['tanggal']]),
      tipe: rawPengumuman[i][mapPengumuman['tipe']] || '',
      judul: rawPengumuman[i][mapPengumuman['judul']] || '',
      isi_pengumuman: rawPengumuman[i][mapPengumuman['isi_pengumuman']] || '',
      created_at: safeDateFormat_(rawPengumuman[i][mapPengumuman['created_at']])
    });
  }

  return {
    success: true,
    agenda: agendaList,
    pengumuman: pengumumanList
  };
}

/**
 * Public function to retrieve public categories (surat and assets) for citizen dropdowns
 */
function getPublicSettings() {
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var settingsSheet = ss.getSheetByName('Settings');
  var settings = {
    kategori_aset: ["Peralatan", "Perlengkapan Acara", "Alat Kebersihan", "Lain-lain"],
    kategori_surat: ["Pembuatan KTP", "Pembuatan KK", "Surat Keterangan Domisili", "Surat Keterangan Usaha", "Surat Keterangan Tidak Mampu", "Lainnya"],
    kategori_umkm: [
      "Kuliner / Makanan & Minuman",
      "Sembako / Toko Manisan",
      "Jasa / Service",
      "Fashion & Pakaian",
      "Kerajinan / Kriya",
      "Pertanian / Peternakan",
      "Lain-lain"
    ]
  };
  if (settingsSheet) {
    var rawSettings = settingsSheet.getDataRange().getValues();
    var mapS = getColumnMap_(settingsSheet);
    for (var k = 1; k < rawSettings.length; k++) {
      var key = String(rawSettings[k][mapS['key']]).trim();
      var val = String(rawSettings[k][mapS['value']]).trim();
      if (key === 'kategori_aset' || key === 'kategori_surat' || key === 'kategori_umkm') {
        try {
          settings[key] = JSON.parse(val);
        } catch (e) {
          settings[key] = val.split(',').map(function(s) { return s.trim(); });
        }
      } else {
        settings[key] = val;
      }
    }
  }
  return settings;
}

/**
 * Recalculate available stock for all assets in the 'Aset' sheet
 */
function recalculateAsetStock_(ss) {
  var ss = ss || SpreadsheetApp.getActiveSpreadsheet();
  var asetSheet = ss.getSheetByName('Aset');
  var peminjamanSheet = ss.getSheetByName('Peminjaman_Aset');
  if (!asetSheet) return;

  var rawAset = asetSheet.getDataRange().getValues();
  var mapAs = getColumnMap_(asetSheet);
  
  var rawPeminjaman = peminjamanSheet ? peminjamanSheet.getDataRange().getValues() : [];
  var mapP = peminjamanSheet ? getColumnMap_(peminjamanSheet) : {};
  
  var activeLoans = {};
  if (peminjamanSheet) {
    for (var j = 1; j < rawPeminjaman.length; j++) {
      var status = rawPeminjaman[j][mapP['status']] || 'Pending';
      if (status === 'Disetujui') {
        var barangName = rawPeminjaman[j][mapP['barang']] || '';
        var units = parseInt(rawPeminjaman[j][mapP['jumlah_unit']] || 0, 10);
        
        // Fallback legacy data parsing
        if (!barangName) {
          var legacyNotes = String(rawPeminjaman[j][mapP['detail_peminjaman']] || '');
          if (legacyNotes.startsWith('Aset: ')) {
            var parts = legacyNotes.split('|');
            if (parts.length >= 2) {
              barangName = parts[0].replace('Aset: ', '').trim();
              var numMatch = parts[1].match(/(\d+)/);
              if (numMatch) units = parseInt(numMatch[1], 10);
            }
          }
        }
        
        if (barangName) {
          activeLoans[barangName] = (activeLoans[barangName] || 0) + units;
        }
      }
    }
  }

  for (var i = 1; i < rawAset.length; i++) {
    var total = parseInt(rawAset[i][mapAs['jumlah_total']] || 0, 10);
    var namaBarang = String(rawAset[i][mapAs['nama_barang']]);
    var borrowed = activeLoans[namaBarang] || 0;
    var tersedia = Math.max(0, total - borrowed);
    
    asetSheet.getRange(i + 1, mapAs['jumlah_tersedia'] + 1).setValue(tersedia);
  }
}

/**
 * CRUD Agenda
 */
function getAgendaData_(token) {
  var session = validateSession_(token);
  if (!session.valid) return { success: false, message: session.message, sessionExpired: true };

  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('Agenda');
  if (!sheet || sheet.getLastRow() <= 1) return { success: true, data: [] };

  var map = getColumnMap_(sheet);
  var data = sheet.getDataRange().getValues();
  var result = [];
  for (var i = 1; i < data.length; i++) {
    result.push({
      id_agenda: data[i][map['id_agenda']] || '',
      judul_kegiatan: data[i][map['judul_kegiatan']] || '',
      kategori: data[i][map['kategori']] || '',
      tanggal_jam: data[i][map['tanggal_jam']] || '',
      lokasi: data[i][map['lokasi']] || '',
      status: data[i][map['status']] || 'TERJADWAL',
      petugas: data[i][map['petugas']] || '',
      created_at: safeDateFormat_(data[i][map['created_at']]),
      url_laporan: data[i][map['url_laporan']] || '',
      url_notulen: data[i][map['url_notulen']] || ''
    });
  }
  return { success: true, data: result };
}

function saveAgenda(token, form) {
  var session = validateSession_(token);
  if (!session.valid) return { success: false, message: session.message, sessionExpired: true };

  form.judul_kegiatan = sanitizeInput_(form.judul_kegiatan, 100);
  form.kategori = sanitizeInput_(form.kategori, 50);
  form.tanggal_jam = sanitizeInput_(form.tanggal_jam, 100);
  form.lokasi = sanitizeInput_(form.lokasi, 200);
  form.status = sanitizeInput_(form.status, 50);
  form.url_laporan = sanitizeInput_(form.url_laporan, 1000);
  form.url_notulen = sanitizeInput_(form.url_notulen, 1000);

  if (!form.judul_kegiatan || !form.tanggal_jam || !form.lokasi) {
    return { success: false, message: 'Judul, Tanggal/Jam, dan Lokasi wajib diisi.' };
  }

  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('Agenda');
  if (!sheet) return { success: false, message: 'Database Agenda tidak ditemukan.' };

  var lock = LockService.getScriptLock();
  try {
    lock.waitLock(10000);
    var map = getColumnMap_(sheet);

    if (form.isEdit === true || form.isEdit === 'true') {
      var data = sheet.getDataRange().getValues();
      for (var i = 1; i < data.length; i++) {
        if (String(data[i][map['id_agenda']]) === form.id_agenda) {
          var rowNum = i + 1;
          sheet.getRange(rowNum, map['judul_kegiatan'] + 1).setValue(form.judul_kegiatan);
          sheet.getRange(rowNum, map['kategori'] + 1).setValue(form.kategori);
          sheet.getRange(rowNum, map['tanggal_jam'] + 1).setValue(form.tanggal_jam);
          sheet.getRange(rowNum, map['lokasi'] + 1).setValue(form.lokasi);
          sheet.getRange(rowNum, map['status'] + 1).setValue(form.status);
          sheet.getRange(rowNum, map['url_laporan'] + 1).setValue(form.url_laporan || '');
          sheet.getRange(rowNum, map['url_notulen'] + 1).setValue(form.url_notulen || '');
          
          logAction_(session.username, 'UPDATE', 'Mengubah agenda: ' + form.judul_kegiatan + ' (' + form.id_agenda + ')');
          return { success: true };
        }
      }
      return { success: false, message: 'Data Agenda tidak ditemukan.' };
    } else {
      var lastRow = sheet.getLastRow();
      var idNum = lastRow > 1 ? parseInt(String(sheet.getRange(lastRow, map['id_agenda'] + 1).getValue()).replace('AGD-', '')) + 1 : 1;
      var newId = 'AGD-' + ('000' + idNum).slice(-3);

      sheet.appendRow([
        newId,
        form.judul_kegiatan,
        form.kategori,
        form.tanggal_jam,
        form.lokasi,
        form.status || 'TERJADWAL',
        session.username,
        new Date(),
        form.url_laporan || '',
        form.url_notulen || ''
      ]);

      logAction_(session.username, 'CREATE', 'Menambahkan agenda baru: ' + form.judul_kegiatan + ' (' + newId + ')');
      return { success: true };
    }
  } catch (e) {
    return { success: false, message: e.toString() };
  } finally {
    lock.releaseLock();
  }
}

function deleteAgenda(token, id_agenda) {
  var session = validateSession_(token);
  if (!session.valid) return { success: false, message: session.message, sessionExpired: true };

  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('Agenda');
  if (!sheet) return { success: false, message: 'Database Agenda tidak ditemukan.' };

  var lock = LockService.getScriptLock();
  try {
    lock.waitLock(10000);
    var data = sheet.getDataRange().getValues();
    var map = getColumnMap_(sheet);

    for (var i = 1; i < data.length; i++) {
      if (String(data[i][map['id_agenda']]) === id_agenda) {
        var rowNum = i + 1;
        var judul = data[i][map['judul_kegiatan']];
        sheet.deleteRow(rowNum);
        
        logAction_(session.username, 'DELETE', 'Menghapus agenda: ' + judul + ' (' + id_agenda + ')');
        return { success: true };
      }
    }
    return { success: false, message: 'ID Agenda tidak ditemukan.' };
  } catch (e) {
    return { success: false, message: e.toString() };
  } finally {
    lock.releaseLock();
  }
}

/**
 * CRUD Pengumuman
 */
function getPengumumanData_(token) {
  var session = validateSession_(token);
  if (!session.valid) return { success: false, message: session.message, sessionExpired: true };

  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('Pengumuman');
  if (!sheet || sheet.getLastRow() <= 1) return { success: true, data: [] };

  var map = getColumnMap_(sheet);
  var data = sheet.getDataRange().getValues();
  var result = [];
  for (var i = 1; i < data.length; i++) {
    result.push({
      id_pengumuman: data[i][map['id_pengumuman']] || '',
      tanggal: safeDateFormat_(data[i][map['tanggal']]),
      tipe: data[i][map['tipe']] || '',
      judul: data[i][map['judul']] || '',
      isi_pengumuman: data[i][map['isi_pengumuman']] || '',
      petugas: data[i][map['petugas']] || '',
      created_at: safeDateFormat_(data[i][map['created_at']])
    });
  }
  return { success: true, data: result };
}

function savePengumuman(token, form) {
  var session = validateSession_(token);
  if (!session.valid) return { success: false, message: session.message, sessionExpired: true };

  form.tanggal = sanitizeInput_(form.tanggal, 30);
  form.tipe = sanitizeInput_(form.tipe, 30);
  form.judul = sanitizeInput_(form.judul, 150);
  form.isi_pengumuman = sanitizeInput_(form.isi_pengumuman, 2000);

  if (!form.tanggal || !form.tipe || !form.judul || !form.isi_pengumuman) {
    return { success: false, message: 'Semua kolom form pengumuman wajib diisi.' };
  }

  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('Pengumuman');
  if (!sheet) return { success: false, message: 'Database Pengumuman tidak ditemukan.' };

  var lock = LockService.getScriptLock();
  try {
    lock.waitLock(10000);
    var map = getColumnMap_(sheet);

    if (form.isEdit === true || form.isEdit === 'true') {
      var data = sheet.getDataRange().getValues();
      for (var i = 1; i < data.length; i++) {
        if (String(data[i][map['id_pengumuman']]) === form.id_pengumuman) {
          var rowNum = i + 1;
          sheet.getRange(rowNum, map['tanggal'] + 1).setValue(form.tanggal ? new Date(form.tanggal) : new Date());
          sheet.getRange(rowNum, map['tipe'] + 1).setValue(form.tipe);
          sheet.getRange(rowNum, map['judul'] + 1).setValue(form.judul);
          sheet.getRange(rowNum, map['isi_pengumuman'] + 1).setValue(form.isi_pengumuman);
          
          logAction_(session.username, 'UPDATE', 'Mengubah pengumuman: ' + form.judul + ' (' + form.id_pengumuman + ')');
          return { success: true };
        }
      }
      return { success: false, message: 'Data Pengumuman tidak ditemukan.' };
    } else {
      var lastRow = sheet.getLastRow();
      var idNum = lastRow > 1 ? parseInt(String(sheet.getRange(lastRow, map['id_pengumuman'] + 1).getValue()).replace('PGM-', '')) + 1 : 1;
      var newId = 'PGM-' + ('000' + idNum).slice(-3);

      sheet.appendRow([
        newId,
        form.tanggal ? new Date(form.tanggal) : new Date(),
        form.tipe,
        form.judul,
        form.isi_pengumuman,
        session.username,
        new Date()
      ]);

      logAction_(session.username, 'CREATE', 'Menambahkan pengumuman baru: ' + form.judul + ' (' + newId + ')');
      return { success: true };
    }
  } catch (e) {
    return { success: false, message: e.toString() };
  } finally {
    lock.releaseLock();
  }
}

function deletePengumuman(token, id_pengumuman) {
  var session = validateSession_(token);
  if (!session.valid) return { success: false, message: session.message, sessionExpired: true };

  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('Pengumuman');
  if (!sheet) return { success: false, message: 'Database Pengumuman tidak ditemukan.' };

  var lock = LockService.getScriptLock();
  try {
    lock.waitLock(10000);
    var data = sheet.getDataRange().getValues();
    var map = getColumnMap_(sheet);

    for (var i = 1; i < data.length; i++) {
      if (String(data[i][map['id_pengumuman']]) === id_pengumuman) {
        var rowNum = i + 1;
        var judul = data[i][map['judul']];
        sheet.deleteRow(rowNum);
        
        logAction_(session.username, 'DELETE', 'Menghapus pengumuman: ' + judul + ' (' + id_pengumuman + ')');
        return { success: true };
      }
    }
    return { success: false, message: 'ID Pengumuman tidak ditemukan.' };
  } catch (e) {
    return { success: false, message: e.toString() };
  } finally {
    lock.releaseLock();
  }
}

/**
 * CRUD UMKM & Usaha Warga
 */
function getUmkmData(token) {
  var session = validateSession_(token);
  if (!session.valid) return { success: false, message: session.message, sessionExpired: true };

  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('UMKM');
  if (!sheet) return { success: true, data: [] };

  var data = sheet.getDataRange().getValues();
  if (data.length <= 1) return { success: true, data: [] };

  var map = getColumnMap_(data);
  var result = [];
  for (var i = 1; i < data.length; i++) {
    result.push({
      id_umkm: data[i][map['id_umkm']] || '',
      id_warga: map['id_warga'] !== undefined ? (data[i][map['id_warga']] || '') : '',
      nama_pemilik: map['nama_pemilik'] !== undefined ? (data[i][map['nama_pemilik']] || '') : '',
      nama_usaha: data[i][map['nama_usaha']] || '',
      kategori_usaha: map['kategori_usaha'] !== undefined ? (data[i][map['kategori_usaha']] || 'Kuliner / Makanan & Minuman') : 'Kuliner / Makanan & Minuman',
      deskripsi: map['deskripsi'] !== undefined ? (data[i][map['deskripsi']] || '') : '',
      no_hp: map['no_hp'] !== undefined ? (data[i][map['no_hp']] || '') : '',
      alamat_lokasi: map['alamat_lokasi'] !== undefined ? (data[i][map['alamat_lokasi']] || '') : '',
      foto_produk: map['foto_produk'] !== undefined ? (data[i][map['foto_produk']] || '') : '',
      status: map['status'] !== undefined ? (data[i][map['status']] || 'Aktif') : 'Aktif',
      created_at: safeDateFormat_(data[i][map['created_at']])
    });
  }
  return { success: true, data: result };
}

function saveUmkm(token, form) {
  var auth = requireRole_(token, 'Staff');
  if (!auth.authorized) return { success: false, message: auth.message, sessionExpired: auth.sessionExpired };
  var session = { username: auth.username };

  form.id_warga = sanitizeInput_(form.id_warga, 20);
  form.nama_pemilik = sanitizeInput_(form.nama_pemilik, 100);
  form.nama_usaha = sanitizeInput_(form.nama_usaha, 120);
  form.kategori_usaha = sanitizeInput_(form.kategori_usaha, 50);
  form.deskripsi = sanitizeInput_(form.deskripsi, 500);
  form.no_hp = sanitizePhone_(form.no_hp);
  form.alamat_lokasi = sanitizeInput_(form.alamat_lokasi, 200);
  form.foto_produk = sanitizeInput_(form.foto_produk, 1000);
  form.status = sanitizeInput_(form.status, 20) || 'Aktif';

  if (!form.nama_usaha) return { success: false, message: 'Nama usaha/toko wajib diisi.' };

  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('UMKM');
  if (!sheet) return { success: false, message: 'Database UMKM tidak ditemukan.' };

  var lock = LockService.getScriptLock();
  try {
    lock.waitLock(10000);
    var map = getColumnMap_(sheet);

    if (form.isEdit === true || form.isEdit === 'true') {
      var data = sheet.getDataRange().getValues();
      for (var i = 1; i < data.length; i++) {
        if (String(data[i][map['id_umkm']]) === form.id_umkm) {
          var rowNum = i + 1;
          if (map['id_warga'] !== undefined) sheet.getRange(rowNum, map['id_warga'] + 1).setValue(form.id_warga);
          if (map['nama_pemilik'] !== undefined) sheet.getRange(rowNum, map['nama_pemilik'] + 1).setValue(form.nama_pemilik);
          sheet.getRange(rowNum, map['nama_usaha'] + 1).setValue(form.nama_usaha);
          if (map['kategori_usaha'] !== undefined) sheet.getRange(rowNum, map['kategori_usaha'] + 1).setValue(form.kategori_usaha);
          if (map['deskripsi'] !== undefined) sheet.getRange(rowNum, map['deskripsi'] + 1).setValue(form.deskripsi);
          if (map['no_hp'] !== undefined) sheet.getRange(rowNum, map['no_hp'] + 1).setNumberFormat('@').setValue("'" + form.no_hp);
          if (map['alamat_lokasi'] !== undefined) sheet.getRange(rowNum, map['alamat_lokasi'] + 1).setValue(form.alamat_lokasi);
          if (map['foto_produk'] !== undefined) sheet.getRange(rowNum, map['foto_produk'] + 1).setValue(form.foto_produk);
          if (map['status'] !== undefined) sheet.getRange(rowNum, map['status'] + 1).setValue(form.status);

          logAction_(session.username, 'UPDATE', 'Mengubah data UMKM: ' + form.nama_usaha + ' (' + form.id_umkm + ')');
          return { success: true };
        }
      }
      return { success: false, message: 'ID UMKM tidak ditemukan.' };
    } else {
      var lastRow = sheet.getLastRow();
      var idNum = lastRow > 1 ? parseInt(String(sheet.getRange(lastRow, map['id_umkm'] + 1).getValue()).replace('UMKM-', '')) + 1 : 1;
      var newId = 'UMKM-' + ('000' + idNum).slice(-3);

      var headers = sheet.getRange(1, 1, 1, sheet.getLastColumn()).getValues()[0];
      var newRow = new Array(headers.length);
      newRow[map['id_umkm']] = newId;
      if (map['id_warga'] !== undefined) newRow[map['id_warga']] = form.id_warga;
      if (map['nama_pemilik'] !== undefined) newRow[map['nama_pemilik']] = form.nama_pemilik;
      newRow[map['nama_usaha']] = form.nama_usaha;
      if (map['kategori_usaha'] !== undefined) newRow[map['kategori_usaha']] = form.kategori_usaha;
      if (map['deskripsi'] !== undefined) newRow[map['deskripsi']] = form.deskripsi;
      if (map['no_hp'] !== undefined) newRow[map['no_hp']] = "'" + form.no_hp;
      if (map['alamat_lokasi'] !== undefined) newRow[map['alamat_lokasi']] = form.alamat_lokasi;
      if (map['foto_produk'] !== undefined) newRow[map['foto_produk']] = form.foto_produk;
      if (map['status'] !== undefined) newRow[map['status']] = form.status;
      if (map['created_at'] !== undefined) newRow[map['created_at']] = new Date();

      sheet.appendRow(newRow);
      logAction_(session.username, 'CREATE', 'Menambahkan usaha UMKM baru: ' + form.nama_usaha + ' (' + newId + ')');
      return { success: true };
    }
  } catch (e) {
    return { success: false, message: e.toString() };
  } finally {
    lock.releaseLock();
  }
}

function deleteUmkm(token, id_umkm) {
  var auth = requireRole_(token, 'Staff');
  if (!auth.authorized) return { success: false, message: auth.message, sessionExpired: auth.sessionExpired };
  var session = { username: auth.username };

  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('UMKM');
  if (!sheet) return { success: false, message: 'Database UMKM tidak ditemukan.' };

  var lock = LockService.getScriptLock();
  try {
    lock.waitLock(10000);
    var data = sheet.getDataRange().getValues();
    var map = getColumnMap_(sheet);

    for (var i = 1; i < data.length; i++) {
      if (String(data[i][map['id_umkm']]) === id_umkm) {
        var rowNum = i + 1;
        var namaUsaha = data[i][map['nama_usaha']];
        sheet.deleteRow(rowNum);

        logAction_(session.username, 'DELETE', 'Menghapus UMKM: ' + namaUsaha + ' (' + id_umkm + ')');
        return { success: true };
      }
    }
    return { success: false, message: 'ID UMKM tidak ditemukan.' };
  } catch (e) {
    return { success: false, message: e.toString() };
  } finally {
    lock.releaseLock();
  }
}

function getPublicUmkmData() {
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName('UMKM');
  if (!sheet) return [];

  var data = sheet.getDataRange().getValues();
  if (data.length <= 1) return [];

  var map = getColumnMap_(data);
  var result = [];
  for (var i = 1; i < data.length; i++) {
    var status = map['status'] !== undefined ? String(data[i][map['status']]) : 'Aktif';
    if (status === 'Aktif') {
      result.push({
        id_umkm: data[i][map['id_umkm']] || '',
        nama_pemilik: map['nama_pemilik'] !== undefined ? (data[i][map['nama_pemilik']] || '') : '',
        nama_usaha: data[i][map['nama_usaha']] || '',
        kategori_usaha: map['kategori_usaha'] !== undefined ? (data[i][map['kategori_usaha']] || '') : '',
        deskripsi: map['deskripsi'] !== undefined ? (data[i][map['deskripsi']] || '') : '',
        no_hp: map['no_hp'] !== undefined ? sanitizePhone_(data[i][map['no_hp']]) : '',
        alamat_lokasi: map['alamat_lokasi'] !== undefined ? (data[i][map['alamat_lokasi']] || '') : '',
        foto_produk: map['foto_produk'] !== undefined ? (data[i][map['foto_produk']] || '') : ''
      });
    }
  }
  return result;
}