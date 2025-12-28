const asyncHandler = require('express-async-handler');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
// const { Types } = require('mongoose');

const OtpChallenge = require('../model/otpChallengeModel');
const User = require('../model/userModel');
const Session = require('../model/sessionModel');
const PendingRegistration = require('../model/pendingRegistrationModel');

const throwError = require('../utils/throwError');
const generateTokens = require('../utils/generateToken');
const {
  hash,
  issueAccessToken,
  issueRefreshToken
} = require('../utils/sessionTokens');

const { generateOtp, hashOtp, verifyOtp, CODE_LEN } = require('../utils/otp');
const { sendOtpWa } = require('../utils/wablas');

const { sendOtpEmail } = require('../utils/mailer');
const {
  signPcToken,
  verifyPcToken,
  signPasswordResetToken,
  verifyPasswordResetToken,
  PC_TTL_SECONDS,
  PR_TOKEN_TTL
} = require('../utils/authTokens');

const parseRemember = (req) => {
  const b = req.body || {};
  const q = req.query || {};
  // dukung alias & querystring juga
  const raw =
    b.remember ??
    b.rememberMe ??
    b.remember_me ??
    q.remember ??
    q.rememberMe ??
    q.remember_me;

  if (raw === undefined || raw === null) return false;
  if (typeof raw === 'boolean') return raw;
  if (typeof raw === 'number') return raw === 1;

  const s = String(raw).trim().toLowerCase();
  return s === 'true' || s === '1' || s === 'on' || s === 'yes' || s === 'y';
};

const isProd = process.env.NODE_ENV === 'production';

const sameSite = process.env.COOKIE_SAMESITE || 'none';
const secure =
  process.env.COOKIE_SECURE?.toLowerCase() === 'true'
    ? true
    : process.env.COOKIE_SECURE?.toLowerCase() === 'false'
    ? false
    : isProd; // default ikut production

const baseCookie = {
  httpOnly: true,
  secure, // true = https only
  sameSite, // none kalau cross-site
  path: '/' // global scope
};

const OTP_TTL_MS = Number(process.env.OTP_TTL_MINUTES || 1) * 60 * 1000; // 1 menit
const RESEND_BLOCK_MS = Number(process.env.OTP_RESEND_SECONDS || 60) * 1000; // 60 detik
const DOC_TTL_MS = Number(process.env.OTP_DOC_TTL_MINUTES || 60) * 60 * 1000; // 1 jam
const MAX_ATTEMPTS = 5;

// ---------------------------------- REGISTER OTP ----------------------------------
const requestRegisterOtp = asyncHandler(async (req, res) => {
  const { email, name, phone, password, delivery = 'gmail' } = req.body || {};

  if (!email || !password || !name || !phone)
    throwError('Semua field harus diisi!', 400);

  if (!['gmail', 'whatsapp'].includes(delivery))
    throwError('Delivery OTP tidak valid', 400);

  const used = await User.findOne({ email });
  if (used) throwError('Email tidak tersedia!', 400, 'email');

  const now = Date.now();
  const existing = await PendingRegistration.findOne({ email });
  if (existing?.resendAfter?.getTime() > now) {
    const wait = Math.ceil((existing.resendAfter.getTime() - now) / 1000);
    throwError(`Tunggu ${wait} detik untuk kirim ulang OTP.`, 429);
  }

  const passwordHash = await bcrypt.hash(password, 10);
  const otp = generateOtp();
  const otpHash = await hashOtp(otp);

  const doc = await PendingRegistration.findOneAndUpdate(
    { email },
    {
      email,
      name,
      phone,
      passwordHash,
      otpHash,
      delivery,
      otpExpiresAt: new Date(now + OTP_TTL_MS),
      resendAfter: new Date(now + RESEND_BLOCK_MS),
      attempts: 0,
      expiresAt: new Date(now + DOC_TTL_MS)
    },
    { upsert: true, new: true, setDefaultsOnInsert: true }
  );

  res.json({
    message: 'OTP diproses',
    pendingId: doc._id,
    delivery,
    resendIn: Math.floor(RESEND_BLOCK_MS / 1000),
    codeLength: CODE_LEN
  });

  // ⬇️ kirim async
  setImmediate(async () => {
    try {
      if (delivery === 'whatsapp') {
        await sendOtpWa(phone, otp, Math.floor(OTP_TTL_MS / 60000));
      } else {
        await sendOtpEmail(email, otp, {
          action: 'Verifikasi Pendaftaran',
          brand: 'SOILAB',
          brandUrl: 'https://soilab.id',
          supportEmail: 'support@soilab.id'
        });
      }
    } catch (err) {
      console.error('[OTP SEND FAILED]', err?.message || err);
    }
  });
});

const resendRegisterOtp = asyncHandler(async (req, res) => {
  const { pendingId } = req.body || {};
  if (!pendingId) throwError('pendingId wajib diisi', 400);

  const doc = await PendingRegistration.findById(pendingId);
  if (!doc) throwError('Sesi OTP tidak ditemukan atau kadaluarsa', 404);

  const now = Date.now();
  if (doc.resendAfter.getTime() > now) {
    const wait = Math.ceil((doc.resendAfter.getTime() - now) / 1000);
    throwError(`Tunggu ${wait} detik untuk kirim ulang`, 429);
  }

  const otp = generateOtp();
  doc.otpHash = await hashOtp(otp);
  doc.otpExpiresAt = new Date(now + OTP_TTL_MS);
  doc.resendAfter = new Date(now + RESEND_BLOCK_MS);
  doc.resendCount = (doc.resendCount || 0) + 1;
  await doc.save();

  res.json({
    message: 'OTP baru telah dikirim',
    delivery: doc.delivery,
    resendIn: Math.floor(RESEND_BLOCK_MS / 1000),
    codeLength: CODE_LEN
  });

  setImmediate(async () => {
    try {
      if (doc.delivery === 'whatsapp') {
        await sendOtpWa(doc.phone, otp, Math.floor(OTP_TTL_MS / 60000));
      } else {
        await sendOtpEmail(doc.email, otp, {
          action: 'Verifikasi Pendaftaran',
          brand: 'SOILAB'
        });
      }
    } catch (err) {
      console.error('[OTP RESEND FAILED]', err?.message || err);
    }
  });
});

const verifyRegisterOtp = asyncHandler(async (req, res) => {
  const { pendingId, code } = req.body || {};
  if (!pendingId || !code)
    throwError('pendingId dan kode otp wajib diisi', 400);

  const doc = await PendingRegistration.findById(pendingId);
  if (!doc)
    throwError('Sesi ini telah habis. Silahkan daftar ulang atau kembali', 404);

  if (doc.otpExpiresAt.getTime() < Date.now()) {
    await PendingRegistration.findByIdAndDelete(pendingId);
    throwError('Kode OTP kadaluarsa. Silakan kirim ulang.', 400, 'otp');
  }
  if (doc.attempts >= MAX_ATTEMPTS) {
    await PendingRegistration.findByIdAndDelete(pendingId);
    throwError('Terlalu banyak percobaan. Mulai ulang proses.', 429);
  }

  const submitted = String(code).replace(/\D/g, '');
  if (submitted.length !== CODE_LEN) {
    doc.attempts += 1;
    await doc.save();
    throwError(`Kode OTP harus ${CODE_LEN} digit.`, 400, 'otp');
  }

  const isValid = await verifyOtp(submitted, doc.otpHash);
  if (!isValid) {
    doc.attempts += 1;
    await doc.save();
    const attemptsLeft = MAX_ATTEMPTS - doc.attempts;
    return res.status(400).json({
      code: 'OTP_WRONG',
      message: 'Kode OTP salah.',
      attemptsLeft
    });
  }

  const exists = await User.findOne({ email: doc.email });
  if (exists) {
    await PendingRegistration.findByIdAndDelete(pendingId);
    throwError('Email tidak tersedia!', 400, 'email');
  }

  const user = await User.create({
    name: doc.name,
    email: doc.email,
    phone: doc.phone,
    password: doc.passwordHash,
    authProvider: 'local',
    emailVerified: true
  });

  await PendingRegistration.findByIdAndDelete(pendingId);

  const { accessToken, refreshToken } = await generateTokens(user);

  res
    .cookie('accessToken', accessToken, {
      ...baseCookie,
      maxAge: 30 * 60 * 1000
    })
    .cookie('refreshToken', refreshToken, {
      ...baseCookie,
      maxAge: 7 * 24 * 60 * 60 * 1000
    })
    .status(201)
    .json({ message: 'Verifikasi berhasil & akun dibuat', role: user.role });
});
// ---------------------------------- REGISTER OTP END ----------------------------------

// POST /users/security/confirm-password
// body: { password, purpose }   // purpose : 'EMAIL_UPDATE' | 'PASSWORD_CHANGE' | 'FORGOT_PASSWORD'
const confirmPassword = asyncHandler(async (req, res) => {
  const userId = req.user?.id;
  const { password, purpose } = req.body || {};
  if (!password || !purpose)
    throwError('Password dan purpose wajib diisi', 400);

  const user = await User.findById(userId).select('+password oauthProvider');
  if (!user) throwError('User tidak ditemukan', 404);
  if (user.oauthProvider && user.oauthProvider !== 'local') {
    throwError('Akun OAuth tidak dapat konfirmasi password.', 403);
  }
  const ok = await bcrypt.compare(password, user.password);
  if (!ok) throwError('Password salah.', 401, 'password');

  const pcToken = signPcToken({ userId, purpose });
  res.json({ pcToken, expiresIn: PC_TTL_SECONDS });
});

// --------------------------------- CHANGE EMAIL OTP START ---------------------------------
const requestEmailUpdateOtp = asyncHandler(async (req, res) => {
  const userId = req.user?.id;
  const { pcToken, newEmail, delivery = 'gmail' } = req.body || {};

  if (!pcToken || !newEmail)
    throwError('Konfirmasi password & email baru wajib diisi', 400);

  if (!['gmail', 'whatsapp'].includes(delivery))
    throwError('Delivery OTP tidak valid', 400);

  verifyPcToken(pcToken, { userId, purpose: 'EMAIL_UPDATE' });

  const user = await User.findById(userId).select('email phone oauthProvider');
  if (!user) throwError('User tidak ditemukan', 404);

  if (user.oauthProvider && user.oauthProvider !== 'local') {
    throwError('Akun OAuth tidak dapat mengubah email.', 403);
  }

  const email = String(newEmail).trim().toLowerCase();
  if (email === user.email) throwError('Email baru tidak boleh sama.', 400);

  const used = await User.findOne({ email });
  if (used) throwError('Email baru sudah digunakan.', 400);

  const now = Date.now();
  const existing = await OtpChallenge.findOne({
    user: userId,
    type: 'EMAIL_UPDATE'
  });

  if (existing?.resendAfter?.getTime() > now) {
    const wait = Math.ceil((existing.resendAfter.getTime() - now) / 1000);
    throwError(`Tunggu ${wait} detik untuk kirim ulang OTP.`, 429);
  }

  const code = generateOtp();

  const ch = await OtpChallenge.findOneAndUpdate(
    { user: userId, type: 'EMAIL_UPDATE' },
    {
      user: userId,
      type: 'EMAIL_UPDATE',
      email,
      delivery,
      otpHash: await hashOtp(code),
      otpExpiresAt: new Date(now + OTP_TTL_MS),
      resendAfter: new Date(now + RESEND_BLOCK_MS),
      attempts: 0,
      expiresAt: new Date(now + DOC_TTL_MS)
    },
    { upsert: true, new: true }
  );

  res.json({
    message: 'OTP diproses',
    challengeId: ch._id,
    delivery,
    resendIn: Math.floor(RESEND_BLOCK_MS / 1000)
  });

  setImmediate(async () => {
    try {
      if (delivery === 'whatsapp') {
        await sendOtpWa(user.phone, code);
      } else {
        await sendOtpEmail(email, code, {
          action: 'Verifikasi Perubahan Email',
          brand: 'SOILAB'
        });
      }
    } catch (e) {
      console.error('[EMAIL UPDATE OTP FAILED]', e);
    }
  });
});

const resendEmailUpdateOtp = asyncHandler(async (req, res) => {
  const userId = req.user?.id;
  const { challengeId } = req.body || {};

  const ch = await OtpChallenge.findById(challengeId);
  if (!ch || String(ch.user) !== String(userId))
    throwError('Sesi OTP tidak valid', 404);

  const now = Date.now();
  if (ch.resendAfter.getTime() > now) {
    const wait = Math.ceil((ch.resendAfter.getTime() - now) / 1000);
    throwError(`Tunggu ${wait} detik`, 429);
  }

  const code = generateOtp();
  ch.otpHash = await hashOtp(code);
  ch.otpExpiresAt = new Date(now + OTP_TTL_MS);
  ch.resendAfter = new Date(now + RESEND_BLOCK_MS);
  ch.resendCount = (ch.resendCount || 0) + 1;
  await ch.save();

  res.json({
    message: 'OTP baru dikirim',
    delivery: ch.delivery
  });

  setImmediate(async () => {
    try {
      if (ch.delivery === 'whatsapp') {
        await sendOtpWa(ch.phone || ch.email, code);
      } else {
        await sendOtpEmail(ch.email, code, {
          action: 'Verifikasi Perubahan Email',
          brand: 'SOILAB'
        });
      }
    } catch (e) {
      console.error('[EMAIL UPDATE RESEND FAILED]', e);
    }
  });
});

const verifyEmailUpdateOtp = asyncHandler(async (req, res) => {
  const userId = req.user?.id;
  const { challengeId, code } = req.body || {};
  if (!challengeId || !code)
    throwError('challengeId dan kode otp wajib diisi', 400);

  const ch = await OtpChallenge.findById(challengeId);
  if (!ch || String(ch.user) !== String(userId) || ch.type !== 'EMAIL_UPDATE') {
    throwError('Sesi ini telah habis. Silahkan daftar ulang atau kembali', 404);
  }

  if (ch.otpExpiresAt.getTime() < Date.now()) {
    await OtpChallenge.findByIdAndDelete(challengeId);
    throwError('Kode OTP kadaluarsa. Silakan kirim ulang.', 400, 'otp');
  }
  if (ch.attempts >= MAX_ATTEMPTS) {
    await OtpChallenge.findByIdAndDelete(challengeId);
    throwError('Terlalu banyak percobaan. Mulai ulang proses.', 429);
  }

  const submitted = String(code).replace(/\D/g, '');
  if (submitted.length !== CODE_LEN) {
    ch.attempts += 1;
    await ch.save();
    throwError(`Kode OTP harus ${CODE_LEN} digit.`, 400, 'otp');
  }

  const ok = await verifyOtp(submitted, ch.otpHash);
  if (!ok) {
    ch.attempts += 1;
    await ch.save();
    throwError('Kode OTP salah.', 400, 'otp');
  }

  const exists = await User.findOne({ email: ch.email });
  if (exists) {
    await OtpChallenge.findByIdAndDelete(challengeId);
    throwError('Email baru sudah digunakan.', 400, 'email');
  }

  const user = await User.findById(userId);
  user.email = ch.email;
  user.emailVerified = true;
  await user.save();

  await OtpChallenge.findByIdAndDelete(challengeId);

  const { accessToken, refreshToken } = await generateTokens(user);
  res
    .cookie('accessToken', accessToken, {
      ...baseCookie,
      maxAge: 30 * 60 * 1000
    })
    .cookie('refreshToken', refreshToken, {
      ...baseCookie,
      maxAge: 7 * 24 * 60 * 60 * 1000
    })
    .json({ message: 'Email berhasil diperbarui', email: user.email });
});
// ---------------------------------- CHANGE EMAIL OTP END----------------------------------

// ---------------------------------- PASSWORD RESET OTP START----------------------------------
// POST /users/forgot-password/request-otp
// body (logged-out): { email }
// body (logged-in):  {}  ambil req.user.id untuk ambil email
const requestPasswordResetOtp = asyncHandler(async (req, res) => {
  const { email, delivery = 'gmail' } = req.body || {};
  if (!email) throwError('Email wajib diisi', 400);

  if (!['gmail', 'whatsapp'].includes(delivery))
    throwError('Delivery OTP tidak valid', 400);

  const user = await User.findOne({ email }).select(
    '_id email phone oauthProvider'
  );
  if (!user) {
    return res.json({ message: 'Jika email terdaftar, OTP telah dikirim.' });
  }

  if (delivery === 'whatsapp' && !user.phone) {
    throwError('Nomor anda belum terdaftar. Gunakan reset via gmail.', 400);
  }

  if (user.oauthProvider && user.oauthProvider !== 'local') {
    throwError(
      'Akun Google tidak bisa reset password. Gunakan login Google.',
      403
    );
  }

  const now = Date.now();
  const existing = await OtpChallenge.findOne({
    user: user._id,
    type: 'PASSWORD_RESET'
  });

  if (existing?.resendAfter?.getTime() > now) {
    const wait = Math.ceil((existing.resendAfter.getTime() - now) / 1000);
    throwError(`Tunggu ${wait} detik`, 429);
  }

  const code = generateOtp();

  const ch = await OtpChallenge.findOneAndUpdate(
    { user: user._id, type: 'PASSWORD_RESET' },
    {
      user: user._id,
      type: 'PASSWORD_RESET',
      email: user.email,
      delivery,
      otpHash: await hashOtp(code),
      otpExpiresAt: new Date(now + OTP_TTL_MS),
      resendAfter: new Date(now + RESEND_BLOCK_MS),
      attempts: 0,
      expiresAt: new Date(now + DOC_TTL_MS)
    },
    { upsert: true, new: true }
  );

  res.json({
    message: 'OTP diproses',
    challengeId: ch._id,
    delivery
  });

  setImmediate(async () => {
    try {
      if (delivery === 'whatsapp') {
        await sendOtpWa(user.phone, code);
      } else {
        await sendOtpEmail(user.email, code, {
          action: 'Reset Password',
          brand: 'SOILAB'
        });
      }
    } catch (e) {
      console.error('[PASSWORD RESET OTP FAILED]', e);
    }
  });
});

// POST /users/forgot-password/resend-otp
// body: { challengeId }
const resendPasswordResetOtp = asyncHandler(async (req, res) => {
  const { challengeId } = req.body || {};
  if (!challengeId) throwError('challengeId wajib diisi', 400);

  const ch = await OtpChallenge.findById(challengeId);
  if (!ch || ch.type !== 'PASSWORD_RESET')
    throwError('Sesi ini telah habis. Silahkan ulangi kembali', 404);

  const now = Date.now();
  if (ch.resendAfter && ch.resendAfter.getTime() > now) {
    const wait = Math.ceil((ch.resendAfter.getTime() - now) / 1000);
    throwError(`Tunggu ${wait} detik untuk kirim ulang OTP.`, 429);
  }

  const code = generateOtp();
  ch.otpHash = await hashOtp(code);
  ch.otpExpiresAt = new Date(now + OTP_TTL_MS);
  ch.resendAfter = new Date(now + RESEND_BLOCK_MS);
  ch.resendCount = (ch.resendCount || 0) + 1;
  await ch.save();

  res.json({
    message: 'OTP baru dikirim',
    resendIn: Math.floor(RESEND_BLOCK_MS / 1000)
  });

  setImmediate(async () => {
    try {
      if (ch.delivery === 'whatsapp') {
        const user = await User.findById(ch.user).select('phone');
        if (!user?.phone) return; // safety guard
        await sendOtpWa(user.phone, code);
      } else {
        await sendOtpEmail(ch.email, code, {
          action: 'Reset Password',
          brand: 'SOILAB'
        });
      }
    } catch (e) {
      console.error('[PASSWORD RESET RESEND FAILED]', e?.message || e);
    }
  });
});

// POST /users/forgot-password/verify-otp
// body: { challengeId, code }
const verifyPasswordResetOtp = asyncHandler(async (req, res) => {
  const { challengeId, code } = req.body || {};
  if (!challengeId || !code) throwError('challengeId dan otp wajib diisi', 400);

  const ch = await OtpChallenge.findById(challengeId);
  if (!ch || ch.type !== 'PASSWORD_RESET')
    throwError('Sesi ini telah habis. Silahkan ulangi kembali', 404);

  if (ch.otpExpiresAt.getTime() < Date.now()) {
    await OtpChallenge.findByIdAndDelete(challengeId);
    throwError('Kode OTP kadaluarsa. Silakan minta yang baru.', 400, 'otp');
  }
  if (ch.attempts >= MAX_ATTEMPTS) {
    await OtpChallenge.findByIdAndDelete(challengeId);
    throwError('Terlalu banyak percobaan. Mulai ulang proses.', 429);
  }

  const submitted = String(code).replace(/\D/g, '');
  if (submitted.length !== CODE_LEN) {
    ch.attempts += 1;
    await ch.save();
    throwError(`Kode OTP harus ${CODE_LEN} digit.`, 400, 'otp');
  }

  const ok = await verifyOtp(submitted, ch.otpHash);
  if (!ok) {
    ch.attempts += 1;
    await ch.save();
    throwError('Kode OTP salah.', 400, 'otp');
  }

  const prToken = signPasswordResetToken(ch.user);
  res.json({ prToken, expiresIn: PR_TOKEN_TTL || 300 }); // 5 menit
});

// POST /users/forgot-password/reset
// body: { prToken, newPassword }
const resetPasswordWithToken = asyncHandler(async (req, res) => {
  const { prToken, newPassword } = req.body || {};
  if (!prToken || !newPassword)
    throwError('Token reset & password baru wajib diisi', 400);

  let payload;
  try {
    payload = verifyPasswordResetToken(prToken);
  } catch {
    throwError('Token reset tidak valid / kedaluwarsa', 401);
  }

  const user = await User.findById(payload.sub).select('+password');
  if (!user) throwError('User tidak ditemukan', 404);

  if (user.oauthProvider && user.oauthProvider !== 'local') {
    throwError('Akun OAuth tidak dapat reset password lokal.', 403);
  }

  const hash = await bcrypt.hash(newPassword, 10);
  user.password = hash;
  await user.save();

  await OtpChallenge.findOneAndDelete({
    user: user._id,
    type: 'PASSWORD_RESET'
  });

  const { accessToken, refreshToken } = await generateTokens(user);

  res
    .cookie('accessToken', accessToken, {
      ...baseCookie,
      maxAge: 30 * 60 * 1000
    })
    .cookie('refreshToken', refreshToken, {
      ...baseCookie,
      maxAge: 7 * 24 * 60 * 60 * 1000
    })
    .json({ message: 'Password berhasil diperbarui' });
});

// const registerUser = asyncHandler(async (req, res) => {
//   const { email, name, phone, password } = req.body || {};
//   if (!email || !password || !name || !phone) {
//     throwError('Semua field harus di isi!', 400);
//   }

//   const userExist = await User.findOne({ email });
//   if (userExist) throwError('Email tidak tersedia!', 400, 'email');

//   const hashedPassword = await bcrypt.hash(password, 10);
//   const user = await User.create({
//     name,
//     email,
//     phone,
//     password: hashedPassword
//   });

//   if (!user) throwError('User data tidak valid!', 400);

//   const { accessToken, refreshToken } = await generateTokens(user);

//   res.clearCookie('refreshToken', { ...baseCookie});

//   res
//     .cookie('accessToken', accessToken, {
//       ...baseCookie,
//       path: '/', // global
//       maxAge: 30 * 60 * 1000 // 30 menit
//     })
//     .cookie('refreshToken', refreshToken, {
//       ...baseCookie,
//       path: '/users', // prefix untuk /users/refresh-token
//       maxAge: 7 * 24 * 60 * 60 * 1000 // 7 hari
//     })
//     .status(201)
//     .json({ message: 'Daftar akun berhasil', role: user.role });
// });

const getCurrentUser = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user.id).select(
    'name phone role email updatedAt'
  );

  if (!user) throwError('User tidak ditemukan!', 404);

  const response = {
    _id: user._id,
    name: user.name,
    email: user.email,
    phone: user.phone,
    role: user.role,
    updatedAt: user.updatedAt
  };

  // 🔥 hanya karyawan yang punya pages
  if (user.role === 'karyawan') {
    response.pages = req.user.pages || [];
  }

  res.status(200).json(response);
});

const updateUser = asyncHandler(async (req, res) => {
  const me = await User.findById(req.user.id).select('-role');
  if (!me) throwError('User data tidak valid!', 400);

  const { name, phone } = req.body || {};
  if (!name && !phone) {
    return throwError('Isi setidaknya salah satu field!', 400);
  }

  const updatedFields = {};
  if (name) updatedFields.name = name;
  if (phone) updatedFields.phone = phone;

  const updatedUser = await User.findByIdAndUpdate(me.id, updatedFields, {
    new: true,
    runValidators: true
  }).select('-role');

  res.status(200).json({ message: 'Berhasil di update!', user: updatedUser });
});

const updatePassword = asyncHandler(async (req, res) => {
  const { currentPassword, newPassword } = req.body || {};

  const user = await User.findById(req.user.id).select('+password');
  if (!user) return throwError('Pengguna tidak ditemukan', 401);

  const isCurrentMatch = await bcrypt.compare(currentPassword, user.password);
  if (!isCurrentMatch)
    return throwError('Password tidak sesuai', 400, 'password');

  const isNewSame = await bcrypt.compare(newPassword, user.password);
  if (isNewSame)
    return throwError(
      'Password tidak boleh sama dengan sebelumnya!',
      400,
      'newPassword'
    );

  user.password = await bcrypt.hash(newPassword, 10);
  await user.save();

  res.status(200).json({ message: 'Password berhasil diganti!' });
});

const loginUser = asyncHandler(async (req, res) => {
  const { email, password } = req.body || {};
  const remember = parseRemember(req);

  if (!email || !password) throwError('Email dan password wajib diisi', 400);

  const user = await User.findOne({ email }).select('+password oauthProvider');
  if (!user) throwError('Email tidak ditemukan', 401);
  if (user.role === 'bot') throwError('Akun bot tidak bisa login', 403);

  // 🚨 PENTING: bedakan login local vs google
  if (user.oauthProvider && user.oauthProvider !== 'local') {
    throwError(
      'Akun ini terdaftar via Google. Silakan login menggunakan Google.',
      403
    );
  }

  if (!user.password) {
    throwError('Password tidak tersedia. Silakan reset password.', 403);
  }

  const isValid = await bcrypt.compare(password, user.password);
  if (!isValid) throwError('Password invalid', 401);

  const { accessToken, refreshToken } = await generateTokens(user, {
    remember,
    ua: req.headers['user-agent'] || '',
    ip: req.ip || ''
  });

  const refreshCookieOpts = remember
    ? { ...baseCookie, maxAge: 7 * 24 * 60 * 60 * 1000 }
    : { ...baseCookie };

  res
    .cookie('accessToken', accessToken, {
      ...baseCookie,
      maxAge: 30 * 60 * 1000
    })
    .cookie('refreshToken', refreshToken, refreshCookieOpts)
    .json({
      message: 'Login berhasil',
      role: user.role,
      accessExpiresInSec: 1800
    });
});

const logoutUser = asyncHandler(async (req, res) => {
  try {
    const token = req.cookies?.refreshToken;
    if (token) {
      try {
        const payload = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET);
        if (payload?.sid) {
          await Session.updateOne(
            { sid: payload.sid, userId: payload.sub },
            { $set: { revokedAt: new Date() } }
          );
        } else {
          // legacy: bersihkan field di User
          await User.findByIdAndUpdate(payload.sub, {
            refreshToken: null,
            prevRefreshToken: null
          });
        }
      } catch (_) {}
    }
    res
      .clearCookie('accessToken', { ...baseCookie })
      .clearCookie('refreshToken', { ...baseCookie })
      .json({ message: 'Berhasil logout' });
  } catch (_) {
    res
      .clearCookie('accessToken', { ...baseCookie })
      .clearCookie('refreshToken', { ...baseCookie })
      .status(200)
      .json({ message: 'Berhasil logout' });
  }
});

const refreshToken = asyncHandler(async (req, res) => {
  const hasCookieHeader = !!req.headers.cookie;
  const token = req.cookies?.refreshToken;

  console.log('[rt][in]', {
    url: req.originalUrl,
    hasCookieHeader,
    hasRefreshCookie: !!token,
    cookieKeys: Object.keys(req.cookies || {}),
    env: {
      NODE_ENV: process.env.NODE_ENV,
      COOKIE_SAMESITE: process.env.COOKIE_SAMESITE,
      COOKIE_SECURE: process.env.COOKIE_SECURE
    }
  });

  if (!token) {
    console.log('[rt] missing refresh cookie');
    return res.status(401).json({ message: 'No refresh token' });
  }

  let payload;
  try {
    payload = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET);
    console.log('[rt] jwt ok', {
      sub: payload?.sub,
      remember: !!payload?.remember,
      sid: payload?.sid || '<none>'
    });
  } catch (e) {
    console.log('[rt] verify error', e?.message || e);
    return res
      .clearCookie('accessToken', { ...baseCookie })
      .clearCookie('refreshToken', { ...baseCookie })
      .status(401)
      .json({ message: 'Refresh token invalid/expired' });
  }

  const remember = !!payload.remember;
  const refreshCookieOpts = remember
    ? { ...baseCookie, maxAge: 7 * 24 * 60 * 60 * 1000 }
    : { ...baseCookie };

  if (payload.sid) {
    const session = await Session.findOne({
      sid: payload.sid,
      userId: payload.sub
    });
    if (!session || session.revokedAt) {
      console.log('[rt] session missing/revoked');
      return res
        .clearCookie('accessToken', { ...baseCookie })
        .clearCookie('refreshToken', { ...baseCookie })
        .status(401)
        .json({ message: 'Refresh token invalid' });
    }
    if (session.expiresAt && session.expiresAt.getTime() < Date.now()) {
      console.log('[rt] session expired');
      return res
        .clearCookie('accessToken', { ...baseCookie })
        .clearCookie('refreshToken', { ...baseCookie })
        .status(401)
        .json({ message: 'Session expired' });
    }

    const presented = hash(token);
    const matchCurrent = presented === session.currentRtHash;
    const matchPrev = presented === session.prevRtHash;

    if (!matchCurrent && !matchPrev) {
      console.log('[rt] mismatch → revoke session');
      session.revokedAt = new Date();
      await session.save();
      return res
        .clearCookie('accessToken', { ...baseCookie })
        .clearCookie('refreshToken', { ...baseCookie })
        .status(401)
        .json({ message: 'Refresh token invalid (mismatch)' });
    }

    // ROTATE dalam sesi ini saja
    const newRt = issueRefreshToken(
      { sub: payload.sub, role: payload.role, name: payload.name },
      session.sid,
      session.remember
    );
    session.prevRtHash = session.currentRtHash;
    session.currentRtHash = hash(newRt);
    session.replacedAt = new Date();
    // sliding window 7 hari (sesuai sebelumnya)
    session.expiresAt = new Date(Date.now() + 7 * 24 * 3600 * 1000);
    await session.save();

    const newAt = issueAccessToken({
      sub: payload.sub,
      role: payload.role,
      name: payload.name
    });

    console.log('[rt][out-rotate-per-session]', {
      setAccessCookie: true,
      setRefreshCookie: true
    });

    return res
      .cookie('accessToken', newAt, { ...baseCookie, maxAge: 30 * 60 * 1000 })
      .cookie('refreshToken', newRt, refreshCookieOpts)
      .json({ message: 'Access token refreshed (per-session)' });
  }

  // ======== LEGACY FALLBACK: tidak ada sid → pakai flow lamamu ========
  const user = await User.findById(payload.sub).select(
    '+refreshToken +prevRefreshToken role name'
  );
  if (!user) {
    console.log('[rt][legacy] user not found', { sub: payload?.sub });
    return res
      .clearCookie('accessToken', { ...baseCookie })
      .clearCookie('refreshToken', { ...baseCookie })
      .status(401)
      .json({ message: 'Refresh token invalid' });
  }

  const matchCurrent = user.refreshToken === token;
  const matchPrev = user.prevRefreshToken === token;

  console.log('[rt][legacy] db match', {
    matchCurrent,
    matchPrev,
    dbCurrent: user.refreshToken ? '<present>' : '<null>',
    dbPrev: user.prevRefreshToken ? '<present>' : '<null>',
    providedLen: token.length
  });

  if (!matchCurrent && !matchPrev) {
    console.log('[rt][legacy] token not found in DB (invalid)');
    return res
      .clearCookie('accessToken', { ...baseCookie })
      .clearCookie('refreshToken', { ...baseCookie })
      .status(401)
      .json({ message: 'Refresh token invalid' });
  }

  if (matchPrev) {
    const newAt = issueAccessToken({
      _id: user._id,
      role: user.role,
      name: user.name
    });
    console.log('[rt][legacy-out-prev-upgrade]', {
      note: 'matchPrev → upgrade client to CURRENT; no rotation'
    });
    return res
      .cookie('accessToken', newAt, { ...baseCookie, maxAge: 30 * 60 * 1000 })
      .cookie('refreshToken', user.refreshToken, refreshCookieOpts)
      .json({
        message: 'Access token refreshed (prev accepted, upgraded to current)'
      });
  }

  // CURRENT → ROTATE (legacy)
  const newAt = issueAccessToken({
    _id: user._id,
    role: user.role,
    name: user.name
  });
  const newRt = jwt.sign(
    { sub: user._id.toString(), role: user.role, name: user.name, remember },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: '7d' }
  );

  const upd = await User.updateOne(
    { _id: user._id, refreshToken: token },
    { $set: { prevRefreshToken: token, refreshToken: newRt } }
  );

  if (upd.modifiedCount === 0) {
    const latest = await User.findById(user._id).select(
      'refreshToken prevRefreshToken'
    );
    console.log('[rt][legacy-out-race]', {
      info: 'already rotated by another request → send latest CURRENT'
    });
    return res
      .cookie('accessToken', newAt, { ...baseCookie, maxAge: 30 * 60 * 1000 })
      .cookie('refreshToken', latest.refreshToken || token, refreshCookieOpts)
      .json({ message: 'Access token refreshed (race-safe upgraded)' });
  }

  console.log('[rt][legacy-out-rotate]', {
    setAccessCookie: true,
    setRefreshCookie: true
  });

  return res
    .cookie('accessToken', newAt, { ...baseCookie, maxAge: 30 * 60 * 1000 })
    .cookie('refreshToken', newRt, refreshCookieOpts)
    .json({ message: 'Access token berhasil di refresh' });
});

const deleteTestAccount = asyncHandler(async (req, res) => {
  const user = await User.findOneAndDelete({ email: 'delivered@resend.dev' });
  if (!user) return throwError('Akun tester tidak ditemukan', 404);

  return res.status(200).json({ message: 'Akun testing berhasil di hapus' });
});

module.exports = {
  // registerUser,
  loginUser,
  getCurrentUser,
  updateUser,
  updatePassword,
  logoutUser,
  refreshToken,
  requestRegisterOtp,
  resendRegisterOtp,
  verifyRegisterOtp,
  confirmPassword,
  requestEmailUpdateOtp,
  resendEmailUpdateOtp,
  verifyEmailUpdateOtp,
  requestPasswordResetOtp,
  resendPasswordResetOtp,
  verifyPasswordResetOtp,
  resetPasswordWithToken,
  deleteTestAccount
};
