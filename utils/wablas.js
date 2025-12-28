const axios = require('axios');

const BASE = process.env.WABLAS_BASE || 'https://tegal.wablas.com/api';
const AUTH = `${process.env.WABLAS_TOKEN}.${process.env.WABLAS_SECRET}`;

function normalizePhone(phone) {
  let p = String(phone).trim();
  if (p.startsWith('+62')) p = '0' + p.slice(3);
  if (p.startsWith('62')) p = '0' + p.slice(2);
  return p;
}

function toWa62(phone) {
  const p = normalizePhone(phone);
  return p.startsWith('0') ? '62' + p.slice(1) : p;
}

async function sendOtpWa(phone, code, ttlMin = 1) {
  const message = `
🔐 *Kode OTP SOILAB*

*${code}*

_Jangan bagikan kode ini ke siapa pun._
_Berlaku ${ttlMin} menit._
`;

  try {
    const res = await axios.get(`${BASE}/send-message`, {
      params: {
        phone: toWa62(phone),
        message,
        token: AUTH
      },
      timeout: 10000
    });

    return res.data;
  } catch (err) {
    console.error('[WABLAS OTP FAILED]', err?.message || err);
    return null;
  }
}

module.exports = {
  sendOtpWa,
  normalizePhone,
  toWa62
};
