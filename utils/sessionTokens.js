const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const hash = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');

function issueAccessToken(payload, { expiresIn = '30m' } = {}) {
  if (!payload?.sub) {
    throw new Error('issueAccessToken: payload.sub wajib ada');
  }

  return jwt.sign(
    {
      sub: String(payload.sub),
      role: payload.role,
      name: payload.name
    },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn }
  );
}

function issueRefreshToken(payload, sid, remember = true, { expiresIn } = {}) {
  if (!payload?.sub) {
    throw new Error('issueRefreshToken: payload.sub wajib ada');
  }

  const ttl = expiresIn || '7d';

  return jwt.sign(
    {
      sub: String(payload.sub),
      role: payload.role,
      name: payload.name,
      sid,
      remember,
      typ: 'refresh'
    },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: ttl }
  );
}

module.exports = { hash, issueAccessToken, issueRefreshToken };
