const { randomUUID } = require('crypto');
const Session = require('../model/sessionModel');
const {
  hash,
  issueAccessToken,
  issueRefreshToken
} = require('./sessionTokens');

const generateTokens = async (
  user,
  { remember = false, ua = '', ip = '' } = {}
) => {
  const sid = randomUUID();

  const payload = {
    sub: user._id.toString(),
    role: user.role,
    name: user.name
  };

  // 🔥 refresh token
  const refreshToken = issueRefreshToken(payload, sid, remember);

  const maxAgeSec = 7 * 24 * 3600;
  await Session.create({
    userId: user._id,
    sid,
    currentRtHash: hash(refreshToken),
    prevRtHash: null,
    remember,
    ua,
    ip,
    expiresAt: new Date(Date.now() + maxAgeSec * 1000)
  });

  // 🔥 access token
  const accessToken = issueAccessToken(payload);

  return { accessToken, refreshToken };
};

module.exports = generateTokens;
