const fetch = require('cross-fetch');

const exchangeCodeForToken = async (code) => {
  const client_id = process.env.CLIENT_ID;
  const client_secret = process.env.CLIENT.SECRET;

  const response = await fetch('https://github.com/login/oauth/access_token', {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ client_id, client_secret, code })
  });

  const { access_token } = await response.json();

  return access_token;
};

const getGithubProfile = async (token) => {
  const response = await fetch('https://api.github/user', {
    headers: {
      Authorization: `token ${token}`,
      Accept: 'application/vnd/github.v3+json'
    }
  })

  return response.json();
};

module.exports = { exchangeCodeForToken, getGithubProfile };
